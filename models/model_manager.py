"""
model_manager.py — Mapache model manager

The top-level orchestrator of the multi-model pipeline.
Wires together: registry, routing engine, planner, executor, verifier.

This is what the agent controller talks to in Phase 7 instead of
talking directly to a single model provider.

Pipeline flow:
    User input
        ↓
    ModelManager.run_turn()
        ↓
    PlannerModel  ← uses best reasoning model
        ↓
    [for each task in plan]
    ExecutorModel ← uses fastest tool-capable model
        ↓
    VerifierModel ← validates each output
        ↓ (retry if needed)
    Synthesizer   ← combines all results into final response
        ↓
    Response to user

The model manager also handles:
    - Provider initialization and health checks
    - Automatic fallback when a model is unavailable
    - Per-session model selection
    - Usage tracking and cost estimation
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Optional

from core.logger import get_logger
from models.model_registry import ModelRegistry, ModelRole, Provider
from models.routing_engine import RoutingEngine, RoutingStrategy
from models.pipelines.planner_model import PlannerModel, PlannerOutput
from models.pipelines.executor_model import ExecutorModel, ExecutionResult
from models.pipelines.verifier_model import VerifierModel, Verdict

logger = get_logger(__name__)

MAX_RETRIES = 2


@dataclass
class PipelineResult:
    """Full result from one pipeline run."""
    goal: str
    plan: Optional[PlannerOutput]
    task_results: list[ExecutionResult] = field(default_factory=list)
    final_response: str = ""
    tool_calls_made: list[str] = field(default_factory=list)
    models_used: dict[str, str] = field(default_factory=dict)  # role → model_id
    iterations: int = 0
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None


class ModelManager:
    """
    Multi-model pipeline orchestrator.

    Supports three operational modes:
        SINGLE   — one model does everything (backward compatible)
        PIPELINE — dedicated planner + executor + verifier
        AUTO     — auto-selects strategy based on available models

    Usage:
        manager = ModelManager()
        await manager.setup(available_models=["qwen2.5:14b", "qwen2.5:7b"])

        result = await manager.run_turn(
            goal="scan 192.168.1.1 for open ports",
            tool_dispatcher=dispatcher,
        )
        print(result.final_response)
    """

    def __init__(
        self,
        strategy: RoutingStrategy = RoutingStrategy.AUTO,
        local_only: bool = True,
        max_vram_gb: float = 12.0,
        enable_verifier: bool = True,
        ollama_url: str = "http://localhost:11434",
    ) -> None:
        self.strategy = strategy
        self.local_only = local_only
        self.max_vram_gb = max_vram_gb
        self.enable_verifier = enable_verifier
        self.ollama_url = ollama_url

        self.registry = ModelRegistry()
        self.routing = RoutingEngine(
            registry=self.registry,
            strategy=strategy,
            local_only=local_only,
            max_vram_gb=max_vram_gb,
        )

        self._providers: dict[str, Any] = {}
        self._planner: Optional[PlannerModel] = None
        self._executor: Optional[ExecutorModel] = None
        self._verifier: Optional[VerifierModel] = None
        self._available_models: list[str] = []
        self._tool_dispatcher: Optional[Any] = None

    # ------------------------------------------------------------------ #
    # Setup
    # ------------------------------------------------------------------ #

    async def setup(
        self,
        available_models: Optional[list[str]] = None,
        tool_dispatcher: Optional[Any] = None,
    ) -> None:
        """
        Initialize providers and pipeline stages.
        Call this once before run_turn().
        """
        self._tool_dispatcher = tool_dispatcher

        # Discover available Ollama models if not provided
        if available_models is None:
            available_models = await self._discover_ollama_models()

        self._available_models = available_models
        self.routing.set_available_models(available_models)

        # Initialize providers for each available model
        await self._init_providers(available_models)

        # Build pipeline stages
        self._planner = PlannerModel(
            routing_engine=self.routing,
            model_providers=self._providers,
        )

        self._executor = ExecutorModel(
            routing_engine=self.routing,
            model_providers=self._providers,
            tool_dispatcher=tool_dispatcher,
        )

        self._verifier = VerifierModel(
            routing_engine=self.routing,
            model_providers=self._providers,
            enabled=self.enable_verifier,
        )

        logger.info(
            "ModelManager ready: %d models, strategy=%s",
            len(available_models), self.strategy.value,
        )
        logger.info(self.routing.explain())

    def set_tool_dispatcher(self, dispatcher: Any) -> None:
        self._tool_dispatcher = dispatcher
        if self._executor:
            self._executor.set_tool_dispatcher(dispatcher)

    def set_available_tools(self, tools: list[str]) -> None:
        if self._planner:
            self._planner.set_available_tools(tools)

    # ------------------------------------------------------------------ #
    # Main pipeline
    # ------------------------------------------------------------------ #

    async def run_turn(
        self,
        goal: str,
        session_id: str = "",
        memory_snippets: Optional[list[str]] = None,
        skip_planning: bool = False,
    ) -> PipelineResult:
        """
        Run the full multi-model pipeline for one user turn.

        1. Planner decomposes the goal
        2. Executor runs each task
        3. Verifier checks each output
        4. Synthesizer builds final response
        """
        result = PipelineResult(goal=goal, plan=None)

        # ── Planning phase ──────────────────────────────────────────────
        if skip_planning or not self._planner:
            plan = self._direct_plan(goal)
        else:
            try:
                plan = await self._planner.plan(
                    goal=goal,
                    memory_snippets=memory_snippets,
                )
                if plan.model_used:
                    result.models_used["planner"] = plan.model_used
                logger.info(
                    "Plan: %d tasks, complexity=%s",
                    len(plan.tasks), plan.complexity,
                )
            except Exception as exc:
                logger.error("Planning failed: %s", exc)
                plan = self._direct_plan(goal)

        result.plan = plan

        # ── Execution phase ─────────────────────────────────────────────
        context_outputs: dict[str, str] = {}

        for task in plan.tasks:
            task_result = await self._execute_with_retry(
                task=task,
                session_id=session_id,
                context_outputs=context_outputs,
                result=result,
            )
            result.task_results.append(task_result)
            result.iterations += 1

            if task_result.tool_name and task_result.tool_name != "noop":
                result.tool_calls_made.append(task_result.tool_name)

            # Store output for reference by subsequent tasks
            output_key = task.get("output_key")
            if output_key and task_result.output:
                context_outputs[output_key] = task_result.output

        # ── Synthesis phase ─────────────────────────────────────────────
        result.final_response = await self._synthesize(goal, result)

        return result

    async def _execute_with_retry(
        self,
        task: dict,
        session_id: str,
        context_outputs: dict,
        result: PipelineResult,
    ) -> ExecutionResult:
        """Execute a task with verification and retry logic."""
        last_result = None

        for attempt in range(MAX_RETRIES + 1):
            if not self._executor:
                break

            task_result = await self._executor.execute_task(
                task=task,
                session_id=session_id,
                context_outputs=context_outputs,
            )
            last_result = task_result

            if task_result.tool_name == "noop":
                break

            # Verify the output
            if self._verifier and self.enable_verifier:
                verification = await self._verifier.verify(
                    task_description=task.get("description", ""),
                    tool_name=task_result.tool_name,
                    tool_output=task_result.output,
                    tool_args=task.get("tool_args", {}),
                )

                if verification.should_pass:
                    if verification.warnings:
                        logger.warning(
                            "Task %s passed with warnings: %s",
                            task.get("id"), verification.warnings,
                        )
                    break

                if verification.should_retry and attempt < MAX_RETRIES:
                    logger.info(
                        "Verifier requested retry for task %s (attempt %d): %s",
                        task.get("id"), attempt + 1, verification.retry_hint,
                    )
                    # Add hint to task args for retry
                    if verification.retry_hint:
                        task = dict(task)
                        task["description"] = f"{task.get('description', '')} [RETRY HINT: {verification.retry_hint}]"
                    continue

                # Verdict is FAIL
                logger.warning(
                    "Verifier rejected task %s output: %s",
                    task.get("id"), verification.reasoning,
                )
                break
            else:
                break

        return last_result or ExecutionResult(
            task_id=task.get("id", "unknown"),
            tool_name=task.get("tool_name", "unknown"),
            output="Task execution failed",
            success=False,
            duration_ms=0.0,
            error="max_retries_exceeded",
        )

    async def _synthesize(self, goal: str, result: PipelineResult) -> str:
        """
        Build a final coherent response from all task outputs.
        Uses the executor model for synthesis — it's fast and knows the outputs.
        """
        if not result.task_results:
            return "No results to report."

        # For simple single-step results, return directly
        if len(result.task_results) == 1:
            task_result = result.task_results[0]
            if task_result.tool_name == "noop":
                return task_result.output
            if task_result.output:
                return task_result.output

        # Multi-step — synthesize with model
        decision = self.routing.route(ModelRole.EXECUTOR)
        model_id = decision.model_id
        provider = self.providers.get(model_id) or next(iter(self._providers.values()), None)

        if not provider:
            # Fallback: concatenate outputs
            parts = []
            for r in result.task_results:
                if r.output and r.tool_name != "noop":
                    parts.append(f"[{r.tool_name}]\n{r.output}")
            return "\n\n".join(parts) or "Tasks completed."

        # Build synthesis prompt
        outputs_text = "\n\n".join(
            f"Step {i+1} ({r.tool_name}):\n{r.output[:1000]}"
            for i, r in enumerate(result.task_results)
            if r.output
        )

        messages = [
            {
                "role": "system",
                "content": (
                    "Synthesize the following task outputs into a clear, concise response "
                    "that directly addresses the user's goal. "
                    "Quote important data verbatim. Be direct. No padding."
                ),
            },
            {
                "role": "user",
                "content": f"GOAL: {goal}\n\nTASK OUTPUTS:\n{outputs_text}",
            },
        ]

        try:
            raw = await provider.chat(messages=messages)
            if isinstance(raw, dict):
                return raw.get("message", {}).get("content", "") or raw.get("content", "")
            return str(raw)
        except Exception as exc:
            logger.error("Synthesis failed: %s", exc)
            return outputs_text or "Tasks completed."

    # ------------------------------------------------------------------ #
    # Provider management
    # ------------------------------------------------------------------ #

    async def _init_providers(self, model_ids: list[str]) -> None:
        """Initialize Ollama providers for each available model."""
        try:
            from models.providers.ollama_provider import OllamaProvider
        except ImportError:
            logger.error("Could not import OllamaProvider")
            return

        for model_id in model_ids:
            try:
                provider = OllamaProvider(
                    model=model_id,
                    base_url=self.ollama_url,
                )
                self._providers[model_id] = provider
                logger.debug("Provider initialized: %s", model_id)
            except Exception as exc:
                logger.warning("Could not init provider for %s: %s", model_id, exc)

    async def _discover_ollama_models(self) -> list[str]:
        """Query Ollama for installed models."""
        try:
            from models.providers.ollama_provider import OllamaProvider
            probe = OllamaProvider(model="", base_url=self.ollama_url)
            models = await probe.list_models()
            logger.info("Discovered Ollama models: %s", models)
            return models
        except Exception as exc:
            logger.warning("Could not discover Ollama models: %s", exc)
            return []

    @property
    def providers(self) -> dict[str, Any]:
        return self._providers

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _direct_plan(self, goal: str) -> PlannerOutput:
        """Passthrough plan when planning is skipped or fails."""
        from models.pipelines.planner_model import PlannerOutput
        return PlannerOutput(
            reasoning="Direct execution — no planning",
            complexity="simple",
            estimated_steps=1,
            risks=[],
            tasks=[{"id": "t1", "type": "noop", "description": goal}],
        )

    def explain_routing(self) -> str:
        return self.routing.explain()

    def stats(self) -> dict:
        return {
            "available_models": self._available_models,
            "strategy": self.strategy.value,
            "planner_calls": self._planner.call_count if self._planner else 0,
            "executor_calls": self._executor.call_count if self._executor else 0,
            "executor_tool_calls": self._executor.tool_call_count if self._executor else 0,
            "verifier_stats": self._verifier.stats if self._verifier else {},
        }
