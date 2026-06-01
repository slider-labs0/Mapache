"""
executor_model.py — Mapache executor pipeline stage

The executor is the action taker of the multi-model pipeline.
It receives ready tasks from the task manager and decides how to
execute them — either as direct tool calls or as model-driven reasoning.

In pipeline mode this uses the FASTEST available model with tool support.
Speed matters here because execution is the hot path — every tool call
goes through the executor model.

The executor model's job:
    1. Receive a task with tool_name + tool_args
    2. For tool_call tasks: validate args and dispatch to tool
    3. For model_query tasks: ask the model a focused sub-question
    4. For complex tasks: reason about execution order
    5. Return structured results to the task manager

The executor does NOT plan — it executes what the planner decided.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Optional

from core.logger import get_logger
from models.model_registry import ModelRole
from models.routing_engine import RoutingEngine

logger = get_logger(__name__)


EXECUTOR_SYSTEM_PROMPT = """You are the execution module of Mapache, an autonomous security research agent.

Your job is to execute specific tasks and report results clearly.

When you receive tool output, report it EXACTLY as received — never paraphrase or invent.
When a tool fails, explain what went wrong clearly.
When asked a sub-question, answer it directly and concisely.

You operate on Windows. Use Windows commands when running shell commands.
Always quote tool output verbatim."""


@dataclass
class ExecutionResult:
    """Result from executing a single task."""
    task_id: str
    tool_name: str
    output: str
    success: bool
    duration_ms: float
    model_used: str = ""
    error: Optional[str] = None
    iterations: int = 1


class ExecutorModel:
    """
    Execution stage of the multi-model pipeline.

    Uses the fastest tool-capable model for action execution.
    Separate from the planner so an expensive planning model
    can be paired with a fast cheap executor.
    """

    MAX_ITERATIONS = 3  # executor has tighter loop than main controller

    def __init__(
        self,
        routing_engine: RoutingEngine,
        model_providers: dict[str, Any],
        tool_dispatcher: Optional[Any] = None,
    ) -> None:
        self.routing = routing_engine
        self.providers = model_providers
        self.tool_dispatcher = tool_dispatcher
        self._call_count = 0
        self._tool_call_count = 0

    def set_tool_dispatcher(self, dispatcher: Any) -> None:
        self.tool_dispatcher = dispatcher

    async def execute_task(
        self,
        task: dict[str, Any],
        session_id: str = "",
        context_outputs: Optional[dict[str, str]] = None,
    ) -> ExecutionResult:
        """
        Execute a single task from the plan.

        Args:
            task: Task dict from the planner (id, type, tool_name, tool_args, etc.)
            session_id: Current session ID
            context_outputs: Results from prior tasks keyed by output_key
        """
        task_id = task.get("id", "unknown")
        task_type = task.get("type", "tool_call")
        tool_name = task.get("tool_name", "")
        tool_args = dict(task.get("tool_args", {}))
        description = task.get("description", "")

        # Resolve output references from prior tasks
        if context_outputs:
            tool_args = self._resolve_refs(tool_args, context_outputs)

        start = time.monotonic()
        self._call_count += 1

        logger.info(
            "Executor: task=%s type=%s tool=%s",
            task_id, task_type, tool_name or "-",
        )

        if task_type == "tool_call" and tool_name:
            result = await self._execute_tool(task_id, tool_name, tool_args, session_id)

        elif task_type == "model_query":
            result = await self._execute_model_query(task_id, description, session_id)

        elif task_type == "noop":
            result = ExecutionResult(
                task_id=task_id,
                tool_name="noop",
                output=description,
                success=True,
                duration_ms=0.0,
            )

        else:
            result = ExecutionResult(
                task_id=task_id,
                tool_name=task_type,
                output="",
                success=False,
                error=f"Unknown task type: {task_type}",
                duration_ms=0.0,
            )

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "Task %s complete: success=%s duration=%.0fms",
            task_id, result.success, result.duration_ms,
        )
        return result

    async def _execute_tool(
        self,
        task_id: str,
        tool_name: str,
        tool_args: dict,
        session_id: str,
    ) -> ExecutionResult:
        """Execute a tool call directly through the dispatcher."""
        self._tool_call_count += 1

        if not self.tool_dispatcher:
            return ExecutionResult(
                task_id=task_id,
                tool_name=tool_name,
                output=f"[STUB] {tool_name}({json.dumps(tool_args)}) — no dispatcher",
                success=True,
                duration_ms=0.0,
            )

        try:
            output = await self.tool_dispatcher.dispatch(tool_name, tool_args, session_id)
            return ExecutionResult(
                task_id=task_id,
                tool_name=tool_name,
                output=output,
                success=not output.startswith("Error:"),
                duration_ms=0.0,
            )
        except Exception as exc:
            return ExecutionResult(
                task_id=task_id,
                tool_name=tool_name,
                output="",
                success=False,
                error=str(exc),
                duration_ms=0.0,
            )

    async def _execute_model_query(
        self,
        task_id: str,
        query: str,
        session_id: str,
    ) -> ExecutionResult:
        """Ask the executor model a focused sub-question."""
        decision = self.routing.route(ModelRole.EXECUTOR)
        model_id = decision.model_id
        provider = self.providers.get(model_id) or next(iter(self.providers.values()), None)

        if not provider:
            return ExecutionResult(
                task_id=task_id,
                tool_name="model_query",
                output="",
                success=False,
                error="No executor model available",
                duration_ms=0.0,
            )

        messages = [
            {"role": "system", "content": EXECUTOR_SYSTEM_PROMPT},
            {"role": "user", "content": query},
        ]

        try:
            raw = await provider.chat(messages=messages)
            if isinstance(raw, dict):
                content = raw.get("message", {}).get("content", "") or raw.get("content", "")
            else:
                content = str(raw)

            return ExecutionResult(
                task_id=task_id,
                tool_name="model_query",
                output=content,
                success=True,
                duration_ms=0.0,
                model_used=model_id,
            )
        except Exception as exc:
            return ExecutionResult(
                task_id=task_id,
                tool_name="model_query",
                output="",
                success=False,
                error=str(exc),
                duration_ms=0.0,
                model_used=model_id,
            )

    def _resolve_refs(self, args: dict, outputs: dict[str, str]) -> dict:
        """Replace {key} references in args with actual output values."""
        resolved = {}
        for k, v in args.items():
            if isinstance(v, str) and v.startswith("{") and v.endswith("}"):
                ref_key = v[1:-1]
                resolved[k] = outputs.get(ref_key, v)
            else:
                resolved[k] = v
        return resolved

    @property
    def call_count(self) -> int:
        return self._call_count

    @property
    def tool_call_count(self) -> int:
        return self._tool_call_count
