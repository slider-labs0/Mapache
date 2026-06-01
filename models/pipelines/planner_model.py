"""
planner_model.py — Mapache planner pipeline stage

The planner is the strategic brain of the multi-model pipeline.
It receives the user's goal and produces a structured execution plan
using the highest-quality available model.

In single-model mode this is the same model that executes.
In pipeline mode this is the best reasoning model available —
could be a large local model or a cloud model like Claude/GPT-4o.

The planner's job:
    1. Understand the goal
    2. Check what prior knowledge exists (memory)
    3. Decompose into ordered steps
    4. Identify which tools each step needs
    5. Estimate complexity and flag risks
    6. Produce a JSON plan the task manager can execute

The planner does NOT execute — it only reasons and plans.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from core.logger import get_logger
from models.model_registry import ModelRole
from models.routing_engine import RoutingEngine

logger = get_logger(__name__)


PLANNER_SYSTEM_PROMPT = """You are the planning module of Mapache, an autonomous security research agent.

Your ONLY job is to decompose goals into executable plans. You do NOT execute anything.

Given a goal and available tools, produce a JSON plan with ordered steps.

OUTPUT FORMAT — respond with ONLY valid JSON, no markdown:
{
  "reasoning": "brief explanation of your approach",
  "complexity": "simple|moderate|complex",
  "estimated_steps": 3,
  "risks": ["list of potential issues"],
  "tasks": [
    {
      "id": "t1",
      "type": "tool_call|model_query|noop",
      "description": "what this step does",
      "tool_name": "tool_name_here",
      "tool_args": {"arg": "value"},
      "depends_on": [],
      "output_key": "optional_key_to_store_result"
    }
  ]
}

PLANNING RULES:
- Only use tools listed as available
- Start with memory_recall if the goal involves a known target
- For recon tasks: nmap_scan → searchsploit/msf_search → burp_scan (if web)
- After any recon: include memory_target_store as final step
- Keep plans minimal — don't add unnecessary steps
- For simple questions that need no tools, use type "noop"
- Reference prior step outputs with {output_key} in tool_args"""


@dataclass
class PlannerOutput:
    """Structured output from the planner."""
    reasoning: str
    complexity: str  # simple | moderate | complex
    estimated_steps: int
    risks: list[str]
    tasks: list[dict[str, Any]]
    raw_response: str = ""
    model_used: str = ""
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None and len(self.tasks) > 0

    def to_plan_dict(self) -> dict:
        return {
            "reasoning": self.reasoning,
            "complexity": self.complexity,
            "tasks": self.tasks,
        }


class PlannerModel:
    """
    Planning stage of the multi-model pipeline.

    Uses the highest-quality available model to produce execution plans.
    Separate from the executor so a fast model can execute while a
    powerful model handles strategic reasoning.
    """

    def __init__(
        self,
        routing_engine: RoutingEngine,
        model_providers: dict[str, Any],  # model_id → provider instance
        available_tools: Optional[list[str]] = None,
    ) -> None:
        self.routing = routing_engine
        self.providers = model_providers
        self.available_tools = available_tools or []
        self._call_count = 0

    def set_available_tools(self, tools: list[str]) -> None:
        self.available_tools = tools

    async def plan(
        self,
        goal: str,
        context: Optional[str] = None,
        memory_snippets: Optional[list[str]] = None,
    ) -> PlannerOutput:
        """
        Generate an execution plan for a goal.

        Args:
            goal: The user's request
            context: Additional context (session history summary, etc.)
            memory_snippets: Relevant facts from memory store
        """
        self._call_count += 1

        # Get routing decision
        decision = self.routing.route(ModelRole.PLANNER)
        model_id = decision.model_id
        provider = self.providers.get(model_id)

        if not provider:
            # Fall back to any available provider
            provider = next(iter(self.providers.values()), None)
            if provider:
                model_id = next(iter(self.providers.keys()))

        if not provider:
            return PlannerOutput(
                reasoning="No model provider available",
                complexity="unknown",
                estimated_steps=0,
                risks=["No model configured"],
                tasks=[{"type": "noop", "description": goal}],
                error="no_provider",
            )

        logger.info(
            "Planner using: %s (strategy=%s)",
            model_id, self.routing.strategy.value,
        )

        # Build planning prompt
        user_content = self._build_prompt(goal, context, memory_snippets)

        messages = [
            {"role": "system", "content": PLANNER_SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]

        # Call the planner model
        try:
            raw = await provider.chat(messages=messages, json_mode=True)
            if isinstance(raw, dict):
                content = raw.get("message", {}).get("content", "") or raw.get("content", "")
            else:
                content = str(raw)
        except Exception as exc:
            logger.error("Planner model call failed: %s", exc)
            return self._passthrough_plan(goal, model_id, str(exc))

        # Parse the plan
        return self._parse_output(content, model_id)

    def _build_prompt(
        self,
        goal: str,
        context: Optional[str],
        memory_snippets: Optional[list[str]],
    ) -> str:
        parts = []

        if memory_snippets:
            parts.append("RELEVANT MEMORY:")
            for snippet in memory_snippets[:5]:
                parts.append(f"  - {snippet[:200]}")
            parts.append("")

        if context:
            parts.append(f"SESSION CONTEXT:\n{context[:500]}\n")

        tools_str = ", ".join(self.available_tools) if self.available_tools else "none"
        parts.append(f"AVAILABLE TOOLS: {tools_str}")
        parts.append(f"\nGOAL: {goal}")

        return "\n".join(parts)

    def _parse_output(self, content: str, model_id: str) -> PlannerOutput:
        """Parse the model's JSON response into a PlannerOutput."""
        # Strip markdown fences if present
        cleaned = content.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            cleaned = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            logger.warning("Planner JSON parse failed: %s", exc)
            return PlannerOutput(
                reasoning="Parse failed — using passthrough",
                complexity="unknown",
                estimated_steps=1,
                risks=[],
                tasks=[],
                raw_response=content,
                model_used=model_id,
                error=f"json_parse_error: {exc}",
            )

        tasks = []
        for t in data.get("tasks", []):
            from uuid import uuid4
            task = {
                "id": t.get("id", str(uuid4())[:6]),
                "type": t.get("type", "tool_call"),
                "description": t.get("description", ""),
                "tool_name": t.get("tool_name"),
                "tool_args": t.get("tool_args", {}),
                "depends_on": t.get("depends_on", []),
                "output_key": t.get("output_key"),
            }
            tasks.append(task)

        return PlannerOutput(
            reasoning=data.get("reasoning", ""),
            complexity=data.get("complexity", "moderate"),
            estimated_steps=data.get("estimated_steps", len(tasks)),
            risks=data.get("risks", []),
            tasks=tasks,
            raw_response=content,
            model_used=model_id,
        )

    def _passthrough_plan(self, goal: str, model_id: str, error: str) -> PlannerOutput:
        """Fallback plan when planning fails."""
        return PlannerOutput(
            reasoning="Planning failed — direct execution",
            complexity="unknown",
            estimated_steps=1,
            risks=[error],
            tasks=[{"id": "t1", "type": "noop", "description": goal}],
            model_used=model_id,
            error=error,
        )

    @property
    def call_count(self) -> int:
        return self._call_count
