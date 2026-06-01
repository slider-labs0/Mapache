"""
planner.py — Mapache goal planner

Receives a user goal and decomposes it into an ordered list of tasks.
Uses the model itself to reason about what steps are needed, then emits
a plan onto the event bus for the task manager to execute.

The planner runs as a lightweight model call with a focused system prompt.
It does NOT execute — it only reasons and emits.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from .event_bus import Event, EventBus

logger = logging.getLogger(__name__)


class TaskType(str, Enum):
    TOOL_CALL = "tool_call"       # invoke a registered tool
    MODEL_QUERY = "model_query"   # ask the model a sub-question
    SHELL = "shell"               # run a shell command directly
    NOOP = "noop"                 # placeholder / already answered


@dataclass
class PlannedTask:
    """A single step in a plan."""

    id: str = field(default_factory=lambda: str(uuid4())[:8])
    type: TaskType = TaskType.TOOL_CALL
    description: str = ""
    tool_name: Optional[str] = None
    tool_args: dict[str, Any] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)  # task IDs
    output_key: Optional[str] = None  # store result under this key for later tasks
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "description": self.description,
            "tool_name": self.tool_name,
            "tool_args": self.tool_args,
            "depends_on": self.depends_on,
            "output_key": self.output_key,
        }


@dataclass
class Plan:
    """An ordered collection of tasks to fulfill a goal."""

    id: str = field(default_factory=lambda: str(uuid4()))
    goal: str = ""
    tasks: list[PlannedTask] = field(default_factory=list)
    reasoning: str = ""
    session_id: Optional[str] = None

    def is_simple(self) -> bool:
        """Single-step plans skip the full planner loop."""
        return len(self.tasks) <= 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "goal": self.goal,
            "tasks": [t.to_dict() for t in self.tasks],
            "reasoning": self.reasoning,
        }


# Focused system prompt — planner only reasons, never executes
PLANNER_SYSTEM_PROMPT = """You are a planning module. Your only job is to decompose a user goal \
into an ordered list of concrete steps that can be executed by available tools.

Output ONLY valid JSON. No markdown, no explanation outside the JSON.

Response format:
{
  "reasoning": "<brief explanation of your plan>",
  "tasks": [
    {
      "type": "tool_call",
      "description": "<what this step does>",
      "tool_name": "<name of tool to call>",
      "tool_args": { "<arg>": "<value>" },
      "output_key": "<optional key to store result>"
    }
  ]
}

Task types: "tool_call", "model_query", "shell", "noop"

Rules:
- Only use tools that are listed as available.
- If the goal can be answered directly without tools, use type "noop" with the answer in description.
- Keep plans minimal — don't add steps that aren't necessary.
- For tool_args, use concrete values where known, or use "{output_key}" to reference a prior step's output.
"""


class Planner:
    """
    Decomposes user goals into executable task plans.

    Lifecycle:
    1. Receives "agent.turn.start" event with user input
    2. Calls the model with a focused planning prompt
    3. Parses the model's JSON response into a Plan
    4. Emits "planner.plan_ready" with the plan

    The planner uses the same model provider as the agent but with a
    separate, shorter context (planning doesn't need conversation history).
    """

    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._model_caller: Any = None  # injected by AgentController
        self._available_tools: list[str] = []

        bus.subscribe("agent.turn.start", self._on_turn_start)
        logger.info("Planner initialized")

    def set_model_caller(self, caller: Any) -> None:
        """Inject the model caller (set by AgentController after model layer is ready)."""
        self._model_caller = caller

    def set_available_tools(self, tools: list[str]) -> None:
        self._available_tools = tools

    # ------------------------------------------------------------------ #
    # Event handler
    # ------------------------------------------------------------------ #

    async def _on_turn_start(self, event: Event) -> None:
        user_input: str = event.data.get("input", "")
        session_id: str = event.data.get("session_id", "")
        skip_planning: bool = event.data.get("skip_planning", False)

        if skip_planning or not user_input:
            return

        logger.debug("Planner received goal: %r", user_input[:80])

        try:
            plan = await self._build_plan(user_input, session_id)
            await self.bus.emit(
                "planner.plan_ready",
                {"plan": plan.to_dict(), "session_id": session_id},
                source="planner",
                session_id=session_id,
            )
        except Exception as exc:
            logger.error("Planning failed: %s", exc)
            await self.bus.emit(
                "planner.plan_failed",
                {"error": str(exc), "input": user_input},
                source="planner",
                session_id=session_id,
            )

    # ------------------------------------------------------------------ #
    # Plan construction
    # ------------------------------------------------------------------ #

    async def _build_plan(self, goal: str, session_id: str) -> Plan:
        """Call the model to produce a plan JSON, then parse it."""
        if self._model_caller is None:
            # No model yet — return a pass-through single-step plan
            return self._passthrough_plan(goal, session_id)

        tools_list = ", ".join(self._available_tools) if self._available_tools else "none"
        user_message = f"Available tools: {tools_list}\n\nGoal: {goal}"

        messages = [
            {"role": "system", "content": PLANNER_SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ]

        raw = await self._model_caller(messages, json_mode=True)
        return self._parse_plan(raw, goal, session_id)

    def _parse_plan(self, raw: str, goal: str, session_id: str) -> Plan:
        """Parse model JSON output into a Plan object."""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("Planner JSON parse failed, using passthrough: %s", exc)
            return self._passthrough_plan(goal, session_id)

        tasks = []
        for t in data.get("tasks", []):
            try:
                task = PlannedTask(
                    type=TaskType(t.get("type", "tool_call")),
                    description=t.get("description", ""),
                    tool_name=t.get("tool_name"),
                    tool_args=t.get("tool_args", {}),
                    output_key=t.get("output_key"),
                )
                tasks.append(task)
            except (ValueError, KeyError) as exc:
                logger.warning("Skipping malformed task in plan: %s", exc)

        if not tasks:
            return self._passthrough_plan(goal, session_id)

        return Plan(
            goal=goal,
            tasks=tasks,
            reasoning=data.get("reasoning", ""),
            session_id=session_id,
        )

    def _passthrough_plan(self, goal: str, session_id: str) -> Plan:
        """Fallback: single noop task — let the executor handle it as a direct response."""
        return Plan(
            goal=goal,
            tasks=[PlannedTask(type=TaskType.NOOP, description=goal)],
            reasoning="Direct response — no tools required.",
            session_id=session_id,
        )
