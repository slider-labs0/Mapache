"""
opplan_tools.py - agent-callable OPPLAN tools (operation-plan management).

The lead orchestrator seeds objectives, then transitions each one through
pending → in_progress → passed | blocked as it dispatches specialists and reads
their reports. The live OPPLAN is read through a provider so the CLI can wire it
after the controller is built; with no plan configured the tools say so plainly.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from plugins.sdk.base_tool import BaseTool, ToolResult


class _OpplanMixin:
    def __init__(self, provider: Callable[[], Any]) -> None:
        self._provider = provider

    def plan(self) -> Optional[Any]:
        return self._provider()


class OpplanAddTool(_OpplanMixin, BaseTool):
    name = "opplan_add"
    description = (
        "Add an objective to the operation plan (OPPLAN). Optionally name the "
        "specialist that owns it (e.g. recon_operator, exploit_operator, "
        "post_operator). New objectives start 'pending'."
    )
    parameters = {
        "type": "object",
        "properties": {
            "objective": {"type": "string", "description": "The objective text."},
            "operator": {"type": "string",
                         "description": "Owning specialist (optional)."},
        },
        "required": ["objective"],
    }
    tags = ["opplan", "planning"]

    async def execute(self, **kwargs: Any) -> ToolResult:
        plan = self.plan()
        if plan is None:
            return ToolResult.ok("No OPPLAN configured.")
        obj = plan.add(kwargs.get("objective", ""), kwargs.get("operator", ""))
        if obj is None:
            return ToolResult.fail("Objective text is required.")
        return ToolResult.ok(f"Added objective #{obj.id}: {obj.text}\n\n{plan.table()}")


class OpplanUpdateTool(_OpplanMixin, BaseTool):
    name = "opplan_update"
    description = (
        "Update an objective's status as work progresses: mark it in_progress when "
        "you dispatch it, then passed or blocked from the specialist's report. "
        "Reference by #id or a substring of its text; add a short note for the "
        "result or blocker."
    )
    parameters = {
        "type": "object",
        "properties": {
            "objective": {"type": "string",
                          "description": "The objective's #id or a text substring."},
            "status": {"type": "string",
                       "description": "pending | in_progress | passed | blocked"},
            "note": {"type": "string", "description": "Short result/blocker detail (optional)."},
        },
        "required": ["objective", "status"],
    }
    tags = ["opplan", "planning"]

    async def execute(self, **kwargs: Any) -> ToolResult:
        plan = self.plan()
        if plan is None:
            return ToolResult.ok("No OPPLAN configured.")
        ok = plan.update(kwargs.get("objective", ""),
                         status=kwargs.get("status"),
                         note=kwargs.get("note"))
        if not ok:
            return ToolResult.fail(
                "No such objective, or invalid status (use pending/in_progress/"
                "passed/blocked).")
        return ToolResult.ok(f"Updated.\n\n{plan.table()}")


class OpplanShowTool(_OpplanMixin, BaseTool):
    name = "opplan_show"
    description = "Show the current operation plan (OPPLAN) with objective statuses."
    parameters = {"type": "object", "properties": {}}
    tags = ["opplan", "planning"]

    async def execute(self, **kwargs: Any) -> ToolResult:
        plan = self.plan()
        if plan is None:
            return ToolResult.ok("No OPPLAN configured.")
        return ToolResult.ok(plan.table() or "OPPLAN is empty. Add objectives with opplan_add.")
