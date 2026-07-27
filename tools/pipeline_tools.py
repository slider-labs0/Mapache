"""
pipeline_tools.py — the Vulnresearch pipeline runner.

`vuln_research` seeds the five-stage pipeline (scanner → detector → verifier →
patcher → exploiter) as OPPLAN objectives for a target, then tells the lead to
delegate each stage in order. State flows between stages through the knowledge
graph — each stage spawns fresh and reads prior stages' findings via `kg_query`,
records its own via `kg_add`. Reuses OPPLAN + operators + delegation rather than a
bespoke orchestrator, so every stage benefits from scope/OPSEC/logging.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from plugins.sdk.base_tool import BaseTool, ToolResult

# What each stage is asked to do (the objective text seeded into the OPPLAN).
_STAGE_TASK = {
    "scanner": "surface vulnerability candidates (CVE/CVSS) on {target}",
    "detector": "analyze the candidates into confidence-rated findings",
    "verifier": "confirm findings (2+ methods for CRITICAL/HIGH)",
    "patcher": "produce a patch or configuration fix for each verified finding",
    "exploiter": "build a working proof-of-concept for a verified finding",
}


class VulnResearchTool(BaseTool):
    name = "vuln_research"
    description = (
        "Run the vulnerability-research pipeline on a target: seeds the five staged "
        "objectives (scanner → detector → verifier → patcher → exploiter) into the "
        "OPPLAN. Then delegate each stage IN ORDER via delegate(operator=<stage>); "
        "stages pass state through the knowledge graph (kg_query/kg_add), each with a "
        "fresh context. Use for a structured vuln-research engagement."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "The in-scope target to research."},
        },
        "required": ["target"],
    }
    tags = ["pipeline", "planning", "vulnresearch"]

    def __init__(self, opplan_provider: Callable[[], Any]) -> None:
        self._provider = opplan_provider

    async def execute(self, **kwargs: Any) -> ToolResult:
        plan = self._provider()
        if plan is None:
            return ToolResult.ok("No OPPLAN configured; cannot seed the pipeline.")
        target = (kwargs.get("target") or "").strip()
        if not target:
            return ToolResult.fail("A target is required.")
        from core.operators import VULN_PIPELINE, get_operator

        seeded = []
        for stage in VULN_PIPELINE:
            op = get_operator(stage)
            title = op.title if op else stage
            task = _STAGE_TASK.get(stage, stage).format(target=target)
            obj = plan.add(f"{title}: {task}", operator=stage)
            if obj is not None:
                seeded.append(obj)
        return ToolResult.ok(
            f"Seeded the vuln-research pipeline for {target} "
            f"({len(seeded)} stages):\n{plan.table()}\n\n"
            "Now delegate each stage IN ORDER, e.g. "
            "delegate(operator='scanner', task='<its objective>'). Mark each "
            "objective in_progress when you dispatch it and passed/blocked from the "
            "stage's report. Stages share findings via the knowledge graph.")
