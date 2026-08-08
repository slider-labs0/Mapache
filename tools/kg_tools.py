"""
kg_tools.py - agent-callable knowledge-graph tools (fresh-context state store).

A sub-agent spawned with a clean context uses these to pull what earlier agents
found (`kg_query`) and to record its own findings for the next stage (`kg_add`),
instead of relying on conversation memory. The live `KnowledgeGraph` is read
through a provider so the CLI can wire it after the controller is built; with no
graph configured the tools report that plainly rather than erroring.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from plugins.sdk.base_tool import BaseTool, ToolResult


def _fmt(entities: list) -> str:
    if not entities:
        return "No matching findings in the knowledge graph."
    lines = []
    for e in entities[:50]:
        extra = ""
        if e.attrs:
            bits = ", ".join(f"{k}={v}" for k, v in list(e.attrs.items())[:4])
            extra = f"  [{bits}]"
        src = f" ({e.source})" if e.source else ""
        lines.append(f"  {e.type}: {e.value}{extra}{src}")
    return "\n".join(lines)


class _KGMixin:
    def __init__(self, kg_provider: Callable[[], Any]) -> None:
        self._kg = kg_provider

    def kg(self) -> Optional[Any]:
        return self._kg()


class KGQueryTool(_KGMixin, BaseTool):
    name = "kg_query"
    description = (
        "Query the shared knowledge graph for findings recorded by you or other "
        "agents (hosts, services, credentials, vulnerabilities, flags, notes). Use "
        "this at the start of an objective to learn what's already known instead of "
        "re-discovering it."
    )
    parameters = {
        "type": "object",
        "properties": {
            "type": {"type": "string",
                     "description": "Filter by entity type: host, service, credential, "
                                    "vulnerability, flag, finding, note (optional)."},
            "contains": {"type": "string",
                         "description": "Only findings whose value/attrs contain this text (optional)."},
        },
    }
    tags = ["knowledge", "state"]

    async def execute(self, **kwargs: Any) -> ToolResult:
        kg = self.kg()
        if kg is None:
            return ToolResult.ok("No knowledge graph configured.")
        ents = kg.query(type=(kwargs.get("type") or None),
                        contains=(kwargs.get("contains") or None))
        header = f"Knowledge graph ({kg.summary()}):\n"
        return ToolResult.ok(header + _fmt(ents))


class KGAddTool(_KGMixin, BaseTool):
    name = "kg_add"
    description = (
        "Record a finding in the shared knowledge graph so later agents (and the "
        "lead) can use it. Persists to disk - survives across objectives and fresh "
        "context windows."
    )
    parameters = {
        "type": "object",
        "properties": {
            "type": {"type": "string",
                     "description": "host | service | credential | vulnerability | flag | finding | note"},
            "value": {"type": "string", "description": "The finding itself."},
            "note": {"type": "string", "description": "Optional detail/context."},
        },
        "required": ["type", "value"],
    }
    tags = ["knowledge", "state"]

    async def execute(self, **kwargs: Any) -> ToolResult:
        kg = self.kg()
        if kg is None:
            return ToolResult.ok("No knowledge graph configured.")
        attrs = {"note": kwargs["note"]} if kwargs.get("note") else None
        ent = kg.add(kwargs.get("type", ""), kwargs.get("value", ""),
                     attrs=attrs, source="agent")
        if ent is None:
            return ToolResult.fail(
                "Could not record: need a valid type (host/service/credential/"
                "vulnerability/flag/finding/note) and a non-empty value.")
        return ToolResult.ok(f"Recorded {ent.type}: {ent.value}")
