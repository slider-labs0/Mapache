"""
tools.py — agent-callable hub tools (feature I): skill_search / list / install.

Each tool reads the live HubClient through a provider, so the CLI can wire the
registry after the controller is built. When no hub/registry is configured the
tools report that plainly rather than erroring.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from plugins.sdk.base_tool import BaseTool, ToolResult


def _fmt(skills: list) -> str:
    if not skills:
        return "No skills found."
    lines = []
    for m in skills:
        sig = " ✓signed" if m.signature else ""
        lines.append(f"  {m.name} v{m.version} [{m.skill_type}]{sig} — {m.description}")
    return "\n".join(lines)


# Mixin (NOT a BaseTool subclass, so it needn't define name/description) holding
# the shared lazy client accessor; concrete tools inherit (mixin, BaseTool).
class _HubMixin:
    def __init__(self, client_provider: Callable[[], Any]) -> None:
        self._client = client_provider

    def client(self) -> Optional[Any]:
        return self._client()


class SkillSearchTool(_HubMixin, BaseTool):
    name = "skill_search"
    description = ("Search the community skill hub for installable skills "
                  "(generated tools, MCP servers) matching a query.")
    parameters = {
        "type": "object",
        "properties": {"query": {"type": "string", "description": "Search terms."}},
    }
    tags = ["hub", "skills"]

    async def execute(self, **kwargs: Any) -> ToolResult:
        client = self.client()
        if client is None:
            return ToolResult.ok("No skill hub configured (set hub.registry in config).")
        return ToolResult.ok(_fmt(client.search(kwargs.get("query", ""))))


class SkillListTool(_HubMixin, BaseTool):
    name = "skill_list"
    description = "List all skills available in the configured community hub registry."
    parameters = {"type": "object", "properties": {}}
    tags = ["hub", "skills"]

    async def execute(self, **kwargs: Any) -> ToolResult:
        client = self.client()
        if client is None:
            return ToolResult.ok("No skill hub configured (set hub.registry in config).")
        return ToolResult.ok(_fmt(client.list_skills()))


class SkillInstallTool(_HubMixin, BaseTool):
    name = "skill_install"
    description = (
        "Install a skill from the community hub by name. Runs third-party code: "
        "the package's checksum (and signature, if a trusted key is set) is verified "
        "before install, and it only takes effect on the next start so it can be "
        "reviewed first."
    )
    parameters = {
        "type": "object",
        "properties": {"name": {"type": "string", "description": "Skill name to install."}},
        "required": ["name"],
    }
    tags = ["hub", "skills"]

    async def execute(self, **kwargs: Any) -> ToolResult:
        client = self.client()
        if client is None:
            return ToolResult.ok("No skill hub configured (set hub.registry in config).")
        name = (kwargs.get("name") or "").strip()
        if not name:
            return ToolResult.ok("No skill name provided.")
        return ToolResult.ok(client.install(name))
