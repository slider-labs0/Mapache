"""
tool_registry.py - Mapache tool registry

Central store of all available tools. Tools register here at startup.
The dispatcher queries the registry to find and invoke tools.
The agent controller queries it to build the model's tool schema list.

Usage:
    registry = ToolRegistry()
    registry.register(NmapTool())
    registry.register(ShellTool())

    tool = registry.get("nmap_scan")
    all_schemas = registry.get_all_schemas()
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

logger = logging.getLogger(__name__)


class ToolNotFoundError(Exception):
    def __init__(self, name: str) -> None:
        super().__init__(f"Tool not found: '{name}'")
        self.tool_name = name


class PermissionDeniedError(Exception):
    def __init__(self, tool_name: str, permission: Permission) -> None:
        super().__init__(
            f"Tool '{tool_name}' requires '{permission.value}' permission which is not granted"
        )
        self.tool_name = tool_name
        self.permission = permission


class ToolNameCollisionError(Exception):
    """A tool tried to claim a name already held by a different tool."""
    def __init__(self, name: str, incumbent: str) -> None:
        super().__init__(
            f"Tool name '{name}' is already registered by {incumbent}; "
            f"pass replace=True to intentionally replace it")
        self.tool_name = name


class ToolRegistry:
    """
    Central registry of all available tools.

    Features:
    - Register / unregister tools by name
    - Permission enforcement per tool
    - Tag-based filtering
    - Schema export for model context
    - Enabled/disabled per tool
    """

    def __init__(self, granted_permissions: set[Permission] | None = None) -> None:
        self._tools: dict[str, BaseTool] = {}
        # Permissions granted to this registry instance
        # Default: shell, filesystem, network, system_info
        self.granted_permissions: set[Permission] = granted_permissions or {
            Permission.SHELL,
            Permission.FILESYSTEM,
            Permission.NETWORK,
            Permission.SYSTEM_INFO,
        }

    # ------------------------------------------------------------------ #
    # Registration
    # ------------------------------------------------------------------ #

    def register(self, tool: BaseTool, *, replace: bool = False) -> None:
        """Register a tool by name.

        Name-collision guard: a *different* tool may not silently overwrite an
        existing name - that lets one source (e.g. a self-authored `create_tool`
        tool) shadow another (e.g. an installed GitHub/integration tool of the same
        name), which is almost always a mistake. On collision this raises
        `ToolNameCollisionError` unless `replace=True` is passed to signal an
        intentional update (a reinstall, a live refresh). Re-registering the *same*
        tool instance is always a harmless no-op.
        """
        if not tool.name:
            raise ValueError(f"Tool {tool.__class__.__name__} has no name")
        existing = self._tools.get(tool.name)
        if existing is not None and existing is not tool and not replace:
            raise ToolNameCollisionError(tool.name, type(existing).__name__)
        self._tools[tool.name] = tool
        verb = "replaced" if (existing is not None and existing is not tool) else "registered"
        logger.info("Tool %s: %s (perms=%s)", verb, tool.name,
                    [p.value for p in tool.permissions])

    def unregister(self, name: str) -> None:
        removed = self._tools.pop(name, None)
        if removed:
            logger.info("Tool unregistered: %s", name)

    def register_many(self, tools: list[BaseTool]) -> None:
        for tool in tools:
            self.register(tool)

    def clone_with_backend(self, backend: Any) -> "ToolRegistry":
        """A copy of this registry where every backend-aware tool (ShellTool,
        NmapTool, KaliRunTool, the MSF tools …) is rebound to `backend`, and every
        other tool is shared as-is.

        This is how a delegated sub-agent gets its OWN execution terminal: the lead
        clones its dispatcher onto a per-sub-agent backend (e.g. that agent's own
        container/SSH host), so the child's shell/nmap/msf run there, isolated from
        the lead's. Tools are stateless config wrappers, so a shallow copy with a
        swapped `.backend` is safe; sharing the non-backend tools avoids needless
        duplication."""
        import copy as _copy
        clone = ToolRegistry(granted_permissions=set(self.granted_permissions))
        for tool in self._tools.values():
            if hasattr(tool, "backend"):
                rebound = _copy.copy(tool)
                rebound.backend = backend
                clone._tools[tool.name] = rebound
            else:
                clone._tools[tool.name] = tool
        return clone

    # ------------------------------------------------------------------ #
    # Lookup
    # ------------------------------------------------------------------ #

    def get(self, name: str) -> BaseTool:
        """Get a tool by name. Raises ToolNotFoundError if missing."""
        tool = self._tools.get(name)
        if tool is None:
            raise ToolNotFoundError(name)
        return tool

    def get_optional(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def has(self, name: str) -> bool:
        return name in self._tools

    def list_names(self) -> list[str]:
        return [name for name, t in self._tools.items() if t.enabled]

    def list_by_tag(self, tag: str) -> list[BaseTool]:
        return [t for t in self._tools.values() if tag in t.tags and t.enabled]

    def list_all(self) -> list[BaseTool]:
        return [t for t in self._tools.values() if t.enabled]

    # ------------------------------------------------------------------ #
    # Permission checking
    # ------------------------------------------------------------------ #

    def check_permissions(self, tool: BaseTool) -> None:
        """
        Raise PermissionDeniedError if the tool requires a permission
        that hasn't been granted to this registry.
        """
        if Permission.UNRESTRICTED in self.granted_permissions:
            return
        for perm in tool.permissions:
            if perm not in self.granted_permissions:
                raise PermissionDeniedError(tool.name, perm)

    def grant_permission(self, perm: Permission) -> None:
        self.granted_permissions.add(perm)
        logger.info("Permission granted: %s", perm.value)

    def revoke_permission(self, perm: Permission) -> None:
        self.granted_permissions.discard(perm)
        logger.info("Permission revoked: %s", perm.value)

    # ------------------------------------------------------------------ #
    # Schema export for model context
    # ------------------------------------------------------------------ #

    def get_all_schemas(self) -> list[dict[str, Any]]:
        """Return OpenAI-compatible function schemas for all enabled tools."""
        return [t.to_schema() for t in self._tools.values() if t.enabled]

    def get_context_schemas(self) -> list:
        """Return ContextBuilder ToolSchema objects for all enabled tools."""
        return [t.to_context_schema() for t in self._tools.values() if t.enabled]

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #

    def summary(self) -> str:
        lines = [f"ToolRegistry ({len(self._tools)} tools):"]
        for name, tool in self._tools.items():
            status = "ok" if tool.enabled else "x"
            perms = ",".join(p.value for p in tool.permissions) or "none"
            lines.append(f"  {status} {name:30s} v{tool.version}  [{perms}]")
        return "\n".join(lines)

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools
