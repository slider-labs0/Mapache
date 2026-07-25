"""
tool_dispatcher.py — Mapache tool dispatcher

Sits between the agent controller and the tool registry.
Every tool call from the model passes through here.

Responsibilities:
- Look up the tool in the registry
- Check permissions
- Validate arguments against the tool's JSON schema
- Execute the tool
- Return structured output back to the agent

This replaces the Phase 1 ShellDispatcher stub entirely.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from core.engagement_scope import EngagementScope
from plugins.sdk.base_tool import Permission, ToolResult
from tools.tool_registry import (
    PermissionDeniedError,
    ToolNotFoundError,
    ToolRegistry,
)
from tools.tool_schema import SchemaValidationError, validate_args

logger = logging.getLogger(__name__)


class ToolDispatcher:
    """
    Routes tool calls from the agent to registered tools.

    Usage:
        dispatcher = ToolDispatcher(registry)
        output = await dispatcher.dispatch("nmap_scan", {"host": "192.168.1.1"}, session_id)
    """

    def __init__(
        self, registry: ToolRegistry, scope: Optional[EngagementScope] = None
    ) -> None:
        self.registry = registry
        # Rules-of-Engagement gate (feature J), defense-in-depth: the controller
        # already gates the model's calls, but generated tools dispatch shell
        # directly through here, bypassing that gate — so re-check at the choke
        # point every tool actually flows through. Inactive scope → no-op.
        self.scope = scope or EngagementScope()
        self._call_count: int = 0
        self._error_count: int = 0
        self._refused_count: int = 0

    def with_backend(self, backend: Any) -> "ToolDispatcher":
        """A sibling dispatcher whose backend-aware tools run on `backend` — used
        to give a delegated sub-agent its own execution terminal (feature H + P).
        Shares the same RoE scope; call-count stats start fresh for the child."""
        return ToolDispatcher(self.registry.clone_with_backend(backend), scope=self.scope)

    async def dispatch(
        self,
        tool_name: str,
        args: dict[str, Any],
        session_id: str = "",
    ) -> str:
        """
        Dispatch a tool call and return string output for the model.

        Never raises — all errors are returned as descriptive strings
        so the model can reason about what went wrong.
        """
        self._call_count += 1
        logger.info("Dispatch: %s(%s) session=%s", tool_name, list(args.keys()), session_id[:8])

        # 1. Look up tool
        try:
            tool = self.registry.get(tool_name)
        except ToolNotFoundError:
            self._error_count += 1
            available = ", ".join(self.registry.list_names())
            return (
                f"Error: Tool '{tool_name}' not found.\n"
                f"Available tools: {available or 'none'}"
            )

        # 2. Check enabled
        if not tool.enabled:
            self._error_count += 1
            return f"Error: Tool '{tool_name}' is currently disabled."

        # 3. Check permissions
        try:
            self.registry.check_permissions(tool)
        except PermissionDeniedError as exc:
            self._error_count += 1
            logger.warning("Permission denied: %s", exc)
            return f"Error: {exc}"

        # 3b. Rules-of-Engagement scope (feature J). No attack-state target is
        # available here (that's the controller's gate); this catches forbidden
        # tools/patterns and any host named directly in the args.
        decision = self.scope.check(tool_name, args)
        if not decision.allowed:
            self._refused_count += 1
            logger.warning("RoE refused %s: %s", tool_name, decision.reason)
            return (
                f"REFUSED by engagement scope: {decision.reason}. "
                "This action was NOT executed."
            )

        # 4. Validate arguments
        try:
            validated_args = validate_args(tool_name, tool.parameters, args)
        except SchemaValidationError as exc:
            self._error_count += 1
            logger.warning("Schema validation failed: %s", exc)
            return (
                f"Error: Invalid arguments for tool '{tool_name}'.\n"
                f"Problems: {'; '.join(exc.errors)}\n"
                f"Expected schema: {tool.parameters}"
            )

        # 5. Execute
        try:
            result: ToolResult = await tool(**validated_args)
        except Exception as exc:
            self._error_count += 1
            logger.error("Tool execution error (%s): %s", tool_name, exc, exc_info=True)
            return f"Error: Tool '{tool_name}' raised an exception: {exc}"

        logger.info(
            "Tool %s completed in %.0fms success=%s",
            tool_name, result.duration_ms, result.success,
        )

        return result.to_string()

    # ------------------------------------------------------------------ #
    # Stats
    # ------------------------------------------------------------------ #

    @property
    def call_count(self) -> int:
        return self._call_count

    @property
    def error_count(self) -> int:
        return self._error_count

    @property
    def refused_count(self) -> int:
        return self._refused_count

    @property
    def success_rate(self) -> float:
        if self._call_count == 0:
            return 1.0
        return (self._call_count - self._error_count) / self._call_count
