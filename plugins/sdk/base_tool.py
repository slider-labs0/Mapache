"""
base_tool.py - Mapache tool SDK base class

Every tool in Mapache - built-in or user-uploaded - extends BaseTool.
This defines the contract the tool dispatcher expects.

A tool is:
  - A name + description the model can read
  - A JSON schema describing its parameters
  - An async execute() method that does the work
  - A set of permission flags the registry enforces

Minimal tool example:
    class EchoTool(BaseTool):
        name = "echo"
        description = "Repeat text back"
        parameters = {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        }
        async def execute(self, text: str, **kwargs) -> ToolResult:
            return ToolResult.ok(text)
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Permission(str, Enum):
    """Permission flags a tool can require. Enforced by the registry."""
    SHELL         = "shell"          # run subprocesses
    FILESYSTEM    = "filesystem"     # read/write files
    NETWORK       = "network"        # make network requests
    SYSTEM_INFO   = "system_info"    # read OS/hardware info
    BROWSER       = "browser"        # control a browser
    TOR           = "tor"            # route through Tor
    DANGEROUS     = "dangerous"      # destructive ops (write, delete, exploit)
    UNRESTRICTED  = "unrestricted"   # bypass all sandbox checks


@dataclass
class ToolResult:
    """Standardized return value from every tool execution."""

    output: str
    success: bool = True
    error: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0

    @classmethod
    def ok(cls, output: str, metadata: dict | None = None) -> "ToolResult":
        return cls(output=output, success=True, metadata=metadata or {})

    @classmethod
    def fail(cls, error: str, output: str = "") -> "ToolResult":
        return cls(output=output, success=False, error=error)

    def to_string(self) -> str:
        """What gets injected back into the model context."""
        if self.success:
            return self.output or "(no output)"
        return f"Error: {self.error}" + (f"\n{self.output}" if self.output else "")


class BaseTool(ABC):
    """
    Abstract base for all Mapache tools.

    Subclasses must define:
        name        - unique identifier (snake_case)
        description - shown to the model, be specific
        parameters  - JSON schema (OpenAI function calling format)

    Subclasses should define (optional):
        permissions     - set of Permission flags required
        timeout         - override default execution timeout
        version         - semver string
        tags            - list of category strings

    Subclasses must implement:
        execute(**kwargs) → ToolResult
    """

    # Required class attributes
    name: str = ""
    description: str = ""
    parameters: dict[str, Any] = {}

    # Optional class attributes
    permissions: set[Permission] = set()
    timeout: int = 30
    version: str = "0.1.0"
    tags: list[str] = []
    enabled: bool = True

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not cls.name:
            raise TypeError(f"{cls.__name__} must define a 'name' class attribute")

    @abstractmethod
    async def execute(self, **kwargs: Any) -> ToolResult:
        """
        Execute the tool with the given arguments.
        kwargs are validated against self.parameters before this is called.
        Always return a ToolResult - never raise from here.
        """
        ...

    async def __call__(self, **kwargs: Any) -> ToolResult:
        """Timed wrapper around execute()."""
        start = time.monotonic()
        result = await self.execute(**kwargs)
        result.duration_ms = (time.monotonic() - start) * 1000
        return result

    def to_schema(self) -> dict[str, Any]:
        """Return the OpenAI-compatible function schema for this tool."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_context_schema(self) -> "ToolSchema":
        """Return a ContextBuilder-compatible ToolSchema."""
        from core.context_builder import ToolSchema
        return ToolSchema(
            name=self.name,
            description=self.description,
            parameters=self.parameters,
        )

    def requires_permission(self, perm: Permission) -> bool:
        return perm in self.permissions

    def __repr__(self) -> str:
        return f"<Tool:{self.name} v{self.version} perms={[p.value for p in self.permissions]}>"
