"""
mcp_client.py - Mapache MCP client (stdio transport)

Connects OUT to Model Context Protocol servers, launched as local subprocesses,
and adapts their tools into Mapache `BaseTool`s so the agent can call them
exactly like a built-in tool. Client-only: Mapache consumes MCP servers, it does
not (here) act as one.

Protocol: JSON-RPC 2.0 framed as newline-delimited JSON over the server's
stdin/stdout (the MCP stdio transport). We speak the minimum needed:
`initialize` → `notifications/initialized` → `tools/list` → `tools/call`.

Configuration is a Claude-Desktop-style JSON file:

    {
      "mcpServers": {
        "filesystem": {
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
          "env": {"FOO": "bar"}
        }
      }
    }

Tools are namespaced `mcp__<server>__<tool>` to avoid collisions with built-ins.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from typing import Any, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

logger = logging.getLogger(__name__)

# Protocol version we advertise; servers negotiate down if needed.
MCP_PROTOCOL_VERSION = "2024-11-05"
# Per-request timeout (seconds) for the handshake and tool calls.
DEFAULT_TIMEOUT = 30.0


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

@dataclass
class MCPServerConfig:
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    # Optional allowlist of remote tool names to expose. Empty = expose all. A big
    # server (e.g. a browser server with ~24 tools) is pinned into every prompt, so
    # trimming it here keeps the function-calling payload small enough for local
    # models with a limited context window.
    tools: list[str] = field(default_factory=list)
    # Per-request timeout (seconds). 0 = use DEFAULT_TIMEOUT. Raise it for a server
    # whose calls are slow, e.g. a browser routed over Tor (page loads take a while).
    timeout: float = 0.0


def load_mcp_config(path: str) -> list[MCPServerConfig]:
    """
    Parse a Claude-Desktop-style mcp.json. Returns [] if the file is absent so
    MCP is simply off when unconfigured.
    """
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not read MCP config %s: %s", path, exc)
        return []

    servers = data.get("mcpServers") or data.get("servers") or {}
    configs: list[MCPServerConfig] = []
    for name, spec in servers.items():
        command = (spec or {}).get("command")
        if not command:
            logger.warning("MCP server %r has no command - skipping", name)
            continue
        configs.append(MCPServerConfig(
            name=name,
            command=command,
            args=list(spec.get("args", []) or []),
            env={str(k): str(v) for k, v in (spec.get("env") or {}).items()},
            tools=[str(t) for t in (spec.get("tools") or [])],
            timeout=float(spec.get("timeout") or 0.0),
        ))
    return configs


# --------------------------------------------------------------------------- #
# stdio JSON-RPC client (one per server)
# --------------------------------------------------------------------------- #

class MCPError(Exception):
    pass


class MCPStdioClient:
    """A single MCP server connection over stdio."""

    def __init__(self, config: MCPServerConfig) -> None:
        self.config = config
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._next_id = 0
        self._lock = asyncio.Lock()  # serialize request/response on the pipe
        self.server_info: dict[str, Any] = {}
        self._timeout = config.timeout if config.timeout and config.timeout > 0 else DEFAULT_TIMEOUT

    @property
    def name(self) -> str:
        return self.config.name

    async def start(self) -> None:
        env = {**os.environ, **self.config.env}
        # Resolve the launcher through PATH honouring PATHEXT so bare commands
        # like "npx"/"uvx" - the way every Claude-Desktop-style mcp.json writes
        # them - find their real executable. On Windows create_subprocess_exec
        # will not resolve the `.cmd`/`.bat` shim itself, so without this the
        # canonical `"command": "npx"` fails with WinError 2 and MCP silently
        # no-ops. Fall back to the raw command (surfaces the same error as before)
        # when which() finds nothing.
        command = shutil.which(self.config.command) or self.config.command
        self._proc = await asyncio.create_subprocess_exec(
            command, *self.config.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
        )
        result = await self._request("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mapache", "version": "0.1.0"},
        })
        self.server_info = result.get("serverInfo", {})
        await self._notify("notifications/initialized", {})
        logger.info("MCP server %r initialized: %s", self.name, self.server_info)

    async def list_tools(self) -> list[dict[str, Any]]:
        result = await self._request("tools/list", {})
        return result.get("tools", []) or []

    async def call_tool(self, tool: str, arguments: dict[str, Any]) -> str:
        result = await self._request("tools/call", {
            "name": tool, "arguments": arguments or {},
        })
        return self._render_content(result)

    async def close(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.stdin and not self._proc.stdin.is_closing():
                self._proc.stdin.close()
            self._proc.terminate()
            await asyncio.wait_for(self._proc.wait(), timeout=5.0)
        except (ProcessLookupError, asyncio.TimeoutError):
            try:
                self._proc.kill()
            except ProcessLookupError:
                pass
        finally:
            self._proc = None

    # -- internals ------------------------------------------------------- #

    @staticmethod
    def _render_content(result: dict[str, Any]) -> str:
        """Flatten an MCP tools/call result into plain text for the model."""
        blocks = result.get("content", [])
        parts: list[str] = []
        for block in blocks:
            if isinstance(block, dict):
                if block.get("type") == "text":
                    parts.append(block.get("text", ""))
                else:
                    parts.append(json.dumps(block))
        text = "\n".join(p for p in parts if p) or "(no content)"
        if result.get("isError"):
            return f"[tool error] {text}"
        return text

    async def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
            raise MCPError(f"MCP server {self.name!r} is not running")

        async with self._lock:
            self._next_id += 1
            req_id = self._next_id
            await self._write({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})

            # Read until we see the response with our id, skipping notifications.
            while True:
                line = await asyncio.wait_for(
                    self._proc.stdout.readline(), timeout=self._timeout
                )
                if not line:
                    raise MCPError(f"MCP server {self.name!r} closed the connection")
                try:
                    msg = json.loads(line.decode("utf-8").strip())
                except json.JSONDecodeError:
                    continue  # ignore non-JSON noise on stdout
                if msg.get("id") != req_id:
                    continue  # a notification or unrelated message
                if "error" in msg:
                    raise MCPError(f"{method} failed: {msg['error']}")
                return msg.get("result", {}) or {}

    async def _notify(self, method: str, params: dict[str, Any]) -> None:
        await self._write({"jsonrpc": "2.0", "method": method, "params": params})

    async def _write(self, message: dict[str, Any]) -> None:
        assert self._proc and self._proc.stdin
        self._proc.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
        await self._proc.stdin.drain()


# --------------------------------------------------------------------------- #
# Tool adapter
# --------------------------------------------------------------------------- #

class MCPTool(BaseTool):
    """Adapts one remote MCP tool to Mapache's BaseTool contract."""

    name = "mcp"  # placeholder for BaseTool.__init_subclass__; overridden per instance
    permissions = {Permission.NETWORK}

    def __init__(
        self,
        client: MCPStdioClient,
        remote_name: str,
        full_name: str,
        description: str,
        parameters: dict[str, Any],
    ) -> None:
        self._client = client
        self._remote_name = remote_name
        self.name = full_name
        self.description = description or f"MCP tool {remote_name} from {client.name}"
        self.parameters = parameters or {"type": "object", "properties": {}}
        self.tags = ["mcp", client.name]

    async def execute(self, **kwargs: Any) -> ToolResult:
        try:
            output = await self._client.call_tool(self._remote_name, kwargs)
            return ToolResult.ok(output)
        except Exception as exc:
            return ToolResult.fail(f"MCP call failed: {exc}")


# --------------------------------------------------------------------------- #
# Manager (all servers)
# --------------------------------------------------------------------------- #

class MCPManager:
    """Connects to every configured MCP server and exposes their tools."""

    def __init__(self, configs: list[MCPServerConfig]) -> None:
        self.configs = configs
        self.clients: list[MCPStdioClient] = []
        self.tools: list[MCPTool] = []

    @classmethod
    def from_config_file(cls, path: str) -> "MCPManager":
        return cls(load_mcp_config(path))

    async def connect_all(self) -> list[MCPTool]:
        """Start every server and build the adapted tool list. Fail-soft."""
        for cfg in self.configs:
            client = MCPStdioClient(cfg)
            try:
                await client.start()
                remote_tools = await client.list_tools()
            except Exception as exc:
                logger.warning("MCP server %r unavailable: %s", cfg.name, exc)
                await client.close()
                continue

            self.clients.append(client)
            allow = set(cfg.tools)
            exposed = 0
            for spec in remote_tools:
                rname = spec.get("name")
                if not rname:
                    continue
                if allow and rname not in allow:
                    continue  # honor the mcp.json `tools` allowlist (keeps payloads small)
                full = f"mcp__{cfg.name}__{rname}"
                self.tools.append(MCPTool(
                    client=client,
                    remote_name=rname,
                    full_name=full,
                    description=spec.get("description", ""),
                    parameters=spec.get("inputSchema") or spec.get("input_schema") or {},
                ))
                exposed += 1
            logger.info("MCP server %r exposed %d of %d tools",
                        cfg.name, exposed, len(remote_tools))
        return self.tools

    @property
    def tool_names(self) -> list[str]:
        return [t.name for t in self.tools]

    async def close_all(self) -> None:
        for client in self.clients:
            await client.close()
        self.clients.clear()
