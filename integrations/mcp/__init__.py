"""
Mapache MCP integration — client side.

Connects out to Model Context Protocol servers over stdio and exposes their
tools to the agent as ordinary Mapache tools. See `mcp_client.py`.
"""

from .mcp_client import (
    MCPManager,
    MCPServerConfig,
    MCPStdioClient,
    MCPTool,
    load_mcp_config,
)

__all__ = [
    "MCPManager",
    "MCPServerConfig",
    "MCPStdioClient",
    "MCPTool",
    "load_mcp_config",
]
