#!/usr/bin/env python3
"""
fake_mcp_server.py - a minimal MCP server over stdio, for tests.

Speaks just enough of the protocol (newline-delimited JSON-RPC 2.0) to exercise
Mapache's MCP client: initialize, tools/list, tools/call. Exposes one tool,
`echo`, that returns its `text` argument.
"""

import json
import sys


TOOLS = [
    {
        "name": "echo",
        "description": "Echo back the provided text.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    }
]


def _send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = msg.get("method")
        msg_id = msg.get("id")

        if method == "initialize":
            _send({"jsonrpc": "2.0", "id": msg_id, "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-mcp", "version": "0.0.1"},
            }})
        elif method == "notifications/initialized":
            pass  # notification, no response
        elif method == "tools/list":
            _send({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            params = msg.get("params", {})
            name = params.get("name")
            args = params.get("arguments", {})
            if name == "echo":
                _send({"jsonrpc": "2.0", "id": msg_id, "result": {
                    "content": [{"type": "text", "text": f"echo: {args.get('text', '')}"}],
                }})
            else:
                _send({"jsonrpc": "2.0", "id": msg_id, "error": {
                    "code": -32601, "message": f"unknown tool {name}",
                }})
        elif msg_id is not None:
            _send({"jsonrpc": "2.0", "id": msg_id, "error": {
                "code": -32601, "message": f"unknown method {method}",
            }})


if __name__ == "__main__":
    main()
