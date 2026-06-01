"""
shell_tool.py — Mapache shell execution tool

Replaces the Phase 1 inline ShellDispatcher with a proper BaseTool implementation.
Handles Windows and Unix transparently.
"""

from __future__ import annotations

import asyncio
import platform
import sys
from typing import Any

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult


class ShellTool(BaseTool):
    name = "shell"
    description = (
        "Execute a shell command on the local system and return its output. "
        "On Windows use Windows commands (dir, type, ipconfig, tasklist, whoami). "
        "On Linux/Mac use Unix commands (ls, cat, ifconfig, ps, whoami). "
        "Use for file operations, system info, running scripts, and any OS interaction."
    )
    parameters = {
        "type": "object",
        "properties": {
            "cmd": {
                "type": "string",
                "description": "The shell command to execute",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in seconds (default: 30)",
                "default": 30,
            },
            "working_dir": {
                "type": "string",
                "description": "Working directory to run the command in (optional)",
                "default": "",
            },
        },
        "required": ["cmd"],
    }
    permissions = {Permission.SHELL}
    timeout = 60
    version = "0.2.0"
    tags = ["system", "shell", "core"]

    MAX_OUTPUT_BYTES = 50_000

    async def execute(self, cmd: str, timeout: int = 30, working_dir: str = "", **kwargs: Any) -> ToolResult:
        if not cmd or not cmd.strip():
            return ToolResult.fail("Empty command")

        cwd = working_dir if working_dir else None

        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=cwd,
            )

            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=float(timeout),
                )
            except asyncio.TimeoutError:
                proc.kill()
                return ToolResult.fail(f"Command timed out after {timeout}s")

            output = stdout.decode("utf-8", errors="replace")

            if len(output) > self.MAX_OUTPUT_BYTES:
                output = output[:self.MAX_OUTPUT_BYTES] + "\n[... output truncated]"

            if proc.returncode != 0 and not output.strip():
                return ToolResult.fail(
                    f"Command failed with exit code {proc.returncode}",
                    output=output,
                )

            return ToolResult.ok(
                output,
                metadata={"exit_code": proc.returncode, "cmd": cmd},
            )

        except FileNotFoundError:
            return ToolResult.fail(f"Command not found: {cmd.split()[0]}")
        except PermissionError:
            return ToolResult.fail(f"Permission denied running: {cmd}")
        except Exception as exc:
            return ToolResult.fail(f"Shell error: {exc}")

    @staticmethod
    def is_windows() -> bool:
        return platform.system() == "Windows"
