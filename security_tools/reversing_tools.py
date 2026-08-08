"""
reversing_tools.py — binary analysis tool (structured command builder + parser).

The reverser drives file/checksec/nm/ROPgadget/strings through the shell. This wraps
the common triage actions with correct invocation and, crucially, PARSES the output
into what matters: memory protections, dangerous imports, interesting strings
(flags/creds/paths/format-strings), and ROP primitives — so triage is one call and
the exploitable facts are surfaced, not buried.

Runs the underlying binary when present; otherwise returns the command. Builders +
parsers are pure and unit-tested without needing the binaries or a target.
"""

from __future__ import annotations

import re
import shutil
from typing import Any

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

_BINS = {"info": "checksec", "strings": "strings", "symbols": "nm", "rop": "ROPgadget"}


def build_rev_command(action: str, path: str) -> str:
    action = (action or "").lower()
    p = path or "<binary>"
    if action == "info":
        return f"file {p}; checksec --file={p}"
    if action == "strings":
        return f"strings -n 6 {p}"
    if action == "symbols":
        return f"nm -D {p} 2>/dev/null; nm {p} 2>/dev/null"
    if action == "rop":
        return f"ROPgadget --binary {p}"
    return ""


# ---- parsers (pure) ------------------------------------------------------ #

_PROT = re.compile(r"(?i)(NX|PIE|RELRO|Canary|Stack)\s*[:=]?\s*(enabled|disabled|found|"
                   r"no\s*canary|full|partial|no)")
_DANGER = ("system", "exec", "popen", "gets", "strcpy", "sprintf", "scanf", "memcpy")
_INTERESTING_STR = re.compile(
    r"(?i)(flag\{[^}]*\}|/bin/sh|/bin/bash|https?://\S+|password|passwd|secret|api[_-]?key|"
    r"%s%s|%n|%x%x)")


def parse_rev_output(action: str, output: str) -> dict:
    out = output or ""
    res: dict[str, Any] = {}
    if action == "info":
        res["protections"] = [f"{m.group(1)}={m.group(2)}" for m in _PROT.finditer(out)]
    elif action == "strings":
        hits = []
        for line in out.splitlines():
            if _INTERESTING_STR.search(line):
                hits.append(line.strip()[:120])
        res["interesting"] = hits[:40]
    elif action == "symbols":
        res["dangerous"] = sorted({d for d in _DANGER if re.search(rf"\b{d}\b", out)})
    elif action == "rop":
        res["gadget_count"] = len(re.findall(r"0x[0-9a-f]+\s*:", out))
        res["pop_rdi"] = bool(re.search(r"pop rdi\s*;\s*ret", out, re.IGNORECASE))
    return res


class BinaryAnalyzeTool(BaseTool):
    name = "binary_analyze"
    description = (
        "Triage a binary for exploitation. action: info (arch + memory protections: NX/"
        "PIE/RELRO/canary), strings (surface flags, creds, paths, format-string bugs), "
        "symbols (dangerous imports: system/gets/strcpy…), rop (ROP gadget inventory + "
        "whether `pop rdi; ret` exists). Parses the output into the exploitable facts. "
        "Give the file path. Runs the tool if installed; otherwise returns the command."
    )
    parameters = {
        "type": "object",
        "properties": {
            "action": {"type": "string", "description": "info | strings | symbols | rop"},
            "path": {"type": "string", "description": "Path to the target binary"},
        },
        "required": ["action", "path"],
    }
    permissions = {Permission.SHELL, Permission.FILESYSTEM}
    tags = ["reversing", "binary", "pwn", "analysis"]

    async def execute(self, action: str = "", path: str = "", **kw: Any):
        action = (action or "").lower()
        if action not in _BINS:
            return ToolResult.fail(f"Unknown action {action!r}. Use: {', '.join(_BINS)}.")
        if not path:
            return ToolResult.fail("Provide the binary 'path'.")
        cmd = build_rev_command(action, path)
        binary = _BINS[action]
        if shutil.which(binary) is None:
            return ToolResult.ok(f"[{binary} not installed here] Run:\n  {cmd}")
        import asyncio
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            raw, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = raw.decode("utf-8", "replace")
        except Exception as exc:
            return ToolResult.fail(f"Ran `{cmd}` but it failed: {exc}")
        parsed = parse_rev_output(action, output)
        return ToolResult.ok(f"$ {cmd}\nParsed: {parsed}\n\n{output[:3000]}",
                             metadata=parsed)
