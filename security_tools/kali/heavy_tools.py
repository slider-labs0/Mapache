"""
heavy_tools.py — disciplined wrappers for heavy exploitation tools (capability #3)

The agent could already shell out to sqlmap / ffuf via `kali_run`, but nothing GUIDED
it: it hand-sprayed payloads and guessed endpoints instead of driving the real tools
with correct flags. These wrappers turn structured arguments into a correct invocation,
run it through the execution backend (local subprocess or a remote Kali box/container,
feature H) with egress-native proxying, and summarise the output — so the model reaches
for the right instrument for the injection / discovery classes.

  - SqlmapTool — automated SQL injection (blind/boolean/time/UNION), DBMS fingerprint,
    optional dump. Finds SQLi the model can't hand-craft.
  - FuzzTool — ffuf content/parameter fuzzing to DISCOVER real endpoints/params instead
    of guessing (grounds later requests; pairs with response-grounded acting).

Both require the underlying tool on the execution host; absent, they return install
guidance rather than crashing.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import shutil
from typing import Any, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult

MAX_OUTPUT = 12000


def _egress_proxy(egress: Any) -> Optional[str]:
    """A proxy URL string (socks5://… / http://…) from the egress profile, or None."""
    if egress is None:
        return None
    try:
        return egress.httpx_proxy()
    except Exception:
        return None


async def run_command(cmdline: str, *, backend: Any = None, timeout: int = 180) -> "tuple[int, str, bool]":
    """Run a full shell command line via the execution backend (remote) or a local
    subprocess. Returns (exit_code, output, timed_out). Egress is handled by the
    caller through each tool's NATIVE proxy flag, not command wrapping."""
    if backend is not None and getattr(backend, "name", "local") != "local":
        res = await backend.run(cmdline, timeout=timeout)
        out = (res.output or "") if not res.error else f"{res.output or ''}\n{res.error}"
        return (getattr(res, "exit_code", 1), out[:MAX_OUTPUT], False)

    try:
        proc = await asyncio.create_subprocess_shell(
            cmdline, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=float(timeout))
            timed_out = False
        except asyncio.TimeoutError:
            proc.kill()
            stdout, timed_out = b"", True
        out = stdout.decode("utf-8", errors="replace")
        return (proc.returncode if proc.returncode is not None else -1,
                out[:MAX_OUTPUT], timed_out)
    except Exception as exc:
        return (-1, f"Execution error: {exc}", False)


def _tool_available(tool: str, backend: Any) -> bool:
    """Best-effort local availability check; assume present on a remote backend."""
    if backend is not None and getattr(backend, "name", "local") != "local":
        return True
    return shutil.which(tool) is not None


class SqlmapTool(BaseTool):
    name = "sqlmap"
    description = (
        "Automated SQL injection with sqlmap. Use this when a parameter (query, POST "
        "field, header, or cookie) might be injectable and manual payloads are "
        "inconclusive — sqlmap finds blind / boolean / time-based / UNION SQLi you can't "
        "reliably hand-craft, fingerprints the DBMS, and can dump data. Give the `url`; "
        "for a POST target also give `data`. Runs non-interactively (--batch). Narrow it "
        "with `param`, and raise `level`/`risk` only if a quick pass finds nothing."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Target URL (http/https), including any query string."},
            "data": {"type": "string", "description": "POST body, e.g. 'user=x&pass=y' — triggers a POST test."},
            "param": {"type": "string", "description": "Test only this parameter (sqlmap -p)."},
            "level": {"type": "integer", "description": "Test depth 1-5 (default 1).", "default": 1},
            "risk": {"type": "integer", "description": "Risk 1-3 (default 1).", "default": 1},
            "technique": {"type": "string", "description": "SQLi techniques to try, e.g. 'BEUSTQ' (default: all)."},
            "dbms": {"type": "string", "description": "DBMS hint (mysql/postgresql/mssql/oracle…) to skip detection."},
            "dump": {"type": "boolean", "description": "Dump data from found injection points (--dump).", "default": False},
            "extra": {"type": "string", "description": "Raw extra sqlmap flags, appended verbatim."},
        },
        "required": ["url"],
    }
    permissions = {Permission.SHELL, Permission.NETWORK, Permission.DANGEROUS}
    timeout = 300
    tags = ["exploit", "sqli", "injection", "kali"]

    def __init__(self, backend: Any = None, egress: Any = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.backend = backend
        self.egress = egress

    def _build_cmd(self, url: str, data: str = "", param: str = "", level: int = 1,
                   risk: int = 1, technique: str = "", dbms: str = "", dump: bool = False,
                   extra: str = "") -> str:
        parts = ["sqlmap", "-u", shlex.quote(url), "--batch", "--disable-coloring"]
        if data:
            parts += ["--data", shlex.quote(data)]
        if param:
            parts += ["-p", shlex.quote(param)]
        if level and int(level) != 1:
            parts += ["--level", str(int(level))]
        if risk and int(risk) != 1:
            parts += ["--risk", str(int(risk))]
        if technique:
            parts += ["--technique", shlex.quote(technique)]
        if dbms:
            parts += ["--dbms", shlex.quote(dbms)]
        if dump:
            parts += ["--dump"]
        proxy = _egress_proxy(self.egress)
        if proxy:
            parts += ["--proxy", shlex.quote(proxy)]
        if extra:
            parts.append(extra)
        return " ".join(parts)

    @staticmethod
    def _summarize(output: str) -> str:
        """Pull the verdict-bearing lines to the top; keep the tail for detail."""
        keys = ("is vulnerable", "injectable", "Parameter:", "Type:", "Title:",
                "Payload:", "back-end DBMS", "available databases", "[CRITICAL]",
                "[WARNING] ", "all tested parameters do not appear")
        hits = [ln for ln in output.splitlines() if any(k in ln for k in keys)]
        summary = ("--- sqlmap verdict ---\n" + "\n".join(hits) + "\n\n") if hits else ""
        return summary + output[-6000:]

    async def execute(self, url: str, data: str = "", param: str = "", level: int = 1,
                      risk: int = 1, technique: str = "", dbms: str = "", dump: bool = False,
                      extra: str = "", **kwargs: Any) -> ToolResult:
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            return ToolResult.fail("Invalid URL: must start with http:// or https://")
        if not _tool_available("sqlmap", self.backend):
            return ToolResult.fail(
                "sqlmap is not installed on the execution host.\n"
                "Install: sudo apt install sqlmap  (or: pip install sqlmap)\n"
                "Meanwhile, test injection by hand with http_request.")
        cmd = self._build_cmd(url, data, param, level, risk, technique, dbms, dump, extra)
        code, out, timed = await run_command(cmd, backend=self.backend, timeout=self.timeout)
        head = f"$ {cmd[:120]}\nexit {code}{' (timed out)' if timed else ''}\n\n"
        if not out.strip():
            return ToolResult.fail(head + "(no output)")
        return ToolResult.ok(head + self._summarize(out),
                             metadata={"exit_code": code, "timed_out": timed})


class FuzzTool(BaseTool):
    name = "fuzz"
    description = (
        "Content and parameter fuzzing with ffuf — DISCOVER real endpoints, files, and "
        "parameters instead of guessing them. Put the keyword FUZZ where you want to "
        "fuzz: a path segment (mode=dir, e.g. https://t/FUZZ), a filename with "
        "extensions, or a query value/param name (mode=param, e.g. https://t/api?FUZZ=1). "
        "Returns matching paths with status codes so your NEXT request is grounded in a "
        "real endpoint. Filter noise with match/filter codes or a filter size."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "URL containing the FUZZ keyword."},
            "wordlist": {"type": "string", "description": "Wordlist path on the host (default: dirb common.txt)."},
            "mode": {"type": "string", "enum": ["dir", "param"], "description": "dir = paths/files; param = parameter fuzzing.", "default": "dir"},
            "extensions": {"type": "string", "description": "Comma list to append, e.g. 'php,bak,txt' (dir mode)."},
            "match_codes": {"type": "string", "description": "Only show these status codes, e.g. '200,301,401'."},
            "filter_codes": {"type": "string", "description": "Hide these status codes, e.g. '404'."},
            "filter_size": {"type": "string", "description": "Hide responses of this byte size (kills a boilerplate 404 page)."},
            "threads": {"type": "integer", "description": "Concurrency (default 40).", "default": 40},
        },
        "required": ["url"],
    }
    permissions = {Permission.SHELL, Permission.NETWORK}
    timeout = 180
    DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
    tags = ["recon", "fuzzing", "discovery", "kali"]

    def __init__(self, backend: Any = None, egress: Any = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.backend = backend
        self.egress = egress

    def _build_cmd(self, url: str, wordlist: str = "", mode: str = "dir",
                   extensions: str = "", match_codes: str = "", filter_codes: str = "",
                   filter_size: str = "", threads: int = 40) -> str:
        wl = wordlist or self.DEFAULT_WORDLIST
        parts = ["ffuf", "-u", shlex.quote(url), "-w", shlex.quote(wl),
                 "-t", str(int(threads or 40)), "-s"]
        if extensions and mode == "dir":
            parts += ["-e", shlex.quote(extensions)]
        if match_codes:
            parts += ["-mc", shlex.quote(match_codes)]
        if filter_codes:
            parts += ["-fc", shlex.quote(filter_codes)]
        if filter_size:
            parts += ["-fs", shlex.quote(filter_size)]
        proxy = _egress_proxy(self.egress)
        if proxy:
            parts += ["-x", shlex.quote(proxy)]
        return " ".join(parts)

    async def execute(self, url: str, wordlist: str = "", mode: str = "dir",
                      extensions: str = "", match_codes: str = "", filter_codes: str = "",
                      filter_size: str = "", threads: int = 40, **kwargs: Any) -> ToolResult:
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            return ToolResult.fail("Invalid URL: must start with http:// or https://")
        if "FUZZ" not in url:
            return ToolResult.fail(
                "The url must contain the keyword FUZZ where you want to fuzz — e.g. "
                "https://target/FUZZ (paths) or https://target/api?FUZZ=1 (params).")
        if not _tool_available("ffuf", self.backend):
            return ToolResult.fail(
                "ffuf is not installed on the execution host.\n"
                "Install: sudo apt install ffuf  (or `go install github.com/ffuf/ffuf/v2@latest`)\n"
                "Meanwhile, discover paths with a gobuster/dirb run via kali_run.")
        cmd = self._build_cmd(url, wordlist, mode, extensions, match_codes,
                              filter_codes, filter_size, threads)
        code, out, timed = await run_command(cmd, backend=self.backend, timeout=self.timeout)
        head = f"$ {cmd[:120]}\nexit {code}{' (timed out)' if timed else ''}\n\n"
        body = out.strip() or "(no matches — try a different wordlist, or relax the filters)"
        return ToolResult.ok(head + body, metadata={"exit_code": code, "timed_out": timed})
