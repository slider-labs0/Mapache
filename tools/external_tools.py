"""
external_tools.py - bring-your-own tools (integrations).

Let an operator route their OWN tools into Mapache from config, without writing a
plugin, in two flavours:

  * HTTP/API tools  - wrap a REST endpoint (VirusTotal, GreyNoise, Censys, AbuseIPDB,
    an internal service …). Declared with a URL template + params; the agent calls
    it like any tool. API keys go in via ${ENV} refs so they never sit in the spec.
    Requests honor the egress profile (proxy/Tor), so lookups aren't attributable
    to the operator either.

  * Command tools   - wrap a CLI or a GitHub repo (a tool the operator cloned or
    wants auto-cloned). Declared with a command template; runs through the execution
    backend, so it lands in the sandbox/pivot like the rest of the toolchain, and
    through the egress wrapper for anonymity.

Specs come from config.integrations (a list); build_external_tools() turns them into
BaseTool instances the CLI registers. Bad specs warn-don't-block (skipped with a
message), so one typo can't stop startup.

Spec shape:
  { "name": "vt_ip", "kind": "http", "method": "GET",
    "url": "https://www.virustotal.com/api/v3/ip_addresses/{ip}",
    "headers": {"x-apikey": "${VT_API_KEY}"},
    "params": {"ip": {"type": "string", "description": "target IP"}},
    "description": "VirusTotal IP reputation", "permission": "network" }

  { "name": "my_recon", "kind": "command",
    "repo": "https://github.com/me/mytool",          # optional: cloned once
    "command": "python3 {dir}/run.py {args}",
    "params": {"args": {"type": "string", "description": "arguments"}},
    "description": "my custom recon tool", "permission": "shell" }
"""

from __future__ import annotations

import asyncio
import os
import re
import shlex
import shutil
import stat
from pathlib import Path
from typing import Any, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult
from core.logger import get_logger

logger = get_logger(__name__)

_ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,39}$")

_PERMISSIONS = {
    "network": Permission.NETWORK,
    "shell": Permission.SHELL,
    "filesystem": Permission.FILESYSTEM,
    "dangerous": Permission.DANGEROUS,
    "system_info": Permission.SYSTEM_INFO,
}


def _rmtree_force(path: Path) -> None:
    """rmtree that survives read-only files (git packs on Windows resist deletion)."""
    def _onerror(func: Any, p: str, _exc: Any) -> None:
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass
    shutil.rmtree(path, onerror=_onerror)


def _resolve_env(text: str) -> str:
    """Substitute ${VAR} from the environment (belt-and-suspenders - config already
    interpolates, but a spec passed directly should resolve too). Unknown → empty."""
    return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), text or "")


def _fill(template: str, values: dict[str, Any], *, url: bool) -> str:
    """Replace {param} placeholders with arg values. URL values are percent-encoded;
    command/body values are inserted as-is (the operator declared the tool)."""
    out = template
    for key, val in values.items():
        token = "{" + key + "}"
        if token in out:
            sval = str(val)
            if url:
                from urllib.parse import quote
                sval = quote(sval, safe="")
            out = out.replace(token, sval)
    return out


def _param_schema(spec: dict) -> dict:
    """Build a valid JSON-Schema object from a param spec.

    A param may carry a convenience `"required": true` flag; that's promoted to the
    object-level `required` array and STRIPPED from the property itself - an inline
    `required` boolean is invalid JSON Schema and strict validators (e.g. the xAI
    API) reject the whole tool with a 400.
    """
    raw = dict(spec.get("params") or {})
    props: dict[str, Any] = {}
    required: list[str] = []
    for key, val in raw.items():
        if isinstance(val, dict):
            if val.get("required"):
                required.append(key)
            props[key] = {k: v for k, v in val.items() if k != "required"}
        else:
            props[key] = val
    return {"type": "object", "properties": props,
            "required": required or list(props.keys())}


class HttpApiTool(BaseTool):
    """A REST/API endpoint wrapped as a tool (e.g. VirusTotal). Set per-instance."""

    name = "http_api_tool"  # placeholder for BaseTool.__init_subclass__
    description = "external API tool"
    parameters = {"type": "object", "properties": {}}
    tags = ["integration", "external"]

    def __init__(self, spec: dict, *, egress: Any = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.name = spec["name"]
        self.description = spec.get("description", f"external API tool {self.name}")
        self.parameters = _param_schema(spec)
        self.permissions = {_PERMISSIONS.get(str(spec.get("permission", "network")),
                                             Permission.NETWORK)}
        self._method = str(spec.get("method", "GET")).upper()
        self._url = str(spec.get("url", ""))
        self._headers = dict(spec.get("headers") or {})
        self._body = spec.get("body")
        self._signup = spec.get("signup_url") or ""
        # Which ${ENV} vars this endpoint needs (the API key etc.) - so we can fail
        # fast with a clear message instead of firing a doomed credential-less request
        # that the provider bounces (a Cloudflare-fronted API answers a keyless call
        # with an HTTP 403 challenge, which reads like a block, not "set a key").
        blob = " ".join([self._url, *map(str, self._headers.values()),
                         str(self._body or "")])
        self._required_env = _ENV_RE.findall(blob)
        self.egress = egress

    def _missing_env(self) -> list[str]:
        return [v for v in self._required_env if not os.environ.get(v)]

    async def execute(self, **kwargs: Any) -> ToolResult:
        from browser.http_client import HttpClient
        # Pre-flight: a required credential is unset - don't send a keyless request
        # that will 403. Tell the operator exactly what to set.
        missing = self._missing_env()
        if missing:
            names = ", ".join(missing)
            hint = (f" Get a key at {self._signup} then set it, or re-run the "
                    f"integration setup." if self._signup else
                    " Set it in your environment (or via the integration setup).")
            return ToolResult.fail(
                f"{self.name}: missing API credential - {names} is not set, so the "
                f"request would be rejected (providers answer a keyless call with an "
                f"HTTP 401/403, not real data).{hint}",
                metadata={"missing_env": missing})
        url = _resolve_env(_fill(self._url, kwargs, url=True))
        headers = {k: _resolve_env(str(v)) for k, v in self._headers.items()}
        body = _resolve_env(_fill(str(self._body), kwargs, url=False)) if self._body else None
        proxy = self.egress.httpx_proxy() if self.egress is not None else None
        try:
            async with HttpClient(timeout=25.0, proxy=proxy) as client:
                resp = await client.request(self._method, url, extra_headers=headers,
                                            content=body)
        except Exception as exc:
            return ToolResult.fail(f"{self.name}: request failed - {exc}")
        text = (resp.text or "")[:8000]
        if not resp.success:
            # A 401/403 on an authenticated API almost always means the key is bad,
            # expired, or out of query credits - flag that so the agent doesn't read
            # it as an unbeatable Cloudflare wall and give up.
            auth_note = ""
            if resp.status_code in (401, 403):
                auth_note = (f"\n(This is an auth/credit response. Check that "
                             f"{', '.join(self._required_env) or 'the API key'} is "
                             f"valid and has remaining credits"
                             + (f"; keys: {self._signup}" if self._signup else "") + ".)")
            return ToolResult.fail(
                f"{self.name}: HTTP {resp.status_code}\n{text}{auth_note}",
                metadata={"status": resp.status_code})
        return ToolResult.ok(f"{self.name} → HTTP {resp.status_code}\n{text}",
                             metadata={"status": resp.status_code})


class CommandTool(BaseTool):
    """A CLI / GitHub-repo tool wrapped as a tool. Runs through the execution
    backend (sandbox/pivot) and the egress wrapper (proxy/Tor)."""

    name = "command_tool"  # placeholder for BaseTool.__init_subclass__
    description = "external command tool"
    parameters = {"type": "object", "properties": {}}
    tags = ["integration", "external"]

    def __init__(self, spec: dict, *, backend: Any = None, egress: Any = None,
                 **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.name = spec["name"]
        self.description = spec.get("description", f"external tool {self.name}")
        self.parameters = _param_schema(spec)
        self.permissions = {_PERMISSIONS.get(str(spec.get("permission", "shell")),
                                             Permission.SHELL)}
        self._command = str(spec.get("command", ""))
        self._repo = str(spec.get("repo", "")).strip()
        self._timeout = int(spec.get("timeout", 120))
        self.backend = backend
        self.egress = egress
        self._clone_dir: Optional[str] = None

    def _remote(self) -> bool:
        return self.backend is not None and getattr(self.backend, "name", "local") != "local"

    async def _run(self, cmd: str, timeout: int) -> tuple[str, Optional[str]]:
        """Run a command where the tool lives (backend if remote, else local)."""
        if self._remote():
            res = await self.backend.run(cmd, timeout=timeout)
            return res.output or "", res.error
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=float(timeout))
        except asyncio.TimeoutError:
            proc.kill()
            return "", f"timed out after {timeout}s"
        text = out.decode("utf-8", errors="replace")
        return text, (None if proc.returncode == 0 or text.strip()
                      else f"exit {proc.returncode}")

    async def _ensure_repo(self) -> Optional[str]:
        """Clone the repo once (where the tool runs) and return its dir."""
        if not self._repo:
            return None
        if self._clone_dir:
            return self._clone_dir
        if self._remote():
            # Remote backends (docker/ssh) are POSIX: an idempotent `[ -d ] ||`
            # guard on the target host, run through the backend.
            d = f"/root/.mapache-tools/{self.name}"
            clone = (f"[ -d {shlex.quote(d)} ] || "
                     f"git clone --depth 1 {shlex.quote(self._repo)} {shlex.quote(d)}")
            _out, err = await self._run(clone, 300)
            if err:
                raise RuntimeError(f"clone of {self._repo} failed: {err}")
            self._clone_dir = d
            return d
        # Local: check for the checkout in Python and clone via argv (no shell), so
        # it's correct on Windows cmd.exe too - POSIX shell quoting / `[ -d ]` don't
        # survive there.
        dest = Path.home() / ".mapache" / "tools" / self.name
        if not self._has_checkout(dest):
            # A stale/partial dir (e.g. an interrupted clone, or a `.git`-only
            # remnant a failed cleanup left behind) would otherwise wedge the tool
            # forever - remove it so the clone lands in a clean path.
            if dest.exists():
                _rmtree_force(dest)
            err = await self._clone_local(dest)
            if err:
                raise RuntimeError(f"clone of {self._repo} failed: {err}")
        self._clone_dir = str(dest)
        return self._clone_dir

    @staticmethod
    def _has_checkout(dest: Path) -> bool:
        """True only if dest looks like a COMPLETED clone - a working tree with real
        files, not an empty dir or a `.git`-only partial clone."""
        try:
            return dest.is_dir() and any(p.name != ".git" for p in dest.iterdir())
        except OSError:
            return False

    async def _clone_local(self, dest: Path) -> Optional[str]:
        """git clone into `dest` on the local host via argv (portable). Returns an
        error string on failure, else None."""
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", self._repo, str(dest),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        except (FileNotFoundError, OSError) as exc:
            return f"could not launch git: {exc}"
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            proc.kill()
            return "clone timed out after 300s"
        if proc.returncode != 0:
            text = out.decode("utf-8", errors="replace").strip()
            return text[:500] or f"git exited {proc.returncode}"
        return None

    async def execute(self, **kwargs: Any) -> ToolResult:
        try:
            clone_dir = await self._ensure_repo()
        except Exception as exc:
            return ToolResult.fail(f"{self.name}: {exc}")
        values = dict(kwargs)
        if clone_dir:
            values["dir"] = clone_dir
        cmd = _resolve_env(_fill(self._command, values, url=False))
        # Anonymise via the egress wrapper (POSIX: backend or a non-Windows box).
        if self.egress is not None:
            import platform
            posix = self._remote() or platform.system() != "Windows"
            cmd = self.egress.wrap_command(cmd, posix=posix)
        out, err = await self._run(cmd, self._timeout)
        header = f"{self.name}"
        if self._remote():
            header += f" [backend: {self.backend.name}]"
        if err and not out.strip():
            return ToolResult.fail(f"{header}: {err}")
        return ToolResult.ok(f"{header}\n{out}", metadata={"tool": self.name})


def _valid(spec: dict) -> Optional[str]:
    """Return an error string if the spec is unusable, else None."""
    name = str(spec.get("name", ""))
    if not _NAME_RE.match(name):
        return f"bad/absent tool name {name!r} (use snake_case, letters/digits/_)"
    kind = str(spec.get("kind", "")).lower()
    if kind == "http" and not spec.get("url"):
        return f"http tool {name!r} needs a 'url'"
    if kind == "command" and not spec.get("command"):
        return f"command tool {name!r} needs a 'command'"
    if kind not in ("http", "command"):
        return f"tool {name!r} has unknown kind {kind!r} (use 'http' or 'command')"
    return None


def build_external_tools(
    specs: Optional[list], *, backend: Any = None, egress: Any = None,
) -> tuple[list[BaseTool], list[str]]:
    """Build BaseTool instances from a list of integration specs. Returns
    (tools, warnings); an invalid spec is skipped with a warning (warn-don't-block)."""
    tools: list[BaseTool] = []
    warnings: list[str] = []
    for spec in (specs or []):
        if not isinstance(spec, dict):
            warnings.append(f"integration spec is not an object: {spec!r}")
            continue
        err = _valid(spec)
        if err:
            warnings.append(f"integration skipped - {err}")
            continue
        try:
            if str(spec["kind"]).lower() == "http":
                tools.append(HttpApiTool(spec, egress=egress))
            else:
                tools.append(CommandTool(spec, backend=backend, egress=egress))
        except Exception as exc:  # pragma: no cover - defensive
            warnings.append(f"integration {spec.get('name')!r} failed to build: {exc}")
    return tools, warnings
