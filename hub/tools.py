"""
tools.py - agent-callable hub tools (feature I): skill_search / list / install.

Each tool reads the live HubClient through a provider, so the CLI can wire the
registry after the controller is built. When no hub/registry is configured the
tools report that plainly rather than erroring.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult
from core.logger import get_logger

logger = get_logger(__name__)


def _fmt(skills: list) -> str:
    if not skills:
        return "No skills found."
    lines = []
    for m in skills:
        sig = " oksigned" if m.signature else ""
        lines.append(f"  {m.name} v{m.version} [{m.skill_type}]{sig} - {m.description}")
    return "\n".join(lines)


# Mixin (NOT a BaseTool subclass, so it needn't define name/description) holding
# the shared lazy client accessor; concrete tools inherit (mixin, BaseTool).
class _HubMixin:
    def __init__(self, client_provider: Callable[[], Any]) -> None:
        self._client = client_provider

    def client(self) -> Optional[Any]:
        return self._client()


class SkillSearchTool(_HubMixin, BaseTool):
    name = "skill_search"
    description = ("Search the community skill hub for installable skills "
                  "(generated tools, MCP servers) matching a query.")
    parameters = {
        "type": "object",
        "properties": {"query": {"type": "string", "description": "Search terms."}},
    }
    tags = ["hub", "skills"]

    async def execute(self, **kwargs: Any) -> ToolResult:
        client = self.client()
        if client is None:
            return ToolResult.ok("No skill hub configured (set hub.registry in config).")
        return ToolResult.ok(_fmt(client.search(kwargs.get("query", ""))))


class SkillListTool(_HubMixin, BaseTool):
    name = "skill_list"
    description = "List all skills available in the configured community hub registry."
    parameters = {"type": "object", "properties": {}}
    tags = ["hub", "skills"]

    async def execute(self, **kwargs: Any) -> ToolResult:
        client = self.client()
        if client is None:
            return ToolResult.ok("No skill hub configured (set hub.registry in config).")
        return ToolResult.ok(_fmt(client.list_skills()))


class SkillInstallTool(_HubMixin, BaseTool):
    name = "skill_install"
    description = (
        "Install a skill from the community hub by name. Runs third-party code: "
        "the package's checksum (and signature, if a trusted key is set) is verified "
        "before install, and it only takes effect on the next start so it can be "
        "reviewed first."
    )
    parameters = {
        "type": "object",
        "properties": {"name": {"type": "string", "description": "Skill name to install."}},
        "required": ["name"],
    }
    tags = ["hub", "skills"]

    async def execute(self, **kwargs: Any) -> ToolResult:
        client = self.client()
        if client is None:
            return ToolResult.ok("No skill hub configured (set hub.registry in config).")
        name = (kwargs.get("name") or "").strip()
        if not name:
            return ToolResult.ok("No skill name provided.")
        return ToolResult.ok(client.install(name))


async def _github_raw(owner: str, repo: str, path: str, *, egress: Any = None) -> Optional[str]:
    """Fetch a file from a GitHub repo (default branch) via the contents API.
    Returns the raw text, or None if it isn't there. Honors the egress proxy."""
    from browser.http_client import HttpClient
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    proxy = egress.httpx_proxy() if egress is not None else None
    headers = {"Accept": "application/vnd.github.raw+json", "User-Agent": "mapache-hub"}
    async with HttpClient(timeout=20.0, proxy=proxy) as client:
        resp = await client.request("GET", url, extra_headers=headers)
    if resp.status_code == 404:
        return None
    if not resp.success:
        raise RuntimeError(f"GitHub API {resp.status_code} fetching {path}")
    return resp.text


class InstallGithubToolTool(BaseTool):
    """Install a tool the user points at on GitHub, right from a natural-language
    request. Reads the repo's `mapache-tool.json` if present; otherwise the caller
    supplies the run `command` (and a name). The tool is registered live - usable
    in the same session - and persisted to config so it survives a restart.

    Runs third-party code from the repo (cloned on first use); only install repos
    the operator trusts.
    """

    name = "install_github_tool"
    description = (
        "USE THIS whenever the user wants to add, install, or wrap a GitHub repo "
        "(a github.com URL or owner/repo) as a callable tool - prefer it over "
        "create_tool for anything backed by a repo. Give the repo in `repo`. If the "
        "repo has a mapache-tool.json it's used automatically; otherwise pass a "
        "`command` template ({dir} = the clone path, {args} = arguments) and a `name`. "
        "The tool clones the repo, becomes usable immediately (no restart), and "
        "persists across restarts. Runs third-party code - only for repos the "
        "operator trusts."
    )
    parameters = {
        "type": "object",
        "properties": {
            "repo": {"type": "string",
                     "description": "GitHub URL or owner/repo, e.g. https://github.com/me/mytool"},
            "name": {"type": "string",
                     "description": "Tool name (snake_case). Defaults to the repo name."},
            "command": {"type": "string",
                        "description": "Run template if the repo has no mapache-tool.json, "
                                       "e.g. 'python {dir}/run.py {args}'. Must include {dir}."},
            "description": {"type": "string", "description": "What the tool does."},
            "permission": {"type": "string",
                           "description": "shell | network | filesystem | system_info | dangerous"},
        },
        "required": ["repo"],
    }
    permissions = {Permission.NETWORK, Permission.FILESYSTEM}
    tags = ["hub", "skills", "integration"]

    def __init__(
        self,
        config_path_provider: Callable[[], Any],
        *,
        egress: Any = None,
        backend: Any = None,
        on_installed: Optional[Callable[[BaseTool], None]] = None,
        fetch: Optional[Callable[..., Any]] = None,
    ) -> None:
        self._config_path = config_path_provider
        self.egress = egress
        self.backend = backend
        self._on_installed = on_installed
        self._fetch = fetch  # async (owner, repo, path) -> Optional[str]; test seam

    async def execute(self, **kwargs: Any) -> ToolResult:
        from .publish import (manifest_from_github, install_to_config, integration_spec,
                              parse_github, normalize_tool_name, PublishError)
        from tools.external_tools import build_external_tools

        repo = (kwargs.get("repo") or "").strip()
        if not repo:
            return ToolResult.ok("No repo given. Pass a GitHub URL or owner/repo.")
        cfg_path = self._config_path()
        if not cfg_path:
            return ToolResult.fail("No config path available to install into.")

        try:
            owner, repo_name, repo_url = parse_github(repo)
        except PublishError as exc:
            return ToolResult.fail(str(exc))

        command = (kwargs.get("command") or "").strip()
        try:
            if command:
                spec: Any = {
                    "name": (kwargs.get("name") or "").strip() or normalize_tool_name(repo_name),
                    "command": command,
                    "description": kwargs.get("description", "") or f"tool from {owner}/{repo_name}",
                    "permission": kwargs.get("permission", "shell") or "shell",
                    "params": {"args": {"type": "string", "description": "arguments"}},
                }
            else:
                fetch = self._fetch or (lambda o, r, p: _github_raw(o, r, p, egress=self.egress))
                text = await fetch(owner, repo_name, "mapache-tool.json")
                if text is None:
                    return ToolResult.fail(
                        f"{owner}/{repo_name} has no mapache-tool.json - pass a `command` "
                        f"(and `name`) so I can install it, e.g. 'python {{dir}}/run.py {{args}}'.")
                spec = text  # manifest_from_github parses the JSON string

            manifest = manifest_from_github(repo_url, spec)
        except PublishError as exc:
            return ToolResult.fail(f"Can't install {owner}/{repo_name}: {exc}")
        except Exception as exc:  # network / parse
            return ToolResult.fail(f"Failed to read {owner}/{repo_name}: {exc}")

        # Persist to config (survives restart) …
        path = install_to_config(manifest, cfg_path)
        # … and register live so it's callable in THIS session.
        live_note = ""
        if self._on_installed is not None:
            tools, warns = build_external_tools([integration_spec(manifest)],
                                                backend=self.backend, egress=self.egress)
            if tools:
                try:
                    self._on_installed(tools[0])
                    live_note = (f" '{manifest.name}' is registered and callable now - "
                                 f"invoke it directly; do NOT author it again with "
                                 f"create_tool.")
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning("live-register failed for %s: %s", manifest.name, exc)
                    live_note = " Loads on next start."
            elif warns:
                return ToolResult.fail(f"Installed spec is invalid: {'; '.join(warns)}")

        return ToolResult.ok(
            f"Installed '{manifest.name}' from {owner}/{repo_name} → {path}."
            f"{live_note} It clones the repo on first run.")
