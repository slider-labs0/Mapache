"""
publish.py — turn a GitHub repo into an installable hub manifest (feature I).

This is the "upload your own GitHub tool" ligament: the community-hub site (a
separate project) fetches a repo's declaration and calls `manifest_from_github`
to mint the verified `external_tool` manifest that lands in the hub's index.json.
Keeping the packaging logic here (not in the web layer) means the CLI, tests, and
any future front end all publish against ONE contract, offline and deterministic.

The author declares their tool in a `mapache-tool.json` at the repo root:

    {
      "name": "my_recon",
      "description": "my custom recon tool",
      "command": "python3 {dir}/run.py {args}",
      "params": {"args": {"type": "string", "description": "arguments"}},
      "permission": "shell",
      "version": "1.0.0",
      "deps": ["requests"]
    }

`{dir}` is the clone path CommandTool fills in at run time; `{param}` tokens map
to `params`. The repo URL is supplied by the publisher (the site knows it), never
trusted from inside the file. The resulting manifest carries a checksum over the
repo+command+params so the CLI refuses a tampered package at install.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from .manifest import SkillManifest, make_external_tool_manifest, verify_manifest

REPO_MANIFEST_NAME = "mapache-tool.json"

# Mirror external_tools.py's contract so a published tool is one the CLI accepts.
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,39}$")
_PERMISSIONS = {"network", "shell", "filesystem", "dangerous", "system_info"}
# GitHub (and generic git) remotes we'll accept as a clonable source.
_REPO_RE = re.compile(r"^(https://|git@)[\w.@:/\-~]+$")
# owner/repo out of a github URL, an scp-style git remote, or a bare "owner/repo".
_GH_RE = re.compile(
    r"(?:github\.com[:/])?([\w.\-]+)/([\w.\-]+?)(?:\.git)?/?$", re.IGNORECASE)


class PublishError(ValueError):
    """A repo/spec that can't be packaged (bad name, missing command, …)."""


def parse_repo_manifest(text: str) -> dict[str, Any]:
    """Parse a repo's `mapache-tool.json` text into a spec dict."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError) as exc:
        raise PublishError(f"{REPO_MANIFEST_NAME} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise PublishError(f"{REPO_MANIFEST_NAME} must be a JSON object")
    return data


def _validate(spec: dict, repo_url: str) -> None:
    name = str(spec.get("name", ""))
    if not _NAME_RE.match(name):
        raise PublishError(
            f"bad/absent tool name {name!r} (snake_case, letters/digits/_, 2-40 chars)")
    if not _REPO_RE.match(repo_url or ""):
        raise PublishError(f"repo url {repo_url!r} is not an http(s)/git remote")
    command = str(spec.get("command", "")).strip()
    if not command:
        raise PublishError(f"tool {name!r} needs a 'command' template")
    if "{dir}" not in command:
        raise PublishError(
            f"tool {name!r} command must reference {{dir}} (the clone path) — "
            f"a repo tool runs from its checkout")
    perm = str(spec.get("permission", "shell"))
    if perm not in _PERMISSIONS:
        raise PublishError(
            f"tool {name!r} permission {perm!r} invalid "
            f"(one of {', '.join(sorted(_PERMISSIONS))})")
    params = spec.get("params")
    if params is not None and not isinstance(params, dict):
        raise PublishError(f"tool {name!r} 'params' must be an object")


def manifest_from_github(
    repo_url: str,
    spec: dict[str, Any] | str,
    *,
    sign_key: Optional[bytes] = None,
) -> SkillManifest:
    """Mint an installable `external_tool` manifest for a GitHub repo.

    `spec` is either the parsed `mapache-tool.json` dict or its raw text. `repo_url`
    is authoritative (the site supplies it) and overrides any repo field inside the
    spec. Raises `PublishError` on an unpublishable tool.
    """
    if isinstance(spec, str):
        spec = parse_repo_manifest(spec)
    _validate(spec, repo_url)
    return make_external_tool_manifest(
        name=str(spec["name"]),
        version=str(spec.get("version", "1.0.0")),
        description=str(spec.get("description", "")),
        repo=repo_url,
        command=str(spec["command"]),
        parameters=dict(spec.get("params") or {}),
        permission=str(spec.get("permission", "shell")),
        deps=list(spec.get("deps") or []),
        sign_key=sign_key,
    )


def normalize_tool_name(raw: str) -> str:
    """Turn a repo name (e.g. 'Hello-World') into a valid tool name ('hello_world')."""
    s = re.sub(r"[^a-z0-9]+", "_", str(raw).lower()).strip("_")
    if not s or not s[0].isalpha():
        s = "tool_" + s
    return s[:40]


def parse_github(repo: str) -> tuple[str, str, str]:
    """(owner, repo, normalized_https_url) from a github URL / scp remote / owner/repo.

    Raises PublishError if it isn't a recognizable github reference.
    """
    m = _GH_RE.search((repo or "").strip())
    if not m:
        raise PublishError(f"can't parse a github owner/repo from {repo!r}")
    owner, name = m.group(1), m.group(2)
    return owner, name, f"https://github.com/{owner}/{name}.git"


def integration_spec(m: SkillManifest) -> dict[str, Any]:
    """The external_tools.py `integrations` entry for an external_tool manifest."""
    return {
        "name": m.name, "kind": "command", "repo": m.repo, "command": m.command,
        "params": dict(m.parameters or {}), "description": m.description,
        "permission": m.permission or "shell",
    }


def install_to_config(m: SkillManifest, config_path: str | Path) -> Path:
    """Write an external_tool manifest into a config's `integrations` (verbatim edit,
    preserving other entries' ${ENV}); replaces a same-name entry. Returns the path.

    Verifies the manifest first — a bad checksum refuses to install."""
    from core.config import load_global_raw, save_global_config
    ok, reason = verify_manifest(m)
    if not ok:
        raise PublishError(f"refusing to install '{m.name}': {reason}")
    data = load_global_raw(Path(config_path)) or {}
    integrations = data.get("integrations")
    if not isinstance(integrations, list):
        integrations = []
    integrations = [e for e in integrations
                    if not (isinstance(e, dict) and e.get("name") == m.name)]
    integrations.append(integration_spec(m))
    data["integrations"] = integrations
    return save_global_config(data, Path(config_path))


def add_to_index(index: list[dict], manifest: SkillManifest) -> list[dict]:
    """Return a new index list with `manifest` added (replacing a same-name entry).

    This is what the hub site does after minting a manifest: fold it into the
    `index.json` the CLI's UrlRegistry fetches. Verified before it's admitted, so a
    broken checksum never reaches the index.
    """
    ok, reason = verify_manifest(manifest)
    if not ok:
        raise PublishError(f"refusing to index '{manifest.name}': {reason}")
    kept = [e for e in (index or [])
            if not (isinstance(e, dict) and e.get("name") == manifest.name)]
    kept.append(manifest.to_dict())
    return kept
