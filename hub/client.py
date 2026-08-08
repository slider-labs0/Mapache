"""
client.py - hub client: search / list / install (feature I)

Installs a verified skill into the right home:

- `generated_tool` → `write_generated_tool` under the generated-tool dir (A). The
  on-disk manifest is stamped `origin="hub"`, so A's loader re-verifies its sha256
  before compiling - a tampered package refuses to load even after install.
- `mcp_server`     → an entry under `mcpServers` in `mcp.json` (the MCP client).
- `external_tool`  → an entry in the global config's `integrations` list (a BYO
  command tool backed by a GitHub repo); the CLI turns it into a CommandTool at
  startup (tools/external_tools.py). This is how an uploaded GitHub tool installs.

Safety: every install re-checks the checksum (and the signature when a trusted key
is configured) BEFORE writing anything; a failure refuses the install. Installs do
NOT hot-load - generated tools and MCP servers are picked up at next startup, which
is the "sandbox review before enabling" gate (the operator can inspect the written
package first). Running a skill is third-party code execution; the agent-facing
install tool says so.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from .manifest import SkillManifest, verify_manifest
from .registry import LocalRegistry


class HubClient:
    def __init__(
        self,
        registry: Any,
        *,
        generated_dir: str | Path,
        mcp_path: str | Path,
        config_path: Optional[str | Path] = None,
        trusted_key: Optional[bytes] = None,
    ) -> None:
        self.registry = registry
        self.generated_dir = Path(generated_dir)
        self.mcp_path = Path(mcp_path)
        # Where an `external_tool` install writes its integrations entry. When
        # None, external_tool installs are refused (nothing to write into).
        self.config_path = Path(config_path) if config_path else None
        self.trusted_key = trusted_key

    # -- browse --------------------------------------------------------- #

    def list_skills(self) -> list[SkillManifest]:
        return self.registry.list_skills()

    def search(self, query: str) -> list[SkillManifest]:
        return self.registry.search(query)

    # -- install -------------------------------------------------------- #

    def install(self, name: str) -> str:
        m = self.registry.get(name)
        if m is None:
            return f"Skill '{name}' not found in the registry."

        ok, reason = verify_manifest(m, key=self.trusted_key)
        if not ok:
            return f"Refused '{name}': {reason}."

        if m.skill_type == "generated_tool":
            detail = self._install_generated_tool(m)
        elif m.skill_type == "mcp_server":
            detail = self._install_mcp_server(m)
        elif m.skill_type == "external_tool":
            if self.config_path is None:
                return f"Refused '{name}': no config path configured for integrations."
            detail = self._install_external_tool(m)
        else:  # pragma: no cover - verify_manifest already gates this
            return f"Refused '{name}': unsupported type {m.skill_type!r}."
        return f"{detail}  [{reason}]  Loads on next start."

    def _install_generated_tool(self, m: SkillManifest) -> str:
        from tools.generated_tool import write_generated_tool, load_manifest, save_manifest
        tool_dir = write_generated_tool(
            self.generated_dir, m.name, m.description, m.parameters, m.code,
            origin="hub", author=m.signer or "hub", version=m.version,
            phase=m.phase, deps=m.deps)
        # Carry provenance onto the installed manifest.
        if m.signature:
            manifest = load_manifest(tool_dir)
            manifest["signature"] = m.signature
            manifest["signer"] = m.signer
            save_manifest(tool_dir, manifest)
        return f"Installed generated tool '{m.name}' v{m.version} → {tool_dir}"

    def _install_mcp_server(self, m: SkillManifest) -> str:
        data: dict[str, Any] = {}
        if self.mcp_path.is_file():
            try:
                data = json.loads(self.mcp_path.read_text(encoding="utf-8")) or {}
            except json.JSONDecodeError:
                data = {}
        servers = data.setdefault("mcpServers", {})
        entry: dict[str, Any] = {"command": m.command, "args": list(m.args)}
        if m.env:
            entry["env"] = dict(m.env)
        servers[m.name] = entry
        self.mcp_path.parent.mkdir(parents=True, exist_ok=True)
        self.mcp_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return f"Installed MCP server '{m.name}' v{m.version} → {self.mcp_path}"

    def _install_external_tool(self, m: SkillManifest) -> str:
        # Append/replace this tool's integrations entry (verbatim config edit,
        # preserving other entries' ${ENV} secrets). See hub.publish.install_to_config.
        from .publish import install_to_config
        path = install_to_config(m, self.config_path)
        return f"Installed external tool '{m.name}' v{m.version} → integrations in {path}"
