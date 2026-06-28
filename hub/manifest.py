"""
manifest.py — skill manifest + verification (feature I)

A "skill" is a downloadable package the hub can install into one of Mapache's
existing homes:

- `generated_tool` — a self-authored tool package (feature A): code body +
  parameters, installed under `plugins/generated/<name>/`.
- `mcp_server`     — an MCP server entry added to `mcp.json` (the MCP client).

The manifest carries identity (name/version/type/description/deps) and the
**safety** fields the hub enforces before running third-party code: a `checksum`
over the installable payload, and an optional `signature`/`signer` (HMAC, reusing
feature N's `core.provenance`). The checksum is mandatory and recomputed at
install; the signature is verified when a trusted key is supplied. Cross-machine
*asymmetric* trust (verifying another operator's key) arrives with N's ed25519
upgrade behind the same `provenance.verify` surface — until then the checksum is
the integrity gate and the signature confirms a self-/key-shared publisher.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional

# Installable types with a clear home. (prompt/persona packs are a documented
# future type — no consumer wired yet, so not accepted here.)
VALID_TYPES = {"generated_tool", "mcp_server"}


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class SkillManifest:
    name: str
    version: str
    skill_type: str
    description: str = ""
    deps: list[str] = field(default_factory=list)
    checksum: str = ""
    signature: str = ""
    signer: str = ""
    # generated_tool payload
    parameters: dict[str, Any] = field(default_factory=dict)
    code: str = ""
    phase: str = "always"
    # mcp_server payload
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "version": self.version,
            "skill_type": self.skill_type, "description": self.description,
            "deps": list(self.deps), "checksum": self.checksum,
            "signature": self.signature, "signer": self.signer,
            "parameters": self.parameters, "code": self.code, "phase": self.phase,
            "command": self.command, "args": list(self.args), "env": dict(self.env),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SkillManifest":
        return cls(
            name=d.get("name", ""), version=d.get("version", "0.0.0"),
            skill_type=d.get("skill_type", ""), description=d.get("description", ""),
            deps=list(d.get("deps") or []), checksum=d.get("checksum", ""),
            signature=d.get("signature", ""), signer=d.get("signer", ""),
            parameters=dict(d.get("parameters") or {}), code=d.get("code", ""),
            phase=d.get("phase", "always"), command=d.get("command", ""),
            args=list(d.get("args") or []), env=dict(d.get("env") or {}),
        )


def payload_digest(m: SkillManifest) -> str:
    """sha256 over the type-specific installable payload.

    For a generated tool it is the sha256 of the *rendered* source — exactly what
    `write_generated_tool` stores in the on-disk manifest — so an installed hub
    tool's checksum matches and the A loader's own sha256 gate passes.
    """
    if m.skill_type == "generated_tool":
        from tools.generated_tool import render_tool_source, sha256_of
        return sha256_of(render_tool_source(m.code))
    if m.skill_type == "mcp_server":
        canonical = m.command + "\n" + " ".join(m.args)
        return _sha256(canonical)
    return _sha256(m.code or "")


def verify_manifest(m: SkillManifest, *, key: Optional[bytes] = None) -> tuple[bool, str]:
    """(ok, reason). Checksum is mandatory; signature verified when `key` given."""
    if m.skill_type not in VALID_TYPES:
        return False, f"unsupported skill type: {m.skill_type!r}"
    if payload_digest(m) != m.checksum:
        return False, "checksum mismatch (payload tampered or mis-published)"
    if m.signature:
        if key is None:
            return True, "checksum verified; signature present but unverified (no key)"
        from core import provenance
        if not provenance.verify(m.checksum, m.signature, key):
            return False, "signature verification failed"
        return True, "checksum + signature verified"
    return True, "checksum verified (unsigned)"


# --------------------------------------------------------------------------- #
# Publisher helpers (used by tests + anyone packaging a skill)
# --------------------------------------------------------------------------- #


def _sign(m: SkillManifest, sign_key: Optional[bytes]) -> SkillManifest:
    m.checksum = payload_digest(m)
    if sign_key is not None:
        from core import provenance
        m.signature = provenance.sign(m.checksum, sign_key)
        m.signer = provenance.signer_id(sign_key)
    return m


def make_generated_tool_manifest(
    name: str, version: str, description: str, parameters: dict, code: str,
    *, phase: str = "always", deps: Optional[list[str]] = None,
    sign_key: Optional[bytes] = None,
) -> SkillManifest:
    return _sign(SkillManifest(
        name=name, version=version, skill_type="generated_tool",
        description=description, deps=deps or [], parameters=parameters,
        code=code, phase=phase), sign_key)


def make_mcp_server_manifest(
    name: str, version: str, description: str, command: str, args: list[str],
    *, env: Optional[dict] = None, deps: Optional[list[str]] = None,
    sign_key: Optional[bytes] = None,
) -> SkillManifest:
    return _sign(SkillManifest(
        name=name, version=version, skill_type="mcp_server",
        description=description, deps=deps or [], command=command,
        args=list(args), env=env or {}), sign_key)
