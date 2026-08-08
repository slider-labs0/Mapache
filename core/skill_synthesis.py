"""
skill_synthesis.py - learn a reusable skill from a successful chain (feature N)

Closes the self-improvement loop, the offensive way. After an engagement reaches
a flag/foothold, the sequence of tool calls that got there (recorded by the
engagement log, K) is a *proven attack chain*. This module turns that concrete,
target-specific run into a **parameterized, reusable tool** authored through the
existing `create_tool` path (A): the same chain, re-runnable against a new target.

That is Hermes-style "learn from experience", specialized to attack techniques -
and the synthesized skill is a normal generated-tool package, so it is curated by
the same lifecycle (A) and will be shareable through the hub (I). Provenance:
each synthesized skill is signed with the local key (`core/provenance.py`), so it
carries tamper-evidence and a signer identity from birth.

Translation is best-effort: shell / kali_run / nmap_scan / searchsploit steps
become runnable commands (with the engagement target swapped for a `__TARGET__`
placeholder the tool fills at run time); steps that don't map to a shell command
are preserved in the methodology playbook so nothing about the chain is lost.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from plugins.sdk.base_tool import BaseTool, ToolResult
from tools.generated_tool import save_manifest
from . import provenance

# nmap scan_type → flags, mirroring NmapTool's vocabulary.
_NMAP_FLAGS = {
    "standard": "-sV", "version": "-sV", "vuln": "--script vuln",
    "full": "-p- -sV", "quick": "-T4 -F", "stealth": "-sS",
}


@dataclass
class SynthesizedSkill:
    name: str
    description: str
    parameters: dict[str, Any]
    code: str
    methodology: str
    target: str
    phase: str = "exploitation"
    runnable_steps: int = 0
    total_steps: int = 0
    session_id: str = ""
    flags: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Step translation
# --------------------------------------------------------------------------- #


def _command_for(tool: str, args: dict[str, Any]) -> Optional[str]:
    """Translate one recorded tool call into a shell command, or None if it
    isn't directly runnable as one (it still survives in the methodology)."""
    args = args or {}
    if tool == "shell":
        return str(args.get("cmd") or "").strip() or None
    if tool == "kali_run":
        cmd = f"{args.get('tool', '')} {args.get('args', '')}".strip()
        return cmd or None
    if tool == "searchsploit":
        q = str(args.get("query") or "").strip()
        return f"searchsploit {q}" if q else None
    if tool == "nmap_scan":
        flags = _NMAP_FLAGS.get(str(args.get("scan_type", "standard")), "-sV")
        extra = str(args.get("extra_args") or "").strip()
        target = str(args.get("target") or "").strip()
        return " ".join(p for p in ["nmap", flags, extra, target] if p)
    return None


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_")
    return s or "chain"


def _skill_name(attack_state: Any, seed: str) -> str:
    vulns = getattr(attack_state, "vulnerabilities", []) or []
    services = list((getattr(attack_state, "services", {}) or {}).values())
    if vulns:
        base = f"replay_{_slug(vulns[0])}"
    elif services:
        base = f"replay_{_slug(services[0])}_chain"
    else:
        base = "replay_chain"
    suffix = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:4]
    name = f"{base}_{suffix}"[:49]
    # Guarantee a valid leading letter (sha suffix is safe; base always alpha).
    return name if re.match(r"[a-z]", name) else f"s_{name}"[:49]


# --------------------------------------------------------------------------- #
# Synthesis
# --------------------------------------------------------------------------- #


def synthesize_from_log(
    records: list[dict[str, Any]],
    attack_state: Any,
    session_id: str = "",
) -> Optional[SynthesizedSkill]:
    """Build a SynthesizedSkill from a successful engagement, or None if the
    engagement has no completed chain (no flag and no captured credential)."""
    flags = list(getattr(attack_state, "flags", []) or [])
    creds = list(getattr(attack_state, "credentials", []) or [])
    if not flags and not creds:
        return None

    # The chain is the tool calls up to the first flag (the moment of success);
    # if the flag wasn't logged as a finding, use every recorded tool call.
    chain: list[tuple[str, dict]] = []
    for r in records or []:
        kind = r.get("kind")
        if kind == "tool_call" and r.get("ok", True):
            chain.append((r.get("tool") or "", r.get("args") or {}))
        elif kind == "finding" and r.get("finding_type") == "flag":
            break
    if not chain and records:
        chain = [(r.get("tool") or "", r.get("args") or {})
                 for r in records if r.get("kind") == "tool_call"]

    target = str(getattr(attack_state, "target", "") or "").strip()

    commands: list[str] = []
    methodology_lines: list[str] = []
    for i, (tool, args) in enumerate(chain, 1):
        cmd = _command_for(tool, args)
        if cmd:
            if target:
                cmd = cmd.replace(target, "__TARGET__")
            commands.append(cmd)
            methodology_lines.append(f"{i}. {tool}: `{cmd}`")
        else:
            methodology_lines.append(f"{i}. {tool}({json.dumps(args, default=str)[:120]})")

    methodology = "Proven chain:\n" + "\n".join(methodology_lines)
    seed = f"{session_id}|{target}|{len(chain)}|{','.join(flags)}"
    name = _skill_name(attack_state, seed)
    primary = (getattr(attack_state, "vulnerabilities", []) or
               list((getattr(attack_state, "services", {}) or {}).values()) or ["chain"])[0]
    description = (f"Replays the proven attack chain ({primary}) that reached "
                  f"{'a flag' if flags else 'a foothold'} during session "
                  f"{session_id or '?'} - pass a new target to re-run it.")

    if commands:
        code = (
            'target = (args.get("target") or args.get("host") or "").strip()\n'
            'if not target:\n'
            '    return "Error: this skill needs a `target` argument."\n'
            f'steps = {json.dumps(commands)}\n'
            'results = []\n'
            'for i, cmd in enumerate(steps, 1):\n'
            '    cmd = cmd.replace("__TARGET__", target)\n'
            '    out = await shell(cmd)\n'
            '    results.append("=== step %d: %s ===\\n%s" % (i, cmd, out))\n'
            'return "\\n\\n".join(results)\n'
        )
        runnable = len(commands)
    else:
        # No runnable steps - return the proven playbook so the agent can follow it.
        code = f'return {json.dumps(methodology)}\n'
        runnable = 0

    return SynthesizedSkill(
        name=name, description=description,
        parameters={"type": "object", "properties": {
            "target": {"type": "string",
                       "description": "Target host/IP to run the chain against."}},
            "required": ["target"]},
        code=code, methodology=methodology, target=target,
        runnable_steps=runnable, total_steps=len(chain),
        session_id=session_id, flags=flags,
    )


def persist_skill(
    manager: Any,
    skill: SynthesizedSkill,
    *,
    sign_key: Optional[bytes] = None,
) -> str:
    """Author the skill through the generated-tool manager, then stamp provenance
    (signature + synthesis metadata) onto its manifest."""
    msg = manager.create(skill.name, skill.description, skill.parameters,
                         skill.code, phase=skill.phase)
    if not msg.startswith("Created"):
        return msg

    tool = getattr(manager, "tools", {}).get(skill.name)
    if tool is not None:
        try:
            key = sign_key if sign_key is not None else provenance.local_key()
            tool.manifest["signature"] = provenance.sign(tool.manifest["sha256"], key)
            tool.manifest["signer"] = provenance.signer_id(key)
            tool.manifest["sign_algo"] = provenance.SIGN_ALGO
            tool.manifest["synthesized_from"] = {
                "session": skill.session_id,
                "origin_target": skill.target,
                "steps": skill.total_steps,
                "runnable_steps": skill.runnable_steps,
                "flags": skill.flags,
                "created": datetime.now(timezone.utc).isoformat(),
            }
            save_manifest(tool.tool_dir, tool.manifest)
        except Exception:
            pass  # provenance is best-effort; never undo a good create
    return (f"Synthesized skill '{skill.name}' from a {skill.total_steps}-step chain "
            f"({skill.runnable_steps} runnable). {msg}")


# --------------------------------------------------------------------------- #
# Agent-callable meta-tool
# --------------------------------------------------------------------------- #


class SynthesizeSkillTool(BaseTool):
    name = "synthesize_skill"
    description = (
        "After you have completed an attack chain (reached a flag or a foothold), "
        "call this to save the proven sequence of steps as a reusable, signed tool "
        "you can re-run against a new target later. No arguments - it reads the "
        "current engagement."
    )
    parameters = {"type": "object", "properties": {}}
    tags = ["meta", "generated", "synthesis"]

    def __init__(
        self,
        manager: Any,
        records_provider: Callable[[], list[dict]],
        state_provider: Callable[[], Any],
        session_provider: Callable[[], str],
    ) -> None:
        self._manager = manager
        self._records = records_provider
        self._state = state_provider
        self._session = session_provider

    async def execute(self, **kwargs: Any) -> ToolResult:
        skill = synthesize_from_log(self._records(), self._state(), self._session())
        if skill is None:
            return ToolResult.ok(
                "No completed exploit chain to synthesize yet (no flag or "
                "credential captured this engagement).")
        return ToolResult.ok(persist_skill(self._manager, skill))
