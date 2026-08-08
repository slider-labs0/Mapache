"""
skill_format.py - author skills as SKILL.md files (Decepticon-parity #6)

Mapache's just-in-time playbooks (`core/skills_playbook.py`) were code-only: each
`Skill` is a Python object with a hand-written predicate. Decepticon packages skills
as **SKILL.md files with YAML-ish frontmatter** so a technique can be authored,
shared, and versioned as plain Markdown - no code change to add one.

This module is that formatter: it parses a SKILL.md into a `SkillSpec`, renders a
spec back to SKILL.md (round-trips), turns a spec into a runtime `Skill` whose
predicate is BUILT FROM the frontmatter (ports / target scheme / keywords), and
loads a directory of them into the injectable set (`register_skill`). The body is
the playbook text injected into context when the skill matches.

Frontmatter (all trigger fields optional; a skill with none never auto-injects):

    ---
    name: lfi_ssrf                      # required, unique
    description: Local file inclusion / SSRF playbook
    when_to_use: When a parameter takes a path or URL
    ports: [80, 443, 8080]             # match if any open port matches
    keywords: [lfi, ssrf, file=, url=] # match if the request mentions any (word-ish)
    target_scheme: [http, https]       # match if the target is a URL with this scheme
    phase: exploitation                # advisory only
    tools: [http_request]              # advisory only
    ---
    <the playbook body injected into context>

The parser is dependency-free (a tiny subset of YAML: scalars + inline [a, b] lists),
so it never pulls in PyYAML.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from core.skills_playbook import Skill, _bare_ports, register_skill

logger = logging.getLogger(__name__)


@dataclass
class SkillSpec:
    """The parsed contents of a SKILL.md - frontmatter fields plus the body."""
    name: str
    description: str = ""
    when_to_use: str = ""
    ports: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    target_scheme: list[str] = field(default_factory=list)
    phase: str = ""
    tools: list[str] = field(default_factory=list)
    body: str = ""


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

def _split_frontmatter(text: str) -> "tuple[str, str]":
    """Return (frontmatter, body). A document that doesn't open with a `---` fence
    has no frontmatter - the whole thing is the body."""
    t = (text or "").lstrip("﻿")            # tolerate a BOM
    if not t.startswith("---"):
        return "", text or ""
    # Drop the opening fence line, find the closing one.
    rest = t.split("\n", 1)[1] if "\n" in t else ""
    m = re.search(r"^---[ \t]*$", rest, re.MULTILINE)
    if not m:
        return "", text or ""
    return rest[: m.start()], rest[m.end():].lstrip("\n")


def _parse_scalar(val: str) -> Any:
    val = val.strip()
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [_unquote(p.strip()) for p in inner.split(",") if p.strip()]
    return _unquote(val)


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


def _parse_frontmatter(fm: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for line in fm.splitlines():
        line = line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        data[key.strip().lower()] = _parse_scalar(val)
    return data


def _as_list(val: Any) -> list[str]:
    if val is None:
        return []
    if isinstance(val, list):
        return [str(x).strip() for x in val if str(x).strip()]
    s = str(val).strip()
    return [s] if s else []


def parse_skill_md(text: str) -> SkillSpec:
    """Parse SKILL.md text into a SkillSpec (name may be empty if malformed)."""
    fm, body = _split_frontmatter(text)
    d = _parse_frontmatter(fm)
    return SkillSpec(
        name=str(d.get("name", "")).strip(),
        description=str(d.get("description", "")).strip(),
        when_to_use=str(d.get("when_to_use", "")).strip(),
        ports=[p.split("/")[0] for p in _as_list(d.get("ports"))],
        keywords=_as_list(d.get("keywords")),
        target_scheme=[s.lower() for s in _as_list(d.get("target_scheme"))],
        phase=str(d.get("phase", "")).strip(),
        tools=_as_list(d.get("tools")),
        body=body.strip(),
    )


# --------------------------------------------------------------------------- #
# Formatting (round-trips with parse_skill_md)
# --------------------------------------------------------------------------- #

def format_skill_md(spec: SkillSpec) -> str:
    """Render a SkillSpec back to canonical SKILL.md text."""
    lines = ["---", f"name: {spec.name}"]
    if spec.description:
        lines.append(f"description: {spec.description}")
    if spec.when_to_use:
        lines.append(f"when_to_use: {spec.when_to_use}")
    if spec.ports:
        lines.append(f"ports: [{', '.join(spec.ports)}]")
    if spec.keywords:
        lines.append(f"keywords: [{', '.join(spec.keywords)}]")
    if spec.target_scheme:
        lines.append(f"target_scheme: [{', '.join(spec.target_scheme)}]")
    if spec.phase:
        lines.append(f"phase: {spec.phase}")
    if spec.tools:
        lines.append(f"tools: [{', '.join(spec.tools)}]")
    lines.append("---")
    lines.append("")
    lines.append(spec.body.strip())
    return "\n".join(lines) + "\n"


TEMPLATE = format_skill_md(SkillSpec(
    name="my_skill",
    description="One line on what this playbook is for.",
    when_to_use="A human-readable description of when this applies.",
    ports=["80", "443"],
    keywords=["example", "keyword"],
    target_scheme=["http", "https"],
    phase="exploitation",
    tools=["http_request"],
    body=("ACTIVE PLAYBOOK - describe the technique here. This body is injected "
          "into the model's context verbatim whenever the skill matches, so write "
          "it as concrete, imperative guidance (tools, endpoints, payloads, proof)."),
))


# --------------------------------------------------------------------------- #
# Spec → runtime Skill (predicate built from the frontmatter)
# --------------------------------------------------------------------------- #

def _make_matcher(spec: SkillSpec):
    ports = {p for p in spec.ports if p}
    schemes = tuple(s for s in spec.target_scheme if s)
    kw_re = None
    if spec.keywords:
        kw_re = re.compile(
            "|".join(re.escape(k) for k in spec.keywords), re.IGNORECASE)

    def matches(state: Any, user_input: str) -> bool:
        if ports and (_bare_ports(state) & ports):
            return True
        target = str(getattr(state, "target", "") or "").lower()
        if schemes and target.startswith(tuple(f"{s}://" for s in schemes)):
            return True
        if ports and ":" in target and target.rsplit(":", 1)[-1] in ports:
            return True
        if kw_re and kw_re.search(user_input or ""):
            return True
        return False

    return matches


def spec_to_skill(spec: SkillSpec) -> Skill:
    """Build an injectable Skill whose predicate comes from the spec's triggers."""
    return Skill(name=spec.name, matches=_make_matcher(spec), body=spec.body)


# --------------------------------------------------------------------------- #
# Loading a directory of SKILL.md files
# --------------------------------------------------------------------------- #

def load_skill_file(path: str) -> Optional[Skill]:
    """Parse and register one SKILL.md file. Returns the Skill, or None if the file
    is unreadable, has no name, or has no body."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        logger.warning("Skill file unreadable (%s): %s", path, exc)
        return None
    spec = parse_skill_md(text)
    if not spec.name or not spec.body:
        logger.warning("Skipping %s - a SKILL.md needs a `name` and a body.", path)
        return None
    skill = spec_to_skill(spec)
    register_skill(skill)
    return skill


def load_skill_dir(path: str) -> list[Skill]:
    """Load every *.md file in `path` (non-recursive) as a SKILL.md and register it.
    Returns the skills loaded. A missing directory is a no-op (returns [])."""
    if not path or not os.path.isdir(path):
        return []
    loaded: list[Skill] = []
    for name in sorted(os.listdir(path)):
        if not name.lower().endswith(".md"):
            continue
        skill = load_skill_file(os.path.join(path, name))
        if skill is not None:
            loaded.append(skill)
    if loaded:
        logger.info("Loaded %d file-authored skill(s) from %s: %s",
                    len(loaded), path, ", ".join(s.name for s in loaded))
    return loaded
