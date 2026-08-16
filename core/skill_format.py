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
    allowed_tools: list[str] = field(default_factory=list)
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
    """Parse SKILL.md frontmatter. Prefers a real YAML parser when one is installed
    (so skills authored for other agents with rich YAML parse faithfully); otherwise
    falls back to a dependency-free parser that still handles block-style lists and
    `|`/`>` multi-line scalars, not just single-line scalars + inline lists."""
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(fm)
        if isinstance(data, dict):
            return {str(k).strip().lower(): v for k, v in data.items()}
    except Exception:
        pass
    return _parse_frontmatter_fallback(fm)


def _parse_frontmatter_fallback(fm: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    lines = fm.splitlines()
    i, n = 0, len(lines)
    while i < n:
        raw = lines[i]
        stripped = raw.strip()
        i += 1
        if not stripped or stripped.startswith("#") or stripped.startswith("- "):
            continue
        if ":" not in raw:
            continue
        key, _, val = raw.partition(":")
        key = key.strip().lower()
        val = val.strip()

        # Block scalar: `key: |` / `key: >` (with optional chomp indicators).
        if val and val[0] in "|>" and val.rstrip("+-") in ("|", ">"):
            base = len(raw) - len(raw.lstrip())
            raw_block: list[str] = []
            while i < n:
                nxt = lines[i]
                if nxt.strip() == "":
                    raw_block.append("")
                    i += 1
                    continue
                if (len(nxt) - len(nxt.lstrip())) <= base:
                    break
                raw_block.append(nxt)
                i += 1
            # Dedent by the block's own indentation (the min indent of its non-blank
            # lines), per YAML block-scalar rules - not a fixed offset from the key.
            indents = [len(l) - len(l.lstrip()) for l in raw_block if l.strip()]
            bi = min(indents) if indents else base + 1
            block = [l[bi:] if len(l) >= bi else l.lstrip() for l in raw_block]
            text = "\n".join(block).strip("\n")
            if val[0] == ">":  # folded: newlines become spaces
                text = re.sub(r"\s*\n\s*", " ", text).strip()
            data[key] = text
            continue

        # `key:` with nothing after it may introduce a block list of `- item` lines.
        if val == "":
            items: list[str] = []
            while i < n and lines[i].strip().startswith("- "):
                items.append(_unquote(lines[i].strip()[2:].strip()))
                i += 1
            data[key] = items if items else ""
            continue

        data[key] = _parse_scalar(val)
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
        # Anthropic-style skills use `allowed-tools`; accept both spellings (advisory).
        allowed_tools=_as_list(d.get("allowed-tools")) or _as_list(d.get("allowed_tools")),
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


def spec_to_skill(
    spec: SkillSpec,
    resource_dir: str = "",
    resources: "tuple[str, ...]" = (),
) -> Skill:
    """Build an injectable Skill. Its predicate comes from the spec's triggers (empty
    for a trigger-less foreign skill, so it never auto-fires); `description` (falling
    back to `when_to_use`) drives model-based selection instead. Bundled resource
    files ride along for progressive disclosure."""
    return Skill(
        name=spec.name,
        matches=_make_matcher(spec),
        body=spec.body,
        description=(spec.description or spec.when_to_use).strip(),
        resource_dir=resource_dir,
        resources=tuple(resources),
    )


# --------------------------------------------------------------------------- #
# Loading a directory of SKILL.md files
# --------------------------------------------------------------------------- #

def _bundled_resources(skill_md_path: str) -> "tuple[str, tuple[str, ...]]":
    """For a `<pkg>/SKILL.md`, return (resource_dir, relative-paths of sibling files)
    so bundled scripts/references travel with the skill. A plain flat `*.md` skill
    has no package dir, so no resources."""
    if os.path.basename(skill_md_path).lower() != "skill.md":
        return "", ()
    d = os.path.dirname(skill_md_path)
    try:
        rels = tuple(sorted(
            os.path.relpath(os.path.join(root, f), d).replace(os.sep, "/")
            for root, _, files in os.walk(d)
            for f in files
            if f.lower() != "skill.md"
        ))
    except OSError:
        rels = ()
    return d, rels


def load_skill_file(path: str) -> Optional[Skill]:
    """Parse and register one SKILL.md file. Returns the Skill, or None if the file
    is unreadable, has no name, or has no body. When the file is a `<pkg>/SKILL.md`,
    sibling files in the package are attached as bundled resources."""
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
    resource_dir, resources = _bundled_resources(path)
    skill = spec_to_skill(spec, resource_dir, resources)
    register_skill(skill)
    return skill


def load_skill_dir(path: str) -> list[Skill]:
    """Load skills from `path`, supporting BOTH layouts and register each:
      - nested skill packages: `<path>/<name>/SKILL.md` (+ bundled resource files),
        discovered recursively - the convention other agents (Claude-style) use;
      - flat single-file skills: `<path>/*.md` at the top level.
    A missing directory is a no-op (returns []). Returns the skills loaded."""
    if not path or not os.path.isdir(path):
        return []
    loaded: list[Skill] = []
    seen: set[str] = set()

    # 1) Nested `SKILL.md` packages at any depth (these carry bundled resources).
    for root, _, files in os.walk(path):
        for f in files:
            if f.lower() == "skill.md":
                fp = os.path.join(root, f)
                skill = load_skill_file(fp)
                if skill is not None:
                    loaded.append(skill)
                seen.add(os.path.abspath(fp))

    # 2) Flat top-level `*.md` single-file skills not already loaded as a package.
    for name in sorted(os.listdir(path)):
        if not name.lower().endswith(".md"):
            continue
        fp = os.path.join(path, name)
        if os.path.abspath(fp) in seen or not os.path.isfile(fp):
            continue
        skill = load_skill_file(fp)
        if skill is not None:
            loaded.append(skill)

    if loaded:
        logger.info("Loaded %d file-authored skill(s) from %s: %s",
                    len(loaded), path, ", ".join(s.name for s in loaded))
    return loaded
