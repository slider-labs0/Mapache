"""
soul.py — user-editable persona (feature E)

`soul.md` is the one knob a user turns to change *how* Mapache talks and what it
prioritizes, without touching the offensive system prompt. Its contents are
prepended to the system prompt each turn (the controller re-reads the file every
turn, so edits hot-reload with no restart). It shapes voice/priorities only — the
safety + RoE framing lives in the system prompt and is not overridable here.

Resolution mirrors the config layer: a project `soul.md` in the working dir wins
over the global `~/.mapache/soul.md`; if neither exists, a documented default
persona ships in-process so there is always a sane voice. `/soul` prints the
active persona; `/soul init` writes the default to the global path to edit.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

DEFAULT_SOUL = """# Operator Persona

You are Mapache, a focused offensive-security operator. Communicate like a
seasoned pentester briefing a teammate: direct, technical, and concise. Lead with
the finding or the next concrete action — skip filler, preamble, and hedging.
Quote exact artifacts (ports, versions, hashes, paths, flags) rather than
paraphrasing them.

Bias toward action: when the attack state makes the next step obvious, take it
rather than asking. Escalate to the user when you are blocked, when something is
ambiguous and the choice matters, or when an action would exceed scope.

You operate only within authorized engagements and the active Rules of
Engagement. When something is out of scope or forbidden, say so plainly instead
of working around it.

(This persona is user-editable — edit soul.md to change Mapache's voice and
priorities. Changes take effect on your next message.)
"""


def global_soul_path(environ: Optional[dict[str, str]] = None) -> Path:
    environ = environ if environ is not None else dict(os.environ)
    home = environ.get("USERPROFILE") or environ.get("HOME") or str(Path.home())
    return Path(home) / ".mapache" / "soul.md"


def soul_file(
    working_dir: str | Path = ".",
    *,
    environ: Optional[dict[str, str]] = None,
) -> Optional[Path]:
    """The active soul.md path: project (working dir) over global, or None."""
    project = Path(working_dir) / "soul.md"
    if project.is_file():
        return project
    glob = global_soul_path(environ)
    return glob if glob.is_file() else None


def load_soul(
    working_dir: str | Path = ".",
    *,
    environ: Optional[dict[str, str]] = None,
) -> str:
    """Active persona text: the project/global file if present, else the default.

    Fail-soft — an unreadable file falls back to the shipped default rather than
    breaking the turn.
    """
    path = soul_file(working_dir, environ=environ)
    if path is not None:
        try:
            text = path.read_text(encoding="utf-8").strip()
            if text:
                return text
        except OSError:
            pass
    return DEFAULT_SOUL.strip()


def init_soul(
    *,
    path: Optional[Path] = None,
    environ: Optional[dict[str, str]] = None,
    overwrite: bool = False,
) -> tuple[Path, bool]:
    """Write the default persona to the global path so the user can edit it.

    Returns (path, written) — written is False if a file already existed and
    overwrite was not requested.
    """
    target = Path(path) if path is not None else global_soul_path(environ)
    if target.is_file() and not overwrite:
        return target, False
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(DEFAULT_SOUL, encoding="utf-8")
    return target, True
