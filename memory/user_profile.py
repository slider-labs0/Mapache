"""
user_profile.py — agent-maintained user profile (feature F)

`user.md` is the inverse of `soul.md` (E): soul is human-owned and shapes the
agent's voice; this is **agent-owned** and records durable facts about the
*operator* — preferences, habits, recurring targets, past engagements — so the
agent carries continuity across sessions. It is distinct from the per-engagement
`AttackState` (which resets per target) and from `soul.md` (persona, not facts).

The agent appends facts through the `user_remember` tool; a compact summary is
injected into the prompt each turn. Growth is bounded — exact-duplicate facts are
dropped, and per-category + total caps evict the oldest entries (the same
"summarize/drop the oldest" idea compaction uses), so the profile stays a small,
high-signal block rather than an ever-growing log.

The canonical store IS the markdown file (human-readable, user-editable): facts
are `- ` bullets under `## Category` headings, parsed back on load. Lives at the
global `~/.mapache/user.md` since the operator is the same across projects.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, Optional

from plugins.sdk.base_tool import BaseTool, ToolResult

DEFAULT_CATEGORY = "Notes"
CATEGORY_ORDER = ["Identity", "Preferences", "Engagements", "Habits", "Notes"]
MAX_PER_CATEGORY = 20
MAX_TOTAL = 60


def global_profile_path(environ: Optional[dict[str, str]] = None) -> Path:
    environ = environ if environ is not None else dict(os.environ)
    home = environ.get("USERPROFILE") or environ.get("HOME") or str(Path.home())
    return Path(home) / ".mapache" / "user.md"


class UserProfile:
    """Durable, bounded, agent-maintained facts about the operator."""

    def __init__(
        self,
        path: Optional[Path] = None,
        *,
        environ: Optional[dict[str, str]] = None,
        max_per_category: int = MAX_PER_CATEGORY,
        max_total: int = MAX_TOTAL,
    ) -> None:
        self.path = Path(path) if path is not None else global_profile_path(environ)
        self.max_per_category = max_per_category
        self.max_total = max_total
        # Flat, insertion-ordered (category, fact) so the total cap can evict the
        # oldest entry across all categories.
        self._facts: list[tuple[str, str]] = []
        self.load()

    # -- read ----------------------------------------------------------- #

    def load(self) -> None:
        self._facts = []
        if not self.path.is_file():
            return
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError:
            return
        category = DEFAULT_CATEGORY
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("## "):
                category = s[3:].strip() or DEFAULT_CATEGORY
            elif s.startswith("- "):
                fact = s[2:].strip()
                if fact:
                    self._facts.append((category, fact))
        self._enforce_caps()  # a hand-edited file may exceed the caps

    def facts(self) -> list[tuple[str, str]]:
        return list(self._facts)

    def _ordered_categories(self) -> list[str]:
        present = []
        for c, _ in self._facts:
            if c not in present:
                present.append(c)
        return ([c for c in CATEGORY_ORDER if c in present]
                + [c for c in present if c not in CATEGORY_ORDER])

    def render_markdown(self) -> str:
        lines = ["# User Profile", "",
                 "_Agent-maintained facts about the operator. Safe to edit._", ""]
        for c in self._ordered_categories():
            lines.append(f"## {c}")
            lines += [f"- {f}" for cc, f in self._facts if cc == c]
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def summary(self, max_chars: int = 800) -> str:
        """Compact, labeled block for prompt injection (empty when no facts)."""
        if not self._facts:
            return ""
        parts = []
        for c in self._ordered_categories():
            facts = [f for cc, f in self._facts if cc == c]
            parts.append(f"[{c}] " + "; ".join(facts))
        body = "\n".join(parts)
        if len(body) > max_chars:
            body = body[: max_chars - 1].rstrip() + "…"
        return "USER PROFILE (durable facts about the operator):\n" + body

    # -- write ---------------------------------------------------------- #

    def add(self, fact: str, category: str = DEFAULT_CATEGORY) -> bool:
        """Add a fact; returns False if it was an exact (case-insensitive) dup."""
        fact = (fact or "").strip()
        category = (category or DEFAULT_CATEGORY).strip() or DEFAULT_CATEGORY
        if not fact:
            return False
        key = (category.lower(), fact.lower())
        if any((c.lower(), f.lower()) == key for c, f in self._facts):
            return False
        self._facts.append((category, fact))
        self._enforce_caps()
        self.save()
        return True

    def remove(self, fact: str) -> bool:
        before = len(self._facts)
        self._facts = [(c, f) for c, f in self._facts
                       if f.lower() != (fact or "").strip().lower()]
        if len(self._facts) != before:
            self.save()
            return True
        return False

    def _enforce_caps(self) -> None:
        # Per-category: keep the newest max_per_category, preserving order.
        counts: dict[str, int] = {}
        kept_rev: list[tuple[str, str]] = []
        for c, f in reversed(self._facts):
            if counts.get(c, 0) < self.max_per_category:
                kept_rev.append((c, f))
                counts[c] = counts.get(c, 0) + 1
        kept = list(reversed(kept_rev))
        # Total: keep the newest max_total across all categories.
        if len(kept) > self.max_total:
            kept = kept[len(kept) - self.max_total:]
        self._facts = kept

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(self.render_markdown(), encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)  # may hold personal info
        except OSError:
            pass


class UserRememberTool(BaseTool):
    name = "user_remember"
    description = (
        "Record a DURABLE fact about the user/operator — a preference, habit, "
        "recurring target, or past engagement — to the long-term user profile so "
        "future sessions remember it. Use sparingly, only for facts that stay true "
        "across engagements; per-engagement findings belong in the attack state, "
        "not here. Optional `category`: Identity, Preferences, Engagements, "
        "Habits, Notes."
    )
    parameters = {
        "type": "object",
        "properties": {
            "fact": {"type": "string",
                     "description": "The durable fact to remember about the operator."},
            "category": {"type": "string",
                         "description": "Identity | Preferences | Engagements | Habits | Notes."},
        },
        "required": ["fact"],
    }
    tags = ["memory", "profile"]

    def __init__(self, profile: UserProfile) -> None:
        self._profile = profile

    async def execute(self, **kwargs: Any) -> ToolResult:
        fact = (kwargs.get("fact") or "").strip()
        if not fact:
            return ToolResult.ok("No fact provided.")
        category = kwargs.get("category") or DEFAULT_CATEGORY
        if self._profile.add(fact, category):
            return ToolResult.ok(f"Remembered under {category}: {fact}")
        return ToolResult.ok(f"Already in the user profile: {fact}")
