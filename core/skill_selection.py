"""
skill_selection.py - model-based (hybrid) skill activation.

Predicate matching (`core/skills_playbook.py`) stays the fast, offline, deterministic
path for the built-in domain playbooks. This adds a SECOND layer: for skills that
carry a `description` but whose predicate did NOT fire - i.e. description-only /
foreign skills imported from other agents (Claude-style SKILL.md that have no Mapache
port/keyword triggers) - a capable model reads the skill catalog and selects which
apply to the current objective + attack state.

The extra model call is cost-bounded two ways: the caller only invokes the selector
when there are candidates at all (built-ins never produce candidates), and selections
are cached by a signature of the engagement state so the call fires only when the
situation materially changes. Any failure falls back to selecting nothing - the
predicate path has already injected everything it matched, so the agent is never worse
off than the deterministic-only behaviour.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Awaitable, Callable, Optional

from core.skills_playbook import Skill, skill_catalog

logger = logging.getLogger(__name__)

SKILL_SELECTOR_SYSTEM_PROMPT = (
    "You are the skill selector for an offensive-security agent. You are given a "
    "catalog of optional playbooks (each as `name: description`) and the current "
    "engagement context. Choose ONLY the playbooks whose guidance is directly "
    "relevant to this target and objective right now. Prefer few; if none apply, "
    'choose none. Respond with STRICT JSON: {"relevant": ["skill_name", ...]}. Use '
    "exact names from the catalog and invent nothing."
)

# ask(messages, json_mode) -> provider response (dict or str)
AskFn = Callable[[list[dict], bool], Awaitable[Any]]


def _state_signature(state: Any, user_input: str, candidates: list[Skill]) -> tuple:
    target = str(getattr(state, "target", "") or "")
    phase = str(getattr(state, "phase", "") or "")
    try:
        ports = tuple(sorted(str(p) for p in (getattr(state, "open_ports", None) or [])))
    except Exception:
        ports = ()
    return (target, phase, ports, (user_input or "")[:200],
            tuple(sorted(s.name for s in candidates)))


def _extract_content(raw: Any) -> str:
    if isinstance(raw, dict):
        return raw.get("message", {}).get("content", "") or raw.get("content", "") or ""
    return str(raw or "")


def _parse_names(text: str, valid: set[str]) -> list[str]:
    """Pull skill names out of a model reply: strict JSON first, then a loose
    object/array scan, then a last-resort scan for exact catalog names in prose.
    Only names present in `valid` survive."""
    names: list[str] = []
    try:
        m = re.search(r"\{.*\}|\[.*\]", text, re.DOTALL)
        data = json.loads(m.group(0) if m else text)
        if isinstance(data, dict):
            data = data.get("relevant") or data.get("skills") or []
        if isinstance(data, list):
            names = [str(x).strip() for x in data]
    except Exception:
        names = []
    if not names:
        names = [n for n in valid if re.search(rf"\b{re.escape(n)}\b", text)]
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        if n in valid and n not in seen:
            seen.add(n)
            out.append(n)
    return out


class ModelSkillSelector:
    """Model-driven selection over description-bearing skill candidates, cached by
    engagement-state signature. `ask` is an async provider call; when it is None or
    the selector is disabled, `select` is a no-op (pure predicate behaviour)."""

    def __init__(self, ask: Optional[AskFn], *, enabled: bool = True) -> None:
        self._ask = ask
        self.enabled = enabled
        self._cache: dict[tuple, list[str]] = {}

    async def select(
        self, candidates: list[Skill], state: Any, user_input: str = "",
    ) -> list[Skill]:
        if not candidates or not self.enabled or self._ask is None:
            return []
        by_name = {s.name: s for s in candidates}
        sig = _state_signature(state, user_input, candidates)
        if sig in self._cache:
            return [by_name[n] for n in self._cache[sig] if n in by_name]

        messages = [
            {"role": "system", "content": SKILL_SELECTOR_SYSTEM_PROMPT},
            {"role": "user", "content": (
                f"CATALOG:\n{skill_catalog(candidates)}\n\n"
                f"ENGAGEMENT CONTEXT:\n{self._context_block(state, user_input)}")},
        ]
        try:
            raw = await self._ask(messages, True)
            names = _parse_names(_extract_content(raw), set(by_name))
        except Exception as exc:  # fail-soft: predicate path already covered the rest
            logger.debug("skill selection failed, selecting none: %s", exc)
            names = []
        self._cache[sig] = names
        if names:
            logger.info("model-selected skill(s): %s", ", ".join(names))
        return [by_name[n] for n in names]

    @staticmethod
    def _context_block(state: Any, user_input: str) -> str:
        target = getattr(state, "target", "") or "(none)"
        phase = getattr(state, "phase", "") or "(none)"
        try:
            ports = ", ".join(
                str(p) for p in (getattr(state, "open_ports", None) or [])) or "(none)"
        except Exception:
            ports = "(none)"
        return (f"Objective/request: {user_input or '(none)'}\n"
                f"Target: {target}\nPhase: {phase}\nOpen ports: {ports}")
