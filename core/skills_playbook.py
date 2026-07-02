"""
skills_playbook.py — just-in-time skill/playbook injection (Decepticon-inspired).

Mirrors Decepticon's SkillsMiddleware "progressive disclosure": rather than
front-loading every technique into the system prompt, a compact playbook is
injected into context ONLY when the live attack state makes it relevant — so a
weak local model is grounded on the right approach at the right moment without
bloating every call. Matched skills drop back out when no longer relevant.

Each Skill carries a predicate over the AttackState + the user's request; the
controller injects matched bodies each turn (idempotently, alongside the live
state block).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

# Ports that indicate an HTTP application is in play.
WEB_PORTS = {"80", "443", "3000", "5000", "8000", "8080", "8443", "8888"}

_WEB_HINT_RE = re.compile(
    r"\b(https?|web(site|app)?|api|rest|login|sign[-\s]?in|url|endpoint|portal|"
    r"form|juice[-\s]?shop)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Skill:
    name: str
    matches: Callable[[Any, str], bool]
    body: str


def _is_web_target(state: Any, user_input: str) -> bool:
    """A web app is in play if a web port is open, the target is a URL, or the
    request itself talks about web/http/login."""
    try:
        ports = {str(p) for p in (getattr(state, "open_ports", None) or [])}
    except Exception:
        ports = set()
    if ports & WEB_PORTS:
        return True
    target = getattr(state, "target", "") or ""
    if target.startswith(("http://", "https://")):
        return True
    if ":" in target and target.rsplit(":", 1)[-1] in WEB_PORTS:
        return True
    return bool(_WEB_HINT_RE.search(user_input or ""))


WEB_ATTACK_SKILL = Skill(
    name="web_app_attacks",
    matches=_is_web_target,
    body=(
        "SKILL — web application attacks (this target exposes a web app):\n"
        "- Use the `http_request` tool, NOT shell curl, for all web/API testing: "
        "it sends the body and params as structured data, so injection payloads "
        "containing quotes (e.g. ' OR 1=1--) are transported verbatim.\n"
        "- Modern apps (Angular/React SPAs) are backed by a REST API; the real "
        "attack surface is the API endpoints, not the static HTML. Fetch the app "
        "root, then probe API routes.\n"
        "- SQL-injection auth bypass: POST the login endpoint with an email or "
        "username of `' OR 1=1--` and any password; a successful bypass returns "
        "an auth token or session for another user (often the administrator).\n"
        "- Common login endpoints to try: /rest/user/login, /api/login, /login, "
        "/auth, /session."
    ),
)

# The active skill set. Kept tiny on purpose — this is the prototype web skill;
# more skills (LFI, SSTI, auth, cloud, AD) slot in here the same way.
SKILLS: list[Skill] = [WEB_ATTACK_SKILL]


def relevant_skills(state: Any, user_input: str = "") -> list[str]:
    """Bodies of the skills whose predicate matches the current state/request."""
    out: list[str] = []
    for skill in SKILLS:
        try:
            if skill.matches(state, user_input):
                out.append(skill.body)
        except Exception:
            continue
    return out
