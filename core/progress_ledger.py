"""
progress_ledger.py - a running record of what the agent has tried, so it stops
re-trying dead ends (agent-loop plan P1).

The controller already injects CONFIRMED facts (the attack-state blackboard + the
knowledge graph) into context each turn, and short-circuits an EXACT duplicate
call within a turn. What was missing is the *negative* knowledge that must survive
ACROSS turns: which distinct actions were tried and led nowhere. Blind
endpoint/credential spraying and re-attempting dead ends were a top failure mode in
the XBOW runs, and the exact-duplicate guard resets every turn, so nothing stopped
the model from re-walking the same fruitless path a turn later.

This ledger records every dispatched action's outcome - productive (it surfaced a
new finding) or a dead end - and renders a compact block the loop injects so the
model avoids repeating approaches that already paid nothing. It is advisory, not a
hard block: an action that was fruitless early (e.g. before auth) can become
productive later, so a later win PROMOTES it back out of the dead-end list.
"""

from __future__ import annotations

from typing import Any

# Arg keys whose value best labels an action, in priority order. The first one
# present gives the ledger entry a human-readable tail (the URL/command/target)
# instead of an opaque JSON signature.
_SALIENT_ARGS = ("url", "cmd", "command", "target", "host", "query",
                 "path", "endpoint", "payload", "task", "goal")


def action_label(tool_name: str, args: dict[str, Any]) -> str:
    """A short, human-readable label for an action.

    e.g. ``http_request GET /admin`` or ``shell nmap -p- 10.0.0.5``. Falls back to
    the bare tool name when no salient argument is present.
    """
    if not isinstance(args, dict):
        return tool_name
    for key in _SALIENT_ARGS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            v = " ".join(val.strip().split())          # collapse whitespace
            if len(v) > 80:
                v = v[:77] + "…"
            method = args.get("method")                # disambiguates web calls
            if isinstance(method, str) and method.strip():
                return f"{tool_name} {method.strip().upper()} {v}"
            return f"{tool_name} {v}"
    return tool_name


class ProgressLedger:
    """Distinct actions and their outcomes over one engagement.

    Keyed on the same call signature the controller uses for its per-turn duplicate
    guard, but persisted on the controller so it accumulates across turns. Dead-end
    membership is tracked by signature (exact); labels are kept only for display.
    """

    def __init__(self, max_shown: int = 8) -> None:
        self.max_shown = max_shown
        self._tried: set[str] = set()       # every signature seen, any outcome
        self._productive: list[str] = []    # labels that surfaced a new finding
        self._dead: list[str] = []          # dead-end labels, ordered, deduped
        self._dead_sigs: set[str] = set()   # dead-end signatures (the real key)
        self.total = 0                      # distinct actions tried

    def record(self, signature: str, label: str, found_new: bool) -> None:
        """Log one dispatched action's outcome."""
        if signature not in self._tried:
            self._tried.add(signature)
            self.total += 1
        if found_new:
            # It paid off - make sure it is not also listed as a dead end.
            if signature in self._dead_sigs:
                self._dead_sigs.discard(signature)
                self._dead = [d for d in self._dead if d != label]
            if label not in self._productive:
                self._productive.append(label)
        elif signature not in self._dead_sigs and label not in self._productive:
            self._dead_sigs.add(signature)
            self._dead.append(label)

    def is_dead_end(self, signature: str) -> bool:
        return signature in self._dead_sigs

    def render(self) -> str:
        """A compact block for injection, or "" when there is nothing to say."""
        if not self._dead and not self.total:
            return ""
        lines = ["Progress ledger (what you have already tried this engagement):"]
        if self._dead:
            shown = self._dead[-self.max_shown:]
            lines.append("  Dead ends - these produced nothing new, so do NOT repeat "
                         "them; try a genuinely different endpoint, parameter, "
                         "credential, or technique:")
            lines += [f"    - {d}" for d in shown]
            if len(self._dead) > len(shown):
                lines.append(f"    …and {len(self._dead) - len(shown)} more.")
        lines.append(f"  ({self.total} distinct actions tried, "
                     f"{len(self._productive)} productive.)")
        return "\n".join(lines)
