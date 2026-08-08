"""
learning_store.py - cross-engagement learning (gets smarter over many runs)

Skill synthesis (feature N) learns a reusable tool from ONE successful chain. This is
the complementary loop across MANY engagements: record each engagement's outcome keyed
by a target FINGERPRINT (its services/ports), then feed that history back so routing and
context favour what has actually worked against similar targets before.

Two feedback channels:
  - `operator_bias(fingerprint)` → a small per-operator score bump the OperatorRouter
    adds, so an operator that has repeatedly won on this kind of target is tried sooner.
  - `hint(fingerprint)` → a compact "what worked against similar targets before" block
    the lead can inject into context.

Persisted as JSON (append-only outcomes) so the knowledge survives across sessions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional


def fingerprint_of(services: Any, ports: Any) -> str:
    """A stable fingerprint of a target from its services (preferred) or bare ports.
    e.g. {'80':'http','443':'https'} -> 'http,https'; ['445/tcp','139'] -> '139,445'."""
    svc = sorted({str(v).strip().lower() for v in (services or {}).values() if str(v).strip()})
    if svc:
        return ",".join(svc)
    bare = sorted({str(p).split("/")[0].strip() for p in (ports or []) if str(p).strip()})
    return ",".join(bare)


@dataclass
class EngagementOutcome:
    fingerprint: str
    solved: bool
    operators: list[str] = field(default_factory=list)   # operators that ran
    vuln_classes: list[str] = field(default_factory=list)  # vulnerabilities found
    target: str = ""
    ts: str = ""                                          # caller-stamped (scripts can't call now())


class LearningStore:
    """Append-only history of engagement outcomes with fingerprint-keyed recall."""

    def __init__(self, path: Optional[str | Path] = None) -> None:
        self.path = Path(path) if path else None
        self._outcomes: list[EngagementOutcome] = []
        if self.path and self.path.is_file():
            self.load()

    # -- persistence ---------------------------------------------------- #
    def load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self._outcomes = [EngagementOutcome(**o) for o in data.get("outcomes", [])]
        except Exception:
            self._outcomes = []

    def save(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(
                json.dumps({"outcomes": [asdict(o) for o in self._outcomes]}, indent=2),
                encoding="utf-8")
        except Exception:
            pass  # a learning-store hiccup must never break an engagement

    # -- record / recall ------------------------------------------------ #
    def record(self, outcome: EngagementOutcome, *, save: bool = True) -> None:
        if not outcome.fingerprint:
            return
        self._outcomes.append(outcome)
        if save:
            self.save()

    def _similar(self, fingerprint: str) -> list[EngagementOutcome]:
        """Outcomes sharing at least one service/port token with the fingerprint."""
        want = {t for t in (fingerprint or "").split(",") if t}
        if not want:
            return []
        out = []
        for o in self._outcomes:
            have = {t for t in o.fingerprint.split(",") if t}
            if want & have:
                out.append(o)
        return out

    def operator_bias(self, fingerprint: str, *, max_bonus: float = 1.5) -> dict[str, float]:
        """Per-operator score bump in [0, max_bonus], from how often each operator was
        part of a SOLVED engagement against a similar target. Only wins count, so this
        biases toward proven paths without penalising the unknown."""
        wins: dict[str, int] = {}
        best = 0
        for o in self._similar(fingerprint):
            if not o.solved:
                continue
            for op in set(o.operators):
                wins[op] = wins.get(op, 0) + 1
                best = max(best, wins[op])
        if best <= 0:
            return {}
        return {op: round(max_bonus * n / best, 3) for op, n in wins.items()}

    def hint(self, fingerprint: str, *, limit: int = 3) -> str:
        """A compact 'what worked against similar targets before' block, or ''."""
        solved = [o for o in self._similar(fingerprint) if o.solved]
        if not solved:
            return ""
        lines = ["Prior wins against similar targets (learned across engagements):"]
        for o in solved[-limit:]:
            ops = ", ".join(o.operators[:4]) or "?"
            vulns = ("; ".join(o.vuln_classes[:3])) if o.vuln_classes else ""
            lines.append(f"  - [{o.fingerprint}] worked via {ops}"
                         + (f" - {vulns}" if vulns else ""))
        return "\n".join(lines)

    def __len__(self) -> int:
        return len(self._outcomes)
