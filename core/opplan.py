"""
opplan.py — operation plan (OPPLAN) with objective status transitions.

The lead orchestrator tracks the engagement as a list of OBJECTIVES, each owned by
a phase/specialist and moving through explicit states:

    pending → in_progress → passed | blocked

This is the richer, orchestration-facing sibling of the model's self-planning todo
list: where todos are the agent's private scratchpad, the OPPLAN is the durable
operation plan the lead drives — dispatch an objective to a specialist, then mark it
`passed` or `blocked` from the specialist's PASSED/BLOCKED report. The progress
table is injected into the lead's context every turn so it always sees what's done,
what's next, and what's stuck. Persisted to `<workspace>/opplan.json`.

Dependency-free + deterministic, like knowledge_graph / engagement_log.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

OBJECTIVE_STATUSES = ("pending", "in_progress", "passed", "blocked")
_MARK = {"pending": "[ ]", "in_progress": "[~]", "passed": "[x]", "blocked": "[!]"}


@dataclass
class Objective:
    id: int
    text: str
    operator: str = ""          # the specialist that owns it (optional)
    status: str = "pending"     # pending | in_progress | passed | blocked
    note: str = ""              # short result/blocker detail

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "text": self.text, "operator": self.operator,
                "status": self.status, "note": self.note}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Objective":
        status = d.get("status", "pending")
        return cls(id=int(d.get("id") or 0), text=str(d.get("text") or ""),
                   operator=str(d.get("operator") or ""),
                   status=status if status in OBJECTIVE_STATUSES else "pending",
                   note=str(d.get("note") or ""))


class OPPLAN:
    def __init__(self, path: Optional[str | Path] = None) -> None:
        self.path = Path(path) if path else None
        self._objectives: list[Objective] = []
        self._next_id = 1
        if self.path and self.path.is_file():
            self.load()

    # -- mutate --------------------------------------------------------- #

    def add(self, text: str, operator: str = "", *, save: bool = True) -> Optional[Objective]:
        text = (text or "").strip()
        if not text:
            return None
        obj = Objective(id=self._next_id, text=text, operator=(operator or "").strip())
        self._next_id += 1
        self._objectives.append(obj)
        if save:
            self.save()
        return obj

    def set_objectives(self, items: list) -> None:
        """Replace the plan from a list of strings or {text, operator, status} dicts,
        preserving the status of any objective whose text already existed."""
        prev = {o.text: o for o in self._objectives}
        self._objectives = []
        self._next_id = 1
        for raw in items or []:
            if isinstance(raw, dict):
                text = str(raw.get("text") or raw.get("objective") or "").strip()
                operator = str(raw.get("operator") or "").strip()
                status = raw.get("status", "pending")
            else:
                text, operator, status = str(raw).strip(), "", "pending"
            if not text:
                continue
            if text in prev:
                status = prev[text].status
                operator = operator or prev[text].operator
            if status not in OBJECTIVE_STATUSES:
                status = "pending"
            self._objectives.append(Objective(id=self._next_id, text=text,
                                              operator=operator, status=status))
            self._next_id += 1
        self.save()

    def update(self, ref, *, status: Optional[str] = None,
               note: Optional[str] = None, operator: Optional[str] = None,
               save: bool = True) -> bool:
        obj = self._resolve(ref)
        if obj is None:
            return False
        if status is not None:
            if status not in OBJECTIVE_STATUSES:
                return False
            obj.status = status
        if note is not None:
            obj.note = note
        if operator is not None:
            obj.operator = operator
        if save:
            self.save()
        return True

    def _resolve(self, ref) -> Optional[Objective]:
        if isinstance(ref, bool):  # bool is an int subclass — guard
            return None
        if isinstance(ref, int):
            return next((o for o in self._objectives if o.id == ref), None)
        text = str(ref).strip().lstrip("#")
        if text.isdigit():
            return next((o for o in self._objectives if o.id == int(text)), None)
        low = text.lower()
        return next((o for o in self._objectives if low in o.text.lower()), None)

    # -- query ---------------------------------------------------------- #

    def objectives(self) -> list[Objective]:
        return list(self._objectives)

    def next_pending(self) -> Optional[Objective]:
        """The next objective to work: an in_progress one, else the first pending."""
        return (next((o for o in self._objectives if o.status == "in_progress"), None)
                or next((o for o in self._objectives if o.status == "pending"), None))

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in OBJECTIVE_STATUSES}
        for o in self._objectives:
            c[o.status] = c.get(o.status, 0) + 1
        return c

    def table(self) -> str:
        """The progress table injected into the lead's context (empty if no plan)."""
        if not self._objectives:
            return ""
        c = self.counts()
        done, total = c["passed"], len(self._objectives)
        lines = [f"OPPLAN — operation plan ({done}/{total} passed, "
                 f"{c['blocked']} blocked):"]
        for o in self._objectives:
            owner = f" @{o.operator}" if o.operator else ""
            note = f" — {o.note}" if o.note else ""
            lines.append(f"  {_MARK.get(o.status, '[ ]')} #{o.id} {o.text}{owner}"
                         f" [{o.status}]{note}")
        return "\n".join(lines)

    # -- persistence ---------------------------------------------------- #

    def to_dict(self) -> dict[str, Any]:
        return {"next_id": self._next_id,
                "objectives": [o.to_dict() for o in self._objectives]}

    def save(self) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.to_dict(), indent=2) + "\n",
                                 encoding="utf-8")
        except OSError:
            pass

    def load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        self._objectives = [Objective.from_dict(d) for d in data.get("objectives") or []
                            if (d.get("text") or "").strip()]
        self._next_id = int(data.get("next_id")
                            or (max((o.id for o in self._objectives), default=0) + 1))
