"""
engagement_log.py — auditable engagement log (feature K)

A structured, timestamped, append-only trail of everything the agent did during
an engagement: every tool call and its outcome, every finding (flag / credential
/ vuln / open port), every Rules-of-Engagement refusal, and delegation/verifier
events. It is pure infrastructure — it subscribes to the existing `EventBus` and
writes records; it never drives behavior.

Why it earns its place: Hermes-style assistants give you a chat history; a
security engagement needs a *deliverable* and an *audit trail*. This log is the
raw material both for compliance/debrief and for the features that build on it —
automated reporting (L) reads it, and skill-synthesis (N) mines successful tool
chains out of it. It is also where feature J's `agent.scope_refused` events land,
turning "the guardrail fired" into a record someone can review.

Format: newline-delimited JSON (one record per line), so it is append-only,
crash-safe (each line flushed), and trivially greppable / streamable. A
human-readable Markdown timeline is generated on demand (`export_markdown`).

Each record:  {"ts": <iso8601>, "kind": <str>, "session": <str>, ...fields}
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .event_bus import Event, EventBus

# Bus topic → record kind. Only these topics are logged; everything else on the
# bus is ignored, so the trail stays signal, not noise.
_TOPIC_KIND = {
    "task.result": "tool_call",
    "task.error": "tool_call",
    "agent.finding": "finding",
    "agent.scope_refused": "scope_refused",
    "agent.delegate.start": "delegate_start",
    "agent.delegate.end": "delegate_end",
    "agent.verify.retry": "verify_retry",
    "agent.duplicate_call": "duplicate_call",
}

# Tool output can be huge; the trail keeps a bounded preview (full output already
# lives in the model context / memory). Tune if richer evidence capture is needed.
_OUTPUT_PREVIEW = 800


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EngagementLog:
    """Append-only JSONL audit trail, fed by the event bus."""

    path: Path
    session_id: str = ""
    _records: list[dict[str, Any]] = field(default_factory=list)
    _bus: Optional[EventBus] = None
    _closed: bool = False

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Wiring
    # ------------------------------------------------------------------ #

    def attach(self, bus: EventBus, *, metadata: Optional[dict[str, Any]] = None) -> None:
        """Subscribe to the audited topics and write the opening record."""
        self._bus = bus
        for topic in _TOPIC_KIND:
            bus.subscribe(topic, self._on_event)
        self.record("session_start", {**(metadata or {}), "session": self.session_id})

    async def _on_event(self, event: Event) -> None:
        kind = _TOPIC_KIND.get(event.topic)
        if kind is None:
            return
        self.record(kind, self._fields_for(kind, event))

    def _fields_for(self, kind: str, event: Event) -> dict[str, Any]:
        data = event.data or {}
        session = data.get("session_id") or self.session_id
        if kind == "tool_call":
            out = data.get("output") or ""
            return {
                "session": session,
                "tool": data.get("tool_name"),
                "args": data.get("args"),
                "ok": not data.get("error"),
                "error": data.get("error"),
                "output_preview": out[:_OUTPUT_PREVIEW],
                "output_len": len(out),
            }
        if kind == "finding":
            return {"session": session, "finding_type": data.get("finding_type"),
                    "value": data.get("value"), "target": data.get("target")}
        if kind == "scope_refused":
            return {"session": session, "tool": data.get("tool_name"),
                    "reason": data.get("reason"), "args": data.get("args")}
        if kind in ("delegate_start", "delegate_end"):
            return {"session": session, "task": data.get("task"),
                    "operator": data.get("operator"),
                    "depth": data.get("depth"), "iterations": data.get("iterations"),
                    "opsec": data.get("opsec"), "opsec_reason": data.get("opsec_reason")}
        if kind == "verify_retry":
            return {"session": session, "reason": data.get("reason"),
                    "suggestion": data.get("suggestion")}
        if kind == "duplicate_call":
            return {"session": session, "tool": data.get("tool_name")}
        return {"session": session}

    # ------------------------------------------------------------------ #
    # Writing
    # ------------------------------------------------------------------ #

    def record(self, kind: str, fields: dict[str, Any]) -> None:
        """Append one record. Never raises — an audit log must not crash a turn."""
        if self._closed:
            return
        rec = {"ts": _now(), "kind": kind, **fields}
        self._records.append(rec)
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, default=str) + "\n")
        except OSError:
            pass

    def close(self, summary: Optional[dict[str, Any]] = None) -> None:
        if self._closed:
            return
        self.record("session_end", {**(summary or {}), "session": self.session_id})
        if self._bus is not None:
            for topic in _TOPIC_KIND:
                self._bus.unsubscribe(topic, self._on_event)
        self._closed = True

    # ------------------------------------------------------------------ #
    # Reading / export
    # ------------------------------------------------------------------ #

    @property
    def records(self) -> list[dict[str, Any]]:
        return list(self._records)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self._records:
            out[r["kind"]] = out.get(r["kind"], 0) + 1
        return out

    def summary(self) -> str:
        c = self.counts()
        return (f"{len(self._records)} records — "
                f"{c.get('tool_call', 0)} tool calls, "
                f"{c.get('finding', 0)} findings, "
                f"{c.get('scope_refused', 0)} RoE refusals  →  {self.path}")

    def export_markdown(self, out_path: Optional[str | Path] = None) -> Path:
        """Render the trail as a human-readable Markdown timeline (seeds L)."""
        out_path = Path(out_path) if out_path else self.path.with_suffix(".md")
        lines = [f"# Engagement log — {self.session_id or self.path.stem}", ""]
        c = self.counts()
        lines.append(f"- Tool calls: {c.get('tool_call', 0)}")
        lines.append(f"- Findings: {c.get('finding', 0)}")
        lines.append(f"- RoE refusals: {c.get('scope_refused', 0)}")
        lines.append("")

        findings = [r for r in self._records if r["kind"] == "finding"]
        if findings:
            lines.append("## Findings")
            for r in findings:
                tgt = f" (target {r.get('target')})" if r.get("target") else ""
                lines.append(f"- **{r.get('finding_type')}**: `{r.get('value')}`{tgt}")
            lines.append("")

        lines.append("## Timeline")
        for r in self._records:
            ts = r.get("ts", "")
            kind = r["kind"]
            if kind == "tool_call":
                status = "ok" if r.get("ok") else f"ERROR: {r.get('error')}"
                detail = f"`{r.get('tool')}` {_short_args(r.get('args'))} → {status}"
            elif kind == "finding":
                detail = f"finding {r.get('finding_type')}: {r.get('value')}"
            elif kind == "scope_refused":
                detail = f"⛔ RoE refused `{r.get('tool')}` — {r.get('reason')}"
            elif kind in ("session_start", "session_end"):
                detail = kind.replace("_", " ")
            else:
                detail = kind.replace("_", " ")
            lines.append(f"- `{ts}` {detail}")
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return out_path


def _short_args(args: Any, limit: int = 80) -> str:
    if not args:
        return ""
    try:
        s = json.dumps(args, default=str)
    except Exception:
        s = str(args)
    return s if len(s) <= limit else s[:limit] + "…}"
