"""
asciicast.py - record the engagement as an asciinema v2 cast (evidence capture).

A real engagement wants a replayable record of what the agent actually did - the
court-ready / debrief artifact. This subscribes to the event bus and writes an
asciicast v2 file (`<workspace>/engagement.cast`): a JSON header line followed by
`[time, "o", text]` output frames for each tool call, its result, findings, and RoE
refusals. Replay with `asciinema play engagement.cast` or any asciicast player.

Pure/offline, dependency-free, never raises into the loop.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional

# Bus topics rendered as terminal frames.
_TOPICS = ("task.start", "task.result", "task.error", "agent.finding",
           "agent.scope_refused", "agent.injection_detected",
           "agent.delegate.start", "agent.delegate.end")


class AsciicastRecorder:
    """Writes an asciicast v2 file from engagement events."""

    def __init__(self, path: str | Path, *, width: int = 100, height: int = 30,
                 title: str = "Mapache engagement") -> None:
        self.path = Path(path)
        self._start = time.time()
        self._bus: Any = None
        self._closed = False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            header = {"version": 2, "width": width, "height": height,
                      "timestamp": int(self._start), "title": title,
                      "env": {"TERM": "xterm-256color", "SHELL": "/bin/sh"}}
            with self.path.open("w", encoding="utf-8") as fh:
                fh.write(json.dumps(header) + "\n")
            self._ok = True
        except OSError:
            self._ok = False

    # -- wiring --------------------------------------------------------- #

    def attach(self, bus: Any) -> None:
        self._bus = bus
        for topic in _TOPICS:
            bus.subscribe(topic, self._on_event)
        self._write("$ mapache engagement - recording started\r\n")

    async def _on_event(self, event: Any) -> None:
        self._write(self._render(getattr(event, "topic", ""), getattr(event, "data", {}) or {}))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._write("$ engagement complete - recording stopped\r\n")
        if self._bus is not None:
            for topic in _TOPICS:
                try:
                    self._bus.unsubscribe(topic, self._on_event)
                except Exception:
                    pass

    # -- rendering ------------------------------------------------------ #

    @staticmethod
    def _render(topic: str, d: dict) -> str:
        def clip(x: Any, n: int = 600) -> str:
            s = str(x or "")
            return s if len(s) <= n else s[:n] + "…"
        if topic == "task.start":
            args = d.get("args")
            return f"$ {d.get('tool') or d.get('name')} {clip(args, 200)}\r\n"
        if topic == "task.result":
            return clip(d.get("output"), 800).replace("\n", "\r\n") + "\r\n"
        if topic == "task.error":
            return f"[error] {clip(d.get('error'), 200)}\r\n"
        if topic == "agent.finding":
            return f"[+] finding {d.get('finding_type')}: {clip(d.get('value'), 120)}\r\n"
        if topic == "agent.scope_refused":
            return f"[!] RoE refused {d.get('tool_name')}: {clip(d.get('reason'), 120)}\r\n"
        if topic == "agent.injection_detected":
            return f"[shield] prompt-injection blocked from {d.get('tool')}: {d.get('patterns')}\r\n"
        if topic == "agent.delegate.start":
            return f"» delegate → {d.get('operator')}: {clip(d.get('task'), 120)}\r\n"
        if topic == "agent.delegate.end":
            return f"« {d.get('operator')} done\r\n"
        return ""

    def _write(self, text: str) -> None:
        if not text or self._closed or not getattr(self, "_ok", False):
            return
        frame = [round(time.time() - self._start, 3), "o", text]
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(frame) + "\n")
        except OSError:
            pass
