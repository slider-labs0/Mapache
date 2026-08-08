"""
knowledge_graph.py - disk-persisted findings store (feature: fresh-context state).

Sub-agents run with a fresh context window per objective, so they can't rely on
in-memory conversation history to know what earlier agents found. This module is
the shared, durable source of truth they read and write instead: a small typed
entity/relation graph persisted to disk (`<workspace>/knowledge/graph.json`).

Design (deliberately dependency-free + deterministic, like engagement_log/reporting):
- `Entity` - a typed node: host, service, credential, vulnerability, flag, finding,
  note. Identity is (type, value); adding the same one twice merges attrs, never
  duplicates.
- `Relation` - a typed edge between entity ids (host --runs--> service, …).
- `KnowledgeGraph` - add/query/persist. `query(type=…, contains=…)` is what an
  agent tool exposes so a freshly-spawned specialist can pull "what do we know about
  <host>" without the lead having to re-explain it.
- `sync_from_attack_state` folds the live AttackState (ports/services/creds/vulns/
  flags) into the graph, so the blackboard and the durable store stay consistent.

This is the persistence + query layer Decepticon-style staged pipelines need: state
flows between stages through the graph on disk, not through agent memory.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# Recognized entity types. `finding`/`note` are free-form; the rest mirror
# AttackState so the blackboard round-trips.
ENTITY_TYPES = {
    "host", "service", "credential", "vulnerability", "flag", "finding", "note",
}


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in text.lower()).strip("-")[:80]


@dataclass
class Entity:
    type: str
    value: str
    attrs: dict[str, Any] = field(default_factory=dict)
    source: str = ""          # which agent/tool recorded it
    ts: float = field(default_factory=time.time)

    @property
    def id(self) -> str:
        return f"{self.type}:{_slug(self.value)}"

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "type": self.type, "value": self.value,
                "attrs": dict(self.attrs), "source": self.source, "ts": self.ts}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Entity":
        return cls(type=d.get("type", "note"), value=d.get("value", ""),
                   attrs=dict(d.get("attrs") or {}), source=d.get("source", ""),
                   ts=float(d.get("ts") or time.time()))


@dataclass
class Relation:
    src: str   # entity id
    rel: str   # e.g. "runs", "found-on", "exploits"
    dst: str   # entity id

    def key(self) -> tuple[str, str, str]:
        return (self.src, self.rel, self.dst)

    def to_dict(self) -> dict[str, str]:
        return {"src": self.src, "rel": self.rel, "dst": self.dst}


class KnowledgeGraph:
    """A typed findings graph persisted to a JSON file. Adds are idempotent by
    entity id; writes auto-save when a path is set (best-effort, never raises)."""

    def __init__(self, path: Optional[str | Path] = None) -> None:
        self.path = Path(path) if path else None
        self._entities: dict[str, Entity] = {}
        self._relations: dict[tuple[str, str, str], Relation] = {}
        if self.path and self.path.is_file():
            self.load()

    # -- mutate --------------------------------------------------------- #

    def add(self, type: str, value: str, *, attrs: Optional[dict] = None,
            source: str = "", save: bool = True) -> Optional[Entity]:
        """Add or merge an entity. Returns it, or None if type/value is invalid."""
        type = (type or "").strip().lower()
        value = (value or "").strip()
        if type not in ENTITY_TYPES or not value:
            return None
        ent = Entity(type=type, value=value, attrs=dict(attrs or {}), source=source)
        existing = self._entities.get(ent.id)
        if existing is not None:
            existing.attrs.update(ent.attrs)  # merge new attrs onto the known node
            if source and not existing.source:
                existing.source = source
            ent = existing
        else:
            self._entities[ent.id] = ent
        if save:
            self.save()
        return ent

    def relate(self, src_id: str, rel: str, dst_id: str, *, save: bool = True) -> None:
        r = Relation(src=src_id, rel=rel, dst=dst_id)
        self._relations[r.key()] = r
        if save:
            self.save()

    # -- query ---------------------------------------------------------- #

    def get(self, entity_id: str) -> Optional[Entity]:
        return self._entities.get(entity_id)

    def query(self, *, type: Optional[str] = None,
              contains: Optional[str] = None) -> list[Entity]:
        """Entities filtered by type and/or a substring of value/attrs, newest first."""
        needle = (contains or "").lower().strip()
        out = []
        for e in self._entities.values():
            if type and e.type != type:
                continue
            if needle:
                hay = (e.value + " " + json.dumps(e.attrs)).lower()
                if needle not in hay:
                    continue
            out.append(e)
        return sorted(out, key=lambda e: e.ts, reverse=True)

    def entities(self) -> list[Entity]:
        return list(self._entities.values())

    def relations(self) -> list[Relation]:
        return list(self._relations.values())

    def summary(self) -> str:
        """A compact per-type tally, e.g. 'host:1 service:4 credential:2 flag:1'."""
        counts: dict[str, int] = {}
        for e in self._entities.values():
            counts[e.type] = counts.get(e.type, 0) + 1
        return " ".join(f"{t}:{counts[t]}" for t in sorted(counts)) or "(empty)"

    # -- AttackState sync ----------------------------------------------- #

    def sync_from_attack_state(self, state: Any, *, source: str = "attack_state") -> int:
        """Fold the live blackboard into the graph. Returns the number of entities
        touched. Host→service relations are recorded so the graph is navigable."""
        touched = 0
        target = getattr(state, "target", None)
        host = None
        if target:
            host = self.add("host", target, source=source, save=False)
            touched += 1
        services = getattr(state, "services", None) or {}
        versions = getattr(state, "versions", None) or {}
        for port, svc in services.items():
            attrs = {"port": port}
            if port in versions:
                attrs["version"] = versions[port]
            s = self.add("service", f"{svc} ({port})", attrs=attrs, source=source, save=False)
            touched += 1
            if host is not None and s is not None:
                self.relate(host.id, "runs", s.id, save=False)
        for kind, attr in (("vulnerability", "vulnerabilities"),
                           ("credential", "credentials"), ("flag", "flags")):
            for v in getattr(state, attr, None) or []:
                self.add(kind, v, source=source, save=False)
                touched += 1
        self.save()
        return touched

    # -- persistence ---------------------------------------------------- #

    def to_dict(self) -> dict[str, Any]:
        return {"entities": [e.to_dict() for e in self._entities.values()],
                "relations": [r.to_dict() for r in self._relations.values()]}

    def save(self) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.to_dict(), indent=2) + "\n",
                                 encoding="utf-8")
        except OSError:
            pass  # a findings store that can't write must not crash the engagement

    def load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for d in data.get("entities") or []:
            e = Entity.from_dict(d)
            if e.type in ENTITY_TYPES and e.value:
                self._entities[e.id] = e
        for d in data.get("relations") or []:
            r = Relation(src=d.get("src", ""), rel=d.get("rel", ""), dst=d.get("dst", ""))
            if r.src and r.dst:
                self._relations[r.key()] = r
