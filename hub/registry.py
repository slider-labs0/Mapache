"""
registry.py — skill registry sources (feature I)

A registry is just an index of skill manifests. `LocalRegistry` reads an
`index.json` (a list of manifest dicts) from a directory — enough to browse and
install from a checked-out repo or a synced folder, and trivially testable.

A `UrlRegistry` / GitHub-index source drops in behind the same `list_skills` /
`search` / `get` surface later (the network fetch is the only addition); kept out
of the default so the hub has no network dependency and tests stay offline.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .manifest import SkillManifest

INDEX_NAME = "index.json"


class LocalRegistry:
    """Skill index backed by a local `index.json` (list of manifest dicts)."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def _load(self) -> list[SkillManifest]:
        index = self.root / INDEX_NAME
        try:
            data = json.loads(index.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        entries = data if isinstance(data, list) else data.get("skills", [])
        out: list[SkillManifest] = []
        for d in entries or []:
            if isinstance(d, dict) and d.get("name"):
                out.append(SkillManifest.from_dict(d))
        return out

    def list_skills(self) -> list[SkillManifest]:
        return self._load()

    def get(self, name: str) -> Optional[SkillManifest]:
        for m in self._load():
            if m.name == name:
                return m
        return None

    def search(self, query: str) -> list[SkillManifest]:
        q = (query or "").lower().strip()
        if not q:
            return self._load()
        hits = []
        for m in self._load():
            hay = f"{m.name} {m.description} {' '.join(m.deps)} {m.skill_type}".lower()
            if q in hay:
                hits.append(m)
        return hits
