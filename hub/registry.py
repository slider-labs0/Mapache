"""
registry.py — skill registry sources (feature I)

A registry is just an index of skill manifests. `LocalRegistry` reads an
`index.json` (a list of manifest dicts) from a directory — enough to browse and
install from a checked-out repo or a synced folder, and trivially testable.

`UrlRegistry` adds an HTTP/GitHub-index source behind the same `list_skills` /
`search` / `get` surface — the only addition is the fetch, which is injectable so
tests stay offline and the default install needs no network.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Optional

from .manifest import SkillManifest

INDEX_NAME = "index.json"


def _parse_index(text: str) -> list[SkillManifest]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    entries = data if isinstance(data, list) else data.get("skills", [])
    return [SkillManifest.from_dict(d) for d in (entries or [])
            if isinstance(d, dict) and d.get("name")]


def _search(skills: list[SkillManifest], query: str) -> list[SkillManifest]:
    q = (query or "").lower().strip()
    if not q:
        return skills
    hits = []
    for m in skills:
        hay = f"{m.name} {m.description} {' '.join(m.deps)} {m.skill_type}".lower()
        if q in hay:
            hits.append(m)
    return hits


class LocalRegistry:
    """Skill index backed by a local `index.json` (list of manifest dicts)."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def _load(self) -> list[SkillManifest]:
        try:
            return _parse_index((self.root / INDEX_NAME).read_text(encoding="utf-8"))
        except OSError:
            return []

    def list_skills(self) -> list[SkillManifest]:
        return self._load()

    def get(self, name: str) -> Optional[SkillManifest]:
        return next((m for m in self._load() if m.name == name), None)

    def search(self, query: str) -> list[SkillManifest]:
        return _search(self._load(), query)


def _http_get(url: str) -> str:
    """Default fetcher: stdlib urllib (no third-party dependency)."""
    from urllib.request import urlopen
    with urlopen(url, timeout=20) as resp:  # noqa: S310 - operator-supplied registry URL
        return resp.read().decode("utf-8", errors="replace")


class UrlRegistry:
    """Skill index fetched from an HTTP(S) URL (e.g. a raw GitHub `index.json`).

    The fetch is injectable so it's offline-testable; the network call is the only
    difference from `LocalRegistry`. A failed fetch yields an empty index rather
    than raising, so a down registry degrades gracefully.
    """

    def __init__(self, url: str, *, fetch: Optional[Callable[[str], str]] = None) -> None:
        self.url = url
        self._fetch = fetch or _http_get

    def _load(self) -> list[SkillManifest]:
        try:
            return _parse_index(self._fetch(self.url))
        except Exception:
            return []

    def list_skills(self) -> list[SkillManifest]:
        return self._load()

    def get(self, name: str) -> Optional[SkillManifest]:
        return next((m for m in self._load() if m.name == name), None)

    def search(self, query: str) -> list[SkillManifest]:
        return _search(self._load(), query)


def make_registry(spec: str, *, fetch: Optional[Callable[[str], str]] = None):
    """LocalRegistry for a path, UrlRegistry for an http(s):// spec."""
    if spec.startswith(("http://", "https://")):
        return UrlRegistry(spec, fetch=fetch)
    return LocalRegistry(spec)
