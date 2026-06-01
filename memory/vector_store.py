"""
vector_store.py — Mapache vector store

Semantic search over notes, findings, and session history.
Converts text to embeddings and finds similar content by meaning.

Two backends:
    1. Ollama embeddings (local, no API key, default)
       - Uses nomic-embed-text or any embedding model in Ollama
    2. Simple TF-IDF fallback (no model needed, less accurate)
       - Used automatically if Ollama embeddings aren't available

This enables queries like:
    "find anything I learned about port 443"
    "what did I find on that web server last week"
    "show me all credential findings"
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

VECTOR_DIR = Path.home() / ".config" / "mapache" / "vectors"
DEFAULT_EMBED_MODEL = "nomic-embed-text"
OLLAMA_URL = "http://localhost:11434"


@dataclass
class VectorEntry:
    id: str
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)
    vector: list[float] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "text": self.text,
            "metadata": self.metadata,
            "vector": self.vector,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VectorEntry":
        return cls(
            id=data["id"],
            text=data["text"],
            metadata=data.get("metadata", {}),
            vector=data.get("vector", []),
        )


@dataclass
class SearchResult:
    entry: VectorEntry
    score: float

    @property
    def text(self) -> str:
        return self.entry.text

    @property
    def metadata(self) -> dict:
        return self.entry.metadata


class VectorStore:
    """
    Semantic search store with Ollama embedding backend.

    Falls back to TF-IDF if Ollama embeddings aren't available.

    Usage:
        store = VectorStore()
        await store.add("Nmap found port 22 open on 192.168.1.1", {"source": "nmap", "target": "192.168.1.1"})
        results = await store.search("SSH services found")
        for r in results:
            print(r.score, r.text)
    """

    def __init__(
        self,
        store_path: Optional[Path] = None,
        embed_model: str = DEFAULT_EMBED_MODEL,
        ollama_url: str = OLLAMA_URL,
    ) -> None:
        self._path = store_path or (VECTOR_DIR / "vectors.json")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self.embed_model = embed_model
        self.ollama_url = ollama_url
        self._entries: list[VectorEntry] = []
        self._use_ollama: Optional[bool] = None
        self._load()

    # ------------------------------------------------------------------ #
    # Add entries
    # ------------------------------------------------------------------ #

    async def add(
        self,
        text: str,
        metadata: Optional[dict] = None,
        entry_id: Optional[str] = None,
    ) -> str:
        from uuid import uuid4
        eid = entry_id or str(uuid4())[:8]

        vector = await self._embed(text)
        entry = VectorEntry(
            id=eid,
            text=text,
            metadata=metadata or {},
            vector=vector,
        )
        # Replace if ID exists
        self._entries = [e for e in self._entries if e.id != eid]
        self._entries.append(entry)
        self._save()
        return eid

    async def add_many(self, items: list[tuple[str, dict]]) -> list[str]:
        """Add multiple entries efficiently."""
        ids = []
        for text, metadata in items:
            eid = await self.add(text, metadata)
            ids.append(eid)
        return ids

    def remove(self, entry_id: str) -> bool:
        before = len(self._entries)
        self._entries = [e for e in self._entries if e.id != entry_id]
        if len(self._entries) < before:
            self._save()
            return True
        return False

    # ------------------------------------------------------------------ #
    # Search
    # ------------------------------------------------------------------ #

    async def search(
        self,
        query: str,
        limit: int = 10,
        min_score: float = 0.0,
        filter_metadata: Optional[dict] = None,
    ) -> list[SearchResult]:
        """
        Find the most semantically similar entries to the query.
        Returns results sorted by similarity score (highest first).
        """
        if not self._entries:
            return []

        query_vector = await self._embed(query)

        results = []
        for entry in self._entries:
            # Metadata filter
            if filter_metadata:
                if not all(entry.metadata.get(k) == v for k, v in filter_metadata.items()):
                    continue

            if entry.vector:
                score = self._cosine_similarity(query_vector, entry.vector)
            else:
                score = self._tfidf_score(query, entry.text)

            if score >= min_score:
                results.append(SearchResult(entry=entry, score=score))

        results.sort(key=lambda r: r.score, reverse=True)
        return results[:limit]

    # ------------------------------------------------------------------ #
    # Embedding backends
    # ------------------------------------------------------------------ #

    async def _embed(self, text: str) -> list[float]:
        """Get embedding vector for text."""
        if self._use_ollama is None:
            self._use_ollama = await self._check_ollama()

        if self._use_ollama:
            try:
                return await self._ollama_embed(text)
            except Exception:
                self._use_ollama = False

        # Fallback to TF-IDF style sparse vector
        return self._sparse_vector(text)

    async def _check_ollama(self) -> bool:
        if not HAS_HTTPX:
            return False
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"{self.ollama_url}/api/tags")
                if resp.status_code == 200:
                    models = [m["name"] for m in resp.json().get("models", [])]
                    return any(
                        self.embed_model.split(":")[0] in m
                        for m in models
                    )
        except Exception:
            pass
        return False

    async def _ollama_embed(self, text: str) -> list[float]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.ollama_url}/api/embeddings",
                json={"model": self.embed_model, "prompt": text},
            )
            response.raise_for_status()
            return response.json()["embedding"]

    def _sparse_vector(self, text: str, dims: int = 512) -> list[float]:
        """
        Simple hash-based sparse vector for fallback.
        Less accurate than real embeddings but works without any model.
        """
        words = re.findall(r"\w+", text.lower())
        vector = [0.0] * dims
        for word in words:
            h = hash(word) % dims
            vector[h] += 1.0

        # L2 normalize
        norm = math.sqrt(sum(v * v for v in vector))
        if norm > 0:
            vector = [v / norm for v in vector]
        return vector

    def _tfidf_score(self, query: str, text: str) -> float:
        """Simple keyword overlap score for fallback search."""
        query_words = set(re.findall(r"\w+", query.lower()))
        text_words = set(re.findall(r"\w+", text.lower()))
        if not query_words:
            return 0.0
        overlap = len(query_words & text_words)
        return overlap / len(query_words)

    @staticmethod
    def _cosine_similarity(a: list[float], b: list[float]) -> float:
        if len(a) != len(b) or not a:
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #

    def _save(self) -> None:
        data = [e.to_dict() for e in self._entries]
        self._path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load(self) -> None:
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                self._entries = [VectorEntry.from_dict(d) for d in data]
            except Exception:
                self._entries = []

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        backend = "ollama" if self._use_ollama else "tfidf"
        return f"VectorStore({len(self)} entries, backend={backend})"
