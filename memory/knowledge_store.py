"""
knowledge_store.py — Mapache knowledge store

Persistent key-value store for cross-session facts and agent state.
Simpler than the note store — designed for structured data the agent
needs to recall quickly:

    - Target profiles (IP, open ports, services found)
    - Discovered credentials
    - Session summaries
    - Agent preferences and learned behaviors
    - Arbitrary structured data

Storage: JSON files in ~/.config/mapache/knowledge/
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


KNOWLEDGE_DIR = Path.home() / ".config" / "mapache" / "knowledge"


class KnowledgeStore:
    """
    Persistent key-value store backed by a single JSON file.
    Supports namespacing via key prefixes (e.g. "targets:192.168.1.1").

    Fast in-memory access with file persistence on every write.
    """

    def __init__(self, store_path: Optional[Path] = None) -> None:
        self._path = store_path or (KNOWLEDGE_DIR / "knowledge.json")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict[str, Any] = {}
        self._load()

    # ------------------------------------------------------------------ #
    # Core operations
    # ------------------------------------------------------------------ #

    def set(self, key: str, value: Any, namespace: str = "") -> None:
        """Store a value. Use namespace for organization: set('ports', [...], 'target:1.2.3.4')"""
        full_key = f"{namespace}:{key}" if namespace else key
        self._data[full_key] = {
            "value": value,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "namespace": namespace,
        }
        self._save()

    def get(self, key: str, namespace: str = "", default: Any = None) -> Any:
        full_key = f"{namespace}:{key}" if namespace else key
        entry = self._data.get(full_key)
        if entry is None:
            return default
        return entry.get("value", default)

    def delete(self, key: str, namespace: str = "") -> bool:
        full_key = f"{namespace}:{key}" if namespace else key
        if full_key in self._data:
            del self._data[full_key]
            self._save()
            return True
        return False

    def exists(self, key: str, namespace: str = "") -> bool:
        full_key = f"{namespace}:{key}" if namespace else key
        return full_key in self._data

    def list_keys(self, namespace: str = "", prefix: str = "") -> list[str]:
        """List all keys, optionally filtered by namespace or prefix."""
        keys = []
        for full_key in self._data:
            if namespace and not full_key.startswith(f"{namespace}:"):
                continue
            if prefix and not full_key.startswith(prefix):
                continue
            keys.append(full_key)
        return sorted(keys)

    def list_namespaces(self) -> list[str]:
        namespaces: set[str] = set()
        for entry in self._data.values():
            ns = entry.get("namespace", "")
            if ns:
                namespaces.add(ns)
        return sorted(namespaces)

    def get_namespace(self, namespace: str) -> dict[str, Any]:
        """Get all key-value pairs under a namespace."""
        prefix = f"{namespace}:"
        result = {}
        for full_key, entry in self._data.items():
            if full_key.startswith(prefix):
                short_key = full_key[len(prefix):]
                result[short_key] = entry.get("value")
        return result

    def delete_namespace(self, namespace: str) -> int:
        """Delete all keys under a namespace. Returns count deleted."""
        prefix = f"{namespace}:"
        to_delete = [k for k in self._data if k.startswith(prefix)]
        for key in to_delete:
            del self._data[key]
        if to_delete:
            self._save()
        return len(to_delete)

    # ------------------------------------------------------------------ #
    # Convenience: target tracking
    # ------------------------------------------------------------------ #

    def store_target(self, ip_or_host: str, data: dict) -> None:
        """Store recon findings for a target."""
        existing = self.get("profile", namespace=f"target:{ip_or_host}") or {}
        existing.update(data)
        existing["last_seen"] = datetime.now(timezone.utc).isoformat()
        self.set("profile", existing, namespace=f"target:{ip_or_host}")

    def get_target(self, ip_or_host: str) -> Optional[dict]:
        return self.get("profile", namespace=f"target:{ip_or_host}")

    def list_targets(self) -> list[str]:
        targets = []
        for key in self.list_keys():
            if key.startswith("target:") and key.endswith(":profile"):
                host = key[len("target:"):-len(":profile")]
                targets.append(host)
        return targets

    # ------------------------------------------------------------------ #
    # Serialization
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict:
        return dict(self._data)

    def _load(self) -> None:
        if self._path.exists():
            try:
                self._data = json.loads(self._path.read_text(encoding="utf-8"))
            except Exception:
                self._data = {}

    def _save(self) -> None:
        self._path.write_text(
            json.dumps(self._data, indent=2, default=str),
            encoding="utf-8",
        )

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"KnowledgeStore({len(self)} entries, path={self._path})"
