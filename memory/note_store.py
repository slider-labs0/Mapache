"""
note_store.py - Mapache note store

Persistent structured notes that survive across sessions.
The agent can read, write, search, and tag notes autonomously.

Think of it as the agent's notebook - it stores:
- Recon findings (open ports, discovered services)
- Target information
- Credentials and secrets found
- Research notes
- Task checklists
- Anything the agent wants to remember

Storage: JSON files in ~/.config/mapache/notes/
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4


NOTES_DIR = Path.home() / ".config" / "mapache" / "notes"


@dataclass
class Note:
    id: str
    title: str
    content: str
    tags: list[str] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "tags": self.tags,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Note":
        return cls(
            id=data.get("id", str(uuid4())[:8]),
            title=data.get("title", ""),
            content=data.get("content", ""),
            tags=data.get("tags", []),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            metadata=data.get("metadata", {}),
        )


class NoteStore:
    """
    Persistent note storage backed by JSON files.

    Each note is a separate JSON file in ~/.config/mapache/notes/
    An index file tracks all notes for fast search.
    """

    def __init__(self, notes_dir: Optional[Path] = None) -> None:
        self.notes_dir = notes_dir or NOTES_DIR
        self.notes_dir.mkdir(parents=True, exist_ok=True)
        self._index: dict[str, dict] = {}
        self._load_index()

    # ------------------------------------------------------------------ #
    # Write
    # ------------------------------------------------------------------ #

    def create(
        self,
        title: str,
        content: str,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict] = None,
    ) -> Note:
        note = Note(
            id=str(uuid4())[:8],
            title=title,
            content=content,
            tags=tags or [],
            metadata=metadata or {},
        )
        self._save_note(note)
        return note

    def update(self, note_id: str, content: str = "", title: str = "", tags: Optional[list[str]] = None) -> Optional[Note]:
        note = self.get(note_id)
        if not note:
            return None
        if content:
            note.content = content
        if title:
            note.title = title
        if tags is not None:
            note.tags = tags
        note.updated_at = datetime.now(timezone.utc).isoformat()
        self._save_note(note)
        return note

    def append(self, note_id: str, content: str) -> Optional[Note]:
        """Append content to an existing note."""
        note = self.get(note_id)
        if not note:
            return None
        note.content += f"\n{content}"
        note.updated_at = datetime.now(timezone.utc).isoformat()
        self._save_note(note)
        return note

    def delete(self, note_id: str) -> bool:
        note_path = self.notes_dir / f"{note_id}.json"
        if note_path.exists():
            note_path.unlink()
            self._index.pop(note_id, None)
            self._save_index()
            return True
        return False

    # ------------------------------------------------------------------ #
    # Read
    # ------------------------------------------------------------------ #

    def get(self, note_id: str) -> Optional[Note]:
        note_path = self.notes_dir / f"{note_id}.json"
        if not note_path.exists():
            return None
        try:
            data = json.loads(note_path.read_text(encoding="utf-8"))
            return Note.from_dict(data)
        except Exception:
            return None

    def list_all(self, tag: Optional[str] = None) -> list[Note]:
        notes = []
        for note_id in self._index:
            note = self.get(note_id)
            if note:
                if tag is None or tag in note.tags:
                    notes.append(note)
        return sorted(notes, key=lambda n: n.updated_at, reverse=True)

    def search(self, query: str, limit: int = 20) -> list[Note]:
        """Full-text search across all notes."""
        query_lower = query.lower()
        results = []
        for note in self.list_all():
            score = 0
            if query_lower in note.title.lower():
                score += 3
            if query_lower in note.content.lower():
                score += 1
            if any(query_lower in tag.lower() for tag in note.tags):
                score += 2
            if score > 0:
                results.append((score, note))
        results.sort(key=lambda x: x[0], reverse=True)
        return [note for _, note in results[:limit]]

    def list_tags(self) -> list[str]:
        tags: set[str] = set()
        for entry in self._index.values():
            tags.update(entry.get("tags", []))
        return sorted(tags)

    # ------------------------------------------------------------------ #
    # Index management
    # ------------------------------------------------------------------ #

    def _save_note(self, note: Note) -> None:
        note_path = self.notes_dir / f"{note.id}.json"
        note_path.write_text(
            json.dumps(note.to_dict(), indent=2),
            encoding="utf-8",
        )
        self._index[note.id] = {
            "title": note.title,
            "tags": note.tags,
            "updated_at": note.updated_at,
        }
        self._save_index()

    def _load_index(self) -> None:
        index_path = self.notes_dir / "index.json"
        if index_path.exists():
            try:
                self._index = json.loads(index_path.read_text(encoding="utf-8"))
            except Exception:
                self._index = {}
        else:
            # Rebuild from files
            self._index = {}
            for note_file in self.notes_dir.glob("*.json"):
                if note_file.name == "index.json":
                    continue
                try:
                    data = json.loads(note_file.read_text(encoding="utf-8"))
                    note_id = data.get("id", note_file.stem)
                    self._index[note_id] = {
                        "title": data.get("title", ""),
                        "tags": data.get("tags", []),
                        "updated_at": data.get("updated_at", ""),
                    }
                except Exception:
                    pass
            self._save_index()

    def _save_index(self) -> None:
        index_path = self.notes_dir / "index.json"
        index_path.write_text(
            json.dumps(self._index, indent=2),
            encoding="utf-8",
        )

    def __len__(self) -> int:
        return len(self._index)
