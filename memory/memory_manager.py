"""
memory_manager.py - Mapache memory manager

Unified interface that wires together all memory subsystems:
    - SessionMemory   - current conversation state
    - NoteStore       - persistent human-readable notes
    - KnowledgeStore  - persistent structured key-value data
    - VectorStore     - semantic search over past findings

Also exposes memory as agent tools so Mapache can manage
its own memory autonomously.

This is what makes Mapache remember things across sessions -
it's the difference between a stateless tool and an agent
that learns and builds context over time.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from memory.knowledge_store import KnowledgeStore
from memory.note_store import NoteStore
from memory.session_memory import SessionMemory
from memory.vector_store import VectorStore
from plugins.sdk.base_tool import BaseTool, Permission, ToolResult


class MemoryManager:
    """
    Central memory coordinator.

    Usage:
        memory = MemoryManager()
        session = memory.new_session()

        # During a turn
        memory.notes.create("Scan results", "Port 22 open on 192.168.1.1", tags=["recon"])
        memory.knowledge.store_target("192.168.1.1", {"ports": [22, 80]})
        await memory.vectors.add("Port 22 SSH open on 192.168.1.1", {"target": "192.168.1.1"})

        # Next session - recall
        results = await memory.vectors.search("SSH services")
        notes = memory.notes.search("recon")
    """

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        self.notes = NoteStore(
            notes_dir=base_dir / "notes" if base_dir else None
        )
        self.knowledge = KnowledgeStore(
            store_path=base_dir / "knowledge.json" if base_dir else None
        )
        self.vectors = VectorStore(
            store_path=base_dir / "vectors.json" if base_dir else None
        )
        self._current_session: Optional[SessionMemory] = None

    def new_session(self, session_id: Optional[str] = None) -> SessionMemory:
        """Start a new session. Called at the beginning of each conversation."""
        self._current_session = SessionMemory(session_id=session_id)
        return self._current_session

    @property
    def session(self) -> Optional[SessionMemory]:
        return self._current_session

    async def end_session(self) -> None:
        """
        End the current session - summarize and persist to long-term memory.
        Called when the user exits or the session ends.
        """
        if not self._current_session:
            return

        summary = self._current_session.to_summary()

        # Store session summary in knowledge store
        self.knowledge.set(
            key=f"session:{summary['session_id']}",
            value=summary,
            namespace="sessions",
        )

        # Store discovered facts in vector store
        for fact in summary.get("facts", []):
            await self.vectors.add(
                fact,
                metadata={"source": "session", "session_id": summary["session_id"]},
            )

        self._current_session = None

    def get_tools(self) -> list[BaseTool]:
        """Return all memory tools for registration with the tool registry."""
        return [
            MemoryRecallTool(self),
            MemorySaveTool(self),
            MemoryNoteCreateTool(self),
            MemoryNoteSearchTool(self),
            MemoryNoteListTool(self),
            MemoryTargetStoreTool(self),
            MemoryTargetGetTool(self),
        ]

    def stats(self) -> dict[str, Any]:
        return {
            "notes": len(self.notes),
            "knowledge_entries": len(self.knowledge),
            "vector_entries": len(self.vectors),
            "session_active": self._current_session is not None,
        }


# ------------------------------------------------------------------ #
# Memory tools the agent can call
# ------------------------------------------------------------------ #

class MemoryRecallTool(BaseTool):
    name = "memory_recall"
    description = (
        "Search long-term memory for relevant past findings, notes, or information. "
        "Use to recall what was found in previous sessions, past recon results, "
        "stored credentials, or anything remembered from prior work. "
        "Semantic search - describe what you're looking for in plain language."
    )
    parameters = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "What to look for in memory (natural language)",
            },
            "limit": {
                "type": "integer",
                "description": "Max results to return (default: 5)",
                "default": 5,
            },
        },
        "required": ["query"],
    }
    permissions = set()
    tags = ["memory", "recall"]

    def __init__(self, manager: MemoryManager) -> None:
        self._manager = manager

    async def execute(self, query: str, limit: int = 5, **kwargs: Any) -> ToolResult:
        results = await self._manager.vectors.search(query, limit=limit)
        notes = self._manager.notes.search(query, limit=limit)

        lines = [f"Memory search: '{query}'\n"]

        if results:
            lines.append("From vector memory:")
            for r in results:
                score_pct = int(r.score * 100)
                source = r.metadata.get("source", "unknown")
                lines.append(f"  [{score_pct}% match | {source}] {r.text[:200]}")
            lines.append("")

        if notes:
            lines.append("From notes:")
            for note in notes[:5]:
                tags_str = f" [{', '.join(note.tags)}]" if note.tags else ""
                lines.append(f"  [{note.id}] {note.title}{tags_str}")
                lines.append(f"    {note.content[:150]}")
            lines.append("")

        if not results and not notes:
            return ToolResult.ok(f"Nothing found in memory for: {query}")

        return ToolResult.ok("\n".join(lines))


class MemorySaveTool(BaseTool):
    name = "memory_save"
    description = (
        "Save an important fact or finding to long-term memory. "
        "Use to remember discoveries, credentials, target info, or anything "
        "that should be recalled in future sessions. "
        "Saved items are searchable with memory_recall."
    )
    parameters = {
        "type": "object",
        "properties": {
            "content": {
                "type": "string",
                "description": "The fact or finding to remember",
            },
            "tags": {
                "type": "string",
                "description": "Comma-separated tags (e.g. 'recon,credentials,target')",
                "default": "",
            },
            "target": {
                "type": "string",
                "description": "Target host/IP this relates to (optional)",
                "default": "",
            },
        },
        "required": ["content"],
    }
    permissions = set()
    tags = ["memory", "save"]

    def __init__(self, manager: MemoryManager) -> None:
        self._manager = manager

    async def execute(
        self,
        content: str,
        tags: str = "",
        target: str = "",
        **kwargs: Any,
    ) -> ToolResult:
        tag_list = [t.strip() for t in tags.split(",") if t.strip()]
        metadata: dict[str, Any] = {"source": "agent", "tags": tag_list}
        if target:
            metadata["target"] = target
            tag_list.append(f"target:{target}")

        entry_id = await self._manager.vectors.add(content, metadata=metadata)

        # Also add to session facts if session is active
        if self._manager.session:
            self._manager.session.add_fact(content)

        return ToolResult.ok(
            f"Saved to memory (id:{entry_id}): {content[:100]}",
            metadata={"entry_id": entry_id},
        )


class MemoryNoteCreateTool(BaseTool):
    name = "memory_note_create"
    description = (
        "Create a persistent note with a title and content. "
        "Notes survive across sessions and are searchable. "
        "Use for detailed findings, checklists, reports, or any structured information."
    )
    parameters = {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "Note title",
            },
            "content": {
                "type": "string",
                "description": "Note content (can be multi-line)",
            },
            "tags": {
                "type": "string",
                "description": "Comma-separated tags",
                "default": "",
            },
        },
        "required": ["title", "content"],
    }
    permissions = set()
    tags = ["memory", "notes"]

    def __init__(self, manager: MemoryManager) -> None:
        self._manager = manager

    async def execute(
        self,
        title: str,
        content: str,
        tags: str = "",
        **kwargs: Any,
    ) -> ToolResult:
        tag_list = [t.strip() for t in tags.split(",") if t.strip()]
        note = self._manager.notes.create(title=title, content=content, tags=tag_list)

        # Also index in vector store for semantic search
        await self._manager.vectors.add(
            f"{title}\n{content}",
            metadata={"source": "note", "note_id": note.id, "title": title},
            entry_id=f"note:{note.id}",
        )

        return ToolResult.ok(
            f"Note created (id:{note.id}): {title}",
            metadata={"note_id": note.id},
        )


class MemoryNoteSearchTool(BaseTool):
    name = "memory_note_search"
    description = "Search existing notes by keyword or tag. Returns matching notes with their content."
    parameters = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Search term or tag to look for",
            },
        },
        "required": ["query"],
    }
    permissions = set()
    tags = ["memory", "notes"]

    def __init__(self, manager: MemoryManager) -> None:
        self._manager = manager

    async def execute(self, query: str, **kwargs: Any) -> ToolResult:
        # Try tag search first
        notes_by_tag = self._manager.notes.list_all(tag=query)
        notes_by_text = self._manager.notes.search(query)

        # Combine and deduplicate
        seen = set()
        all_notes = []
        for note in notes_by_tag + notes_by_text:
            if note.id not in seen:
                seen.add(note.id)
                all_notes.append(note)

        if not all_notes:
            return ToolResult.ok(f"No notes found for: {query}")

        lines = [f"Notes matching '{query}':\n"]
        for note in all_notes[:10]:
            tags_str = f" [{', '.join(note.tags)}]" if note.tags else ""
            lines.append(f"[{note.id}] {note.title}{tags_str}")
            lines.append(f"  {note.content[:200]}")
            lines.append(f"  Updated: {note.updated_at[:10]}")
            lines.append("")

        return ToolResult.ok("\n".join(lines))


class MemoryNoteListTool(BaseTool):
    name = "memory_note_list"
    description = "List all saved notes. Returns titles, IDs, and tags."
    parameters = {
        "type": "object",
        "properties": {
            "tag": {
                "type": "string",
                "description": "Filter by tag (optional)",
                "default": "",
            },
        },
        "required": [],
    }
    permissions = set()
    tags = ["memory", "notes"]

    def __init__(self, manager: MemoryManager) -> None:
        self._manager = manager

    async def execute(self, tag: str = "", **kwargs: Any) -> ToolResult:
        notes = self._manager.notes.list_all(tag=tag if tag else None)

        if not notes:
            msg = f"No notes" + (f" tagged '{tag}'" if tag else "") + "."
            return ToolResult.ok(msg)

        lines = [f"{len(notes)} note(s):\n"]
        for note in notes:
            tags_str = f" [{', '.join(note.tags)}]" if note.tags else ""
            lines.append(f"  [{note.id}] {note.title}{tags_str} - {note.updated_at[:10]}")

        all_tags = self._manager.notes.list_tags()
        if all_tags:
            lines.append(f"\nAll tags: {', '.join(all_tags)}")

        return ToolResult.ok("\n".join(lines))


class MemoryTargetStoreTool(BaseTool):
    name = "memory_target_store"
    description = (
        "Store recon findings for a target host or IP. "
        "Persists across sessions - use after scanning to remember what was found. "
        "Merges with existing data for the same target."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IP or hostname",
            },
            "data": {
                "type": "string",
                "description": "JSON string of findings (e.g. '{\"ports\": [22, 80], \"os\": \"Linux\"}')",
            },
        },
        "required": ["target", "data"],
    }
    permissions = set()
    tags = ["memory", "recon"]

    def __init__(self, manager: MemoryManager) -> None:
        self._manager = manager

    async def execute(self, target: str, data: str, **kwargs: Any) -> ToolResult:
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError:
            parsed = {"raw": data}

        self._manager.knowledge.store_target(target, parsed)

        # Also save to vector store for semantic recall
        summary = f"Target {target}: " + ", ".join(f"{k}={v}" for k, v in parsed.items())
        await self._manager.vectors.add(
            summary,
            metadata={"source": "recon", "target": target},
        )

        return ToolResult.ok(
            f"Target {target} updated in memory.\n"
            f"Stored: {json.dumps(parsed, separators=(',', ':'))[:200]}"
        )


class MemoryTargetGetTool(BaseTool):
    name = "memory_target_get"
    description = (
        "Retrieve stored recon findings for a target. "
        "Returns everything previously found and stored about this host."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IP or hostname (or 'list' to see all targets)",
            },
        },
        "required": ["target"],
    }
    permissions = set()
    tags = ["memory", "recon"]

    def __init__(self, manager: MemoryManager) -> None:
        self._manager = manager

    async def execute(self, target: str, **kwargs: Any) -> ToolResult:
        if target.lower() == "list":
            targets = self._manager.knowledge.list_targets()
            if not targets:
                return ToolResult.ok("No targets stored in memory.")
            return ToolResult.ok(
                f"Stored targets ({len(targets)}):\n" +
                "\n".join(f"  - {t}" for t in targets)
            )

        data = self._manager.knowledge.get_target(target)
        if not data:
            return ToolResult.ok(
                f"No data found for target: {target}\n"
                f"Use memory_target_store to save findings."
            )

        lines = [f"Target: {target}\n"]
        for key, value in data.items():
            lines.append(f"  {key}: {value}")

        return ToolResult.ok("\n".join(lines))
