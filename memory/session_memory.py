"""
session_memory.py - Mapache session memory

Tracks everything that happens within a single conversation session:
- All tool calls and their outputs
- Key facts extracted from tool results
- Task history and outcomes
- Variable store for passing data between turns

This is the short-term memory - it lives for one session then gets
summarized and written to the knowledge store for long-term recall.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4


@dataclass
class ToolCallRecord:
    tool_name: str
    args: dict[str, Any]
    output: str
    success: bool
    duration_ms: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    session_id: str = ""
    turn_id: str = ""


@dataclass
class TurnRecord:
    turn_id: str
    user_input: str
    agent_response: str
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    session_id: str = ""


class SessionMemory:
    """
    In-session memory - tracks the full history of one conversation.

    Features:
    - Complete tool call log with outputs
    - Per-turn records for summarization
    - Key-value variable store (agent can read/write named values)
    - Extraction of important facts for long-term storage
    """

    def __init__(self, session_id: Optional[str] = None) -> None:
        self.session_id = session_id or str(uuid4())
        self.created_at = datetime.now(timezone.utc)
        self._turns: list[TurnRecord] = []
        self._tool_calls: list[ToolCallRecord] = []
        self._variables: dict[str, Any] = {}
        self._facts: list[str] = []  # extracted important facts

    # ------------------------------------------------------------------ #
    # Turn tracking
    # ------------------------------------------------------------------ #

    def start_turn(self, user_input: str) -> str:
        turn_id = str(uuid4())[:8]
        turn = TurnRecord(
            turn_id=turn_id,
            user_input=user_input,
            agent_response="",
            session_id=self.session_id,
        )
        self._turns.append(turn)
        return turn_id

    def end_turn(self, turn_id: str, response: str) -> None:
        for turn in reversed(self._turns):
            if turn.turn_id == turn_id:
                turn.agent_response = response
                return

    def record_tool_call(
        self,
        turn_id: str,
        tool_name: str,
        args: dict,
        output: str,
        success: bool,
        duration_ms: float = 0.0,
    ) -> None:
        record = ToolCallRecord(
            tool_name=tool_name,
            args=args,
            output=output,
            success=success,
            duration_ms=duration_ms,
            session_id=self.session_id,
            turn_id=turn_id,
        )
        self._tool_calls.append(record)

        # Attach to turn
        for turn in reversed(self._turns):
            if turn.turn_id == turn_id:
                turn.tool_calls.append(record)
                break

    # ------------------------------------------------------------------ #
    # Variable store
    # ------------------------------------------------------------------ #

    def set(self, key: str, value: Any) -> None:
        """Store a named value accessible across turns in this session."""
        self._variables[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self._variables.get(key, default)

    def delete(self, key: str) -> None:
        self._variables.pop(key, None)

    def list_vars(self) -> dict[str, Any]:
        return dict(self._variables)

    # ------------------------------------------------------------------ #
    # Facts
    # ------------------------------------------------------------------ #

    def add_fact(self, fact: str) -> None:
        """Record an important fact discovered this session."""
        if fact not in self._facts:
            self._facts.append(fact)

    def get_facts(self) -> list[str]:
        return list(self._facts)

    # ------------------------------------------------------------------ #
    # Retrieval
    # ------------------------------------------------------------------ #

    def get_recent_tool_calls(self, limit: int = 10) -> list[ToolCallRecord]:
        return self._tool_calls[-limit:]

    def get_tool_calls_by_name(self, tool_name: str) -> list[ToolCallRecord]:
        return [t for t in self._tool_calls if t.tool_name == tool_name]

    def get_last_output(self, tool_name: str) -> Optional[str]:
        """Get the most recent output from a specific tool."""
        for record in reversed(self._tool_calls):
            if record.tool_name == tool_name and record.success:
                return record.output
        return None

    def get_turns(self, limit: int = 10) -> list[TurnRecord]:
        return self._turns[-limit:]

    # ------------------------------------------------------------------ #
    # Summary for long-term storage
    # ------------------------------------------------------------------ #

    def to_summary(self) -> dict[str, Any]:
        """
        Produce a compact summary of this session for writing to
        the knowledge store at session end.
        """
        tool_usage: dict[str, int] = {}
        for call in self._tool_calls:
            tool_usage[call.tool_name] = tool_usage.get(call.tool_name, 0) + 1

        return {
            "session_id": self.session_id,
            "created_at": self.created_at.isoformat(),
            "turn_count": len(self._turns),
            "tool_call_count": len(self._tool_calls),
            "tools_used": tool_usage,
            "facts": self._facts,
            "variables": self._variables,
            "turns": [
                {
                    "input": t.user_input[:200],
                    "response": t.agent_response[:200],
                    "tools": [c.tool_name for c in t.tool_calls],
                }
                for t in self._turns
            ],
        }

    @property
    def turn_count(self) -> int:
        return len(self._turns)

    @property
    def tool_call_count(self) -> int:
        return len(self._tool_calls)
