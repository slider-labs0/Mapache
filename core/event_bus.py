"""
event_bus.py - Mapache core event bus

Central pub/sub backbone. All inter-module communication goes through here.
No module should call another module directly - post an event instead.

Usage:
    bus = EventBus()

    @bus.on("tool.result")
    async def handle_result(event: Event):
        print(event.data)

    await bus.emit("tool.result", {"output": "..."})
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)

Handler = Callable[["Event"], Awaitable[None]]


@dataclass
class Event:
    """A single event flowing through the bus."""

    topic: str
    data: dict[str, Any]
    id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: Optional[str] = None  # module that emitted this event
    session_id: Optional[str] = None  # ties events to a conversation session

    def __repr__(self) -> str:
        return f"Event(topic={self.topic!r}, id={self.id[:8]}, source={self.source!r})"


class EventBus:
    """
    Async pub/sub event bus.

    Topics use dot-notation namespacing:
        agent.turn.start
        agent.turn.end
        tool.dispatch
        tool.result
        tool.error
        planner.plan_ready
        task.created
        task.completed
        task.failed
        memory.write
        memory.read
        model.request
        model.response
        session.start
        session.end
        error.unhandled
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = defaultdict(list)
        self._wildcard_handlers: list[Handler] = []
        self._history: list[Event] = []
        self._max_history: int = 500

    # ------------------------------------------------------------------ #
    # Registration
    # ------------------------------------------------------------------ #

    def on(self, topic: str) -> Callable[[Handler], Handler]:
        """Decorator to register a handler for a topic."""

        def decorator(fn: Handler) -> Handler:
            self.subscribe(topic, fn)
            return fn

        return decorator

    def subscribe(self, topic: str, handler: Handler) -> None:
        """Register a handler. Use '*' to receive all events."""
        if topic == "*":
            self._wildcard_handlers.append(handler)
            logger.debug("Wildcard handler registered: %s", handler.__name__)
        else:
            self._handlers[topic].append(handler)
            logger.debug("Handler registered for topic %r: %s", topic, handler.__name__)

    def unsubscribe(self, topic: str, handler: Handler) -> None:
        """Remove a previously registered handler."""
        if topic == "*":
            self._wildcard_handlers = [h for h in self._wildcard_handlers if h is not handler]
        elif topic in self._handlers:
            self._handlers[topic] = [h for h in self._handlers[topic] if h is not handler]

    # ------------------------------------------------------------------ #
    # Emission
    # ------------------------------------------------------------------ #

    async def emit(
        self,
        topic: str,
        data: dict[str, Any] | None = None,
        source: str | None = None,
        session_id: str | None = None,
    ) -> Event:
        """
        Emit an event and invoke all registered handlers concurrently.
        Handlers run as gathered tasks - one slow handler won't block others.
        """
        event = Event(
            topic=topic,
            data=data or {},
            source=source,
            session_id=session_id,
        )

        self._record(event)
        logger.debug("Emitting %r", event)

        handlers = self._handlers.get(topic, []) + self._wildcard_handlers
        if not handlers:
            return event

        results = await asyncio.gather(
            *[self._invoke(h, event) for h in handlers],
            return_exceptions=True,
        )

        for r in results:
            if isinstance(r, Exception):
                logger.error("Handler raised exception for topic %r: %s", topic, r, exc_info=r)
                await self._emit_error(topic, r, session_id)

        return event

    async def emit_and_wait(
        self,
        topic: str,
        data: dict[str, Any] | None = None,
        source: str | None = None,
        session_id: str | None = None,
        response_topic: str | None = None,
        timeout: float = 30.0,
    ) -> Event:
        """
        Emit an event and wait for a response event on `response_topic`.
        Useful for request/response patterns (e.g. emit model.request, wait for model.response).
        """
        response_topic = response_topic or f"{topic}.response"
        future: asyncio.Future[Event] = asyncio.get_event_loop().create_future()

        async def _capture(event: Event) -> None:
            if not future.done():
                future.set_result(event)

        self.subscribe(response_topic, _capture)
        try:
            await self.emit(topic, data, source=source, session_id=session_id)
            return await asyncio.wait_for(future, timeout=timeout)
        finally:
            self.unsubscribe(response_topic, _capture)

    # ------------------------------------------------------------------ #
    # History / introspection
    # ------------------------------------------------------------------ #

    def get_history(
        self,
        topic: str | None = None,
        session_id: str | None = None,
        limit: int = 50,
    ) -> list[Event]:
        """Return recent events, optionally filtered by topic or session."""
        events = self._history
        if topic:
            events = [e for e in events if e.topic == topic]
        if session_id:
            events = [e for e in events if e.session_id == session_id]
        return events[-limit:]

    def clear_history(self) -> None:
        self._history.clear()

    @property
    def registered_topics(self) -> list[str]:
        return list(self._handlers.keys())

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    async def _invoke(self, handler: Handler, event: Event) -> None:
        try:
            await handler(event)
        except Exception as exc:
            raise exc

    async def _emit_error(self, failed_topic: str, exc: Exception, session_id: str | None) -> None:
        """Emit an error event without recursing if error handlers also fail."""
        if failed_topic == "error.unhandled":
            return
        try:
            await self.emit(
                "error.unhandled",
                {"failed_topic": failed_topic, "error": str(exc), "type": type(exc).__name__},
                source="event_bus",
                session_id=session_id,
            )
        except Exception:
            pass

    def _record(self, event: Event) -> None:
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history :]


class ScopedBus:
    """A bus proxy that stamps ambient delegation tags onto every emitted event's
    data, then forwards to the underlying bus.

    A delegated sub-agent shares the lead's bus, so its tool calls, findings, and
    reasks already flow through the same stream - but nothing marks them as the
    sub-agent's. Wrapping the child's bus in a ScopedBus injects an `_agent` tag
    ({"operator", "depth", "suffix", …}) into each event so consumers (e.g. the CLI)
    can attribute and nest the sub-agent's full trace instead of seeing only the
    delegate start/end banners (Decepticon-parity #7: full sub-agent trace streaming).

    Subscription, history, and everything else delegate to the wrapped bus, so the
    event stream is unchanged apart from the added tag. A deeper scope's tag wins
    (set once, never overwritten), so a grandchild keeps its own identity even as
    the event bubbles up through its parent's ScopedBus."""

    def __init__(self, bus: Any, tags: dict[str, Any]) -> None:
        self._bus = bus
        self._tags = dict(tags or {})

    def __getattr__(self, name: str) -> Any:
        # Everything not overridden here (subscribe/unsubscribe/get_history/…) is the
        # real bus's - so consumers and nested scopes behave identically.
        return getattr(self._bus, name)

    def _stamp(self, data: dict[str, Any] | None) -> dict[str, Any]:
        merged = dict(data or {})
        merged.setdefault("_agent", self._tags)   # deepest scope wins
        return merged

    async def emit(self, topic: str, data: dict[str, Any] | None = None,
                   source: str | None = None, session_id: str | None = None) -> Event:
        return await self._bus.emit(topic, self._stamp(data),
                                    source=source, session_id=session_id)

    async def emit_and_wait(self, topic: str, data: dict[str, Any] | None = None,
                            source: str | None = None, session_id: str | None = None,
                            response_topic: str | None = None,
                            timeout: float = 30.0) -> Event:
        return await self._bus.emit_and_wait(
            topic, self._stamp(data), source=source, session_id=session_id,
            response_topic=response_topic, timeout=timeout)
