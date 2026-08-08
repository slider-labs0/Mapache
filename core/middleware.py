"""
middleware.py - composable slots around the agent loop (Decepticon-parity #1)

Mapache's controller was monolithic: cross-cutting concerns (budget, human
approval, defensive follow-up, tracing) had to be hand-wired into `_agent_loop`.
This adds a small middleware layer so those concerns become pluggable components
that hook the loop at well-defined slots - the composable architecture Decepticon
gets from LangGraph, without adopting the framework.

A middleware implements any subset of the hooks; the controller runs them at:
  - turn_start        once, before the first model call
  - iteration_start   top of every loop step (budget checks, HITL gates, injects)
  - turn_end          once, after the turn produces its AgentResponse

Hooks receive a mutable `LoopContext`. To influence the loop a middleware sets:
  - ctx.stop = True (+ ctx.stop_reason)  → the turn ends now with that reason
  - ctx.inject.append("...")             → a user message is added before the next
                                            model call (steering/nudges/approvals)
The default chain is empty, so this is inert until middlewares are registered.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class LoopContext:
    """Mutable per-turn state passed to every middleware hook."""
    controller: Any
    session_id: str
    user_input: str
    iteration: int = 0
    # Control signals a middleware may set:
    stop: bool = False              # end the turn now
    stop_reason: str = ""           # AgentResponse.error when stopped
    stop_message: str = ""          # AgentResponse.content when stopped
    inject: list[str] = field(default_factory=list)  # user msgs to add next step
    # Free-form scratch space middlewares can share within a turn.
    scratch: dict[str, Any] = field(default_factory=dict)

    @property
    def attack_state(self) -> Any:
        return getattr(getattr(self.controller, "chain", None), "attack_state", None)


class AgentMiddleware:
    """Base class - override the hooks you need. All are async and optional."""
    name: str = "middleware"

    async def on_turn_start(self, ctx: LoopContext) -> None:
        ...

    async def on_iteration_start(self, ctx: LoopContext) -> None:
        ...

    async def on_turn_end(self, ctx: LoopContext, response: Any) -> None:
        ...


class MiddlewareChain:
    """Runs registered middlewares at each slot, in order. A hook raising is logged
    and swallowed so one bad middleware can't break the engagement loop."""

    def __init__(self, middlewares: Optional[list[AgentMiddleware]] = None) -> None:
        self.middlewares: list[AgentMiddleware] = list(middlewares or [])

    def add(self, mw: AgentMiddleware) -> None:
        self.middlewares.append(mw)

    def __bool__(self) -> bool:
        return bool(self.middlewares)

    async def _run(self, hook: str, ctx: LoopContext, *args: Any) -> None:
        for mw in self.middlewares:
            try:
                await getattr(mw, hook)(ctx, *args)
            except Exception as exc:  # a middleware must never crash the loop
                logger.warning("Middleware %s.%s failed: %s",
                               getattr(mw, "name", mw), hook, exc)
            if ctx.stop:              # a stop signal short-circuits the rest
                break

    async def turn_start(self, ctx: LoopContext) -> None:
        await self._run("on_turn_start", ctx)

    async def iteration_start(self, ctx: LoopContext) -> None:
        await self._run("on_iteration_start", ctx)

    async def turn_end(self, ctx: LoopContext, response: Any) -> None:
        # turn_end is best-effort cleanup; don't let a stop short-circuit it.
        for mw in self.middlewares:
            try:
                await mw.on_turn_end(ctx, response)
            except Exception as exc:
                logger.warning("Middleware %s.on_turn_end failed: %s",
                               getattr(mw, "name", mw), exc)
