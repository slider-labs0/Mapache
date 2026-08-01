"""
agent_middlewares.py — concrete loop middlewares (built on core/middleware.py)

Standard, opt-in policies that plug into the agent loop's slots. Kept separate
from the framework so the framework stays dependency-free.

  - BudgetMiddleware — engagement-level token/time budget with a graceful stop
    (Decepticon-parity: budget enforcement).
  - HITLMiddleware — human-in-the-loop checkpoint gate: pause the loop at
    milestones and let a human approve / deny / steer (Decepticon-parity: real
    HITL slot).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from core.middleware import AgentMiddleware, LoopContext

logger = logging.getLogger(__name__)


class BudgetMiddleware(AgentMiddleware):
    """Stop the engagement once it exceeds a token or wall-clock budget.

    Both caps are ENGAGEMENT-level (cumulative across turns): the timer starts on
    the first turn and `max_tokens` is checked against the controller's cumulative
    `session_tokens`. Enforcement is graceful — it ends the current turn cleanly via
    ctx.stop rather than raising, so partial results and the transcript survive."""

    name = "budget"

    def __init__(self, max_tokens: Optional[int] = None,
                 max_seconds: Optional[float] = None) -> None:
        self.max_tokens = max_tokens
        self.max_seconds = max_seconds
        self._start: Optional[float] = None  # engagement start (first turn)

    async def on_turn_start(self, ctx: LoopContext) -> None:
        if self._start is None:
            self._start = time.monotonic()

    def _exceeded(self, ctx: LoopContext) -> Optional[str]:
        if self.max_tokens is not None:
            used = int(getattr(ctx.controller, "session_tokens", 0) or 0)
            if used >= self.max_tokens:
                return f"tokens {used} ≥ {self.max_tokens}"
        if self.max_seconds is not None and self._start is not None:
            elapsed = time.monotonic() - self._start
            if elapsed >= self.max_seconds:
                return f"time {elapsed:.0f}s ≥ {self.max_seconds:.0f}s"
        return None

    async def on_iteration_start(self, ctx: LoopContext) -> None:
        reason = self._exceeded(ctx)
        if not reason:
            return
        ctx.stop = True
        ctx.stop_reason = "budget_exceeded"
        ctx.stop_message = (f"Engagement budget exceeded ({reason}) — stopping to "
                            "stay within the operator's limit.")
        logger.warning("Budget middleware: %s", reason)
        bus = getattr(ctx.controller, "bus", None)
        if bus is not None:
            try:
                await bus.emit("budget.exceeded",
                               {"reason": reason, "session_id": ctx.session_id},
                               source="budget", session_id=ctx.session_id)
            except Exception:
                pass


@dataclass
class HITLDecision:
    """A human's answer at a HITL checkpoint."""
    action: str = "approve"   # "approve" | "deny" | "steer"
    message: str = ""

    @classmethod
    def approve(cls) -> "HITLDecision":
        return cls("approve")

    @classmethod
    def deny(cls, message: str = "") -> "HITLDecision":
        return cls("deny", message)

    @classmethod
    def steer(cls, message: str) -> "HITLDecision":
        return cls("steer", message)


HITLCallback = Callable[[LoopContext, str], Awaitable[Optional[HITLDecision]]]


class HITLMiddleware(AgentMiddleware):
    """Human-in-the-loop checkpoint gate (loop-level, composable).

    At defined checkpoints the loop PAUSES and asks a human callback to
    approve / deny / steer before the agent takes its next step. This is distinct
    from the per-tool `confirm_dangerous` prompt: that gates individual dangerous
    CALLS; this gates the LOOP at milestones (Decepticon's HITL node).

    A checkpoint fires when either:
      - `every` > 0 and that many iterations have passed since the last checkpoint, or
      - `on_phase_change` and the engagement phase changed since the last step.
    The first iteration never gates — there is nothing to review yet.

    The callback is async `(ctx, reason) -> HITLDecision | None`:
      - approve / None → continue
      - deny           → end the turn now (ctx.stop, error='hitl_denied')
      - steer          → inject the operator's message before the next model call
    A callback that raises is treated as approve (fail-open) so a broken prompt
    can't wedge the engagement.
    """

    name = "hitl"

    def __init__(self, callback: HITLCallback, every: int = 0,
                 on_phase_change: bool = True) -> None:
        self.callback = callback
        self.every = int(every or 0)
        self.on_phase_change = on_phase_change
        self._last_checkpoint = 0
        self._last_phase: Optional[str] = None
        self._primed = False

    @staticmethod
    def _phase(ctx: LoopContext) -> Optional[str]:
        st = ctx.attack_state
        return getattr(st, "current_phase", None) if st is not None else None

    async def on_iteration_start(self, ctx: LoopContext) -> None:
        phase = self._phase(ctx)
        # Prime state on the first step seen, without gating.
        if not self._primed:
            self._primed = True
            self._last_phase = phase
            self._last_checkpoint = ctx.iteration
            return

        reasons = []
        if self.every and (ctx.iteration - self._last_checkpoint) >= self.every:
            reasons.append(f"{self.every} steps since last review")
        if self.on_phase_change and phase != self._last_phase:
            reasons.append(f"phase → {phase}")
        self._last_phase = phase
        if not reasons:
            return
        self._last_checkpoint = ctx.iteration
        reason = "; ".join(reasons)

        bus = getattr(ctx.controller, "bus", None)
        if bus is not None:
            try:
                await bus.emit("hitl.checkpoint",
                               {"reason": reason, "iteration": ctx.iteration,
                                "session_id": ctx.session_id},
                               source="hitl", session_id=ctx.session_id)
            except Exception:
                pass

        try:
            decision = await self.callback(ctx, reason)
        except Exception as exc:  # a broken prompt must not wedge the loop
            logger.warning("HITL callback failed (%s) — auto-approving", exc)
            return

        if decision is None or decision.action == "approve":
            return
        if decision.action == "deny":
            ctx.stop = True
            ctx.stop_reason = "hitl_denied"
            ctx.stop_message = decision.message or "Engagement halted by the operator."
            logger.info("HITL: operator denied at iteration %d", ctx.iteration)
        elif decision.action == "steer" and decision.message:
            ctx.inject.append(decision.message)
            logger.info("HITL: operator steered at iteration %d", ctx.iteration)
