"""
multi_attempt.py — self-consistency / multi-attempt solving (capability #5)

A single ReAct pass fixates: once it commits to a vulnerability class or a wrong
hypothesis, it burns its whole budget there. Frontier results (e.g. MAPTA) get a large
share of their lift from running SEVERAL independent attempts and keeping the one that
succeeds. This wraps a controller in exactly that: run the objective up to `max_attempts`
times, stopping the moment success holds.

Each retry starts a FRESH conversation (`context.clear_history`) so the reasoning isn't
anchored to the failed line — but the shared attack-state blackboard and knowledge graph
PERSIST, so it keeps confirmed findings (ports, services, creds) and doesn't re-discover
them. The retry prompt tells the model to take a genuinely different approach and hands it
the accumulated dead ends (from the progress ledger) so it doesn't re-walk them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional


@dataclass
class AttemptResult:
    result: Any            # the last AgentResponse
    attempts: int          # how many attempts were run
    solved: bool           # did the success predicate hold


def _has_flag(controller: Any) -> bool:
    st = getattr(getattr(controller, "chain", None), "attack_state", None)
    return bool(getattr(st, "flags", None))


async def _emit(controller: Any, topic: str, data: dict) -> None:
    bus = getattr(controller, "bus", None)
    if bus is None:
        return
    try:
        await bus.emit(topic, data, source="multi_attempt",
                       session_id=data.get("session_id"))
    except Exception:
        pass


def _retry_prompt(controller: Any, objective: str, attempt: int) -> str:
    parts = [
        objective,
        f"\n\nATTEMPT {attempt}. The previous attempt(s) did NOT reach the objective. "
        "Start FRESH and take a GENUINELY DIFFERENT approach — a different vulnerability "
        "class, endpoint, parameter, credential, or technique than before. Your "
        "confirmed findings so far (ports, services, credentials) still stand; build on "
        "them, but do not repeat the line of attack that already failed.",
    ]
    ledger = getattr(controller, "_progress_ledger", None)
    if ledger is not None:
        try:
            block = ledger.render()
        except Exception:
            block = ""
        if block:
            parts.append("\n" + block)
    return "\n".join(parts)


async def run_with_attempts(
    controller: Any,
    objective: str,
    *,
    session_id: str = "engagement",
    max_attempts: int = 3,
    per_attempt_iters: Optional[int] = None,
    success: Optional[Callable[[Any], bool]] = None,
) -> AttemptResult:
    """Run `objective` up to `max_attempts` times, stopping as soon as `success` holds.

    success: predicate over the controller (default: a flag is in the attack state).
    per_attempt_iters: if set, cap each attempt's ReAct loop to this many iterations
        (adaptive budget) instead of the controller's default.
    """
    check = success or _has_flag
    max_attempts = max(1, int(max_attempts or 1))
    if per_attempt_iters:
        controller.MAX_ITERATIONS = int(per_attempt_iters)

    result = None
    for attempt in range(1, max_attempts + 1):
        sid = f"{session_id}#a{attempt}" if max_attempts > 1 else session_id
        if attempt > 1:
            # Fresh reasoning context; findings survive in attack-state + KG.
            try:
                controller.context.clear_history()
            except Exception:
                pass
            prompt = _retry_prompt(controller, objective, attempt)
        else:
            prompt = objective

        await _emit(controller, "attempt.start",
                    {"attempt": attempt, "of": max_attempts, "session_id": sid})
        result = await controller.run(prompt, session_id=sid)

        if check(controller):
            await _emit(controller, "attempt.solved",
                        {"attempt": attempt, "session_id": sid})
            return AttemptResult(result=result, attempts=attempt, solved=True)

    await _emit(controller, "attempt.exhausted",
                {"attempts": max_attempts, "session_id": session_id})
    return AttemptResult(result=result, attempts=max_attempts, solved=False)
