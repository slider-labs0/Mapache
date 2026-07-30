"""
orchestrator.py — autonomous multi-agent routing (feature: supervisor, P0)

Mapache already has the specialist substrate: 20+ `Operator`s (core/operators.py),
`delegate`/`delegate_parallel` to deploy them, a shared knowledge graph + AttackState
blackboard, and phase-based color routing. What was missing — and what Decepticon
has — is an autonomous ROUTER/SUPERVISOR: something that reads the current state and
decides which specialist to deploy next, instead of relying on the lead model to call
`delegate` by hand.

This module adds exactly that, reusing the existing pieces:

- `RoutingState` — a compact snapshot of the engagement (AttackState + knowledge
  graph) that routing decisions are made from.
- `OperatorRouter` — deterministic tier-1 routing: it turns the dormant
  `Operator.triggers` field (plus phase and finding types) into a ranked list of
  `(operator, subtask)` candidates. No model calls — fast and cheap. (The tier-2
  LLM supervisor is P1.)
- `Supervisor` — the control loop: snapshot → route → dispatch (via the controller's
  own `_spawn_and_run`, so bus events / color routing / KG sharing all still work) →
  the operator's findings fold back into the shared state → re-route, until the
  objective is met, no route remains, or the round budget is spent. Anti-loop: it
  never re-dispatches the same operator against an unchanged state.

P0 is deliberately model-free so it can be unit-tested without a provider and
benchmarked (`benchmark_xbow.py`) against the single-agent baseline to measure the
multi-agent lift.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from core.operators import get_operator, suggest_operators

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# State snapshot
# --------------------------------------------------------------------------- #

@dataclass
class RoutingState:
    """A routing-relevant snapshot of the engagement, read from the controller's
    AttackState blackboard and (if present) the shared knowledge graph."""
    target: Optional[str] = None
    phase: str = "recon"
    open_ports: list[str] = field(default_factory=list)
    services: dict[str, str] = field(default_factory=dict)
    versions: dict[str, str] = field(default_factory=dict)
    vulnerabilities: list[str] = field(default_factory=list)
    credentials: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    kg_counts: dict[str, int] = field(default_factory=dict)

    @classmethod
    def snapshot(cls, controller: Any) -> "RoutingState":
        st = getattr(getattr(controller, "chain", None), "attack_state", None)
        kg = getattr(controller, "knowledge_graph", None)
        kg_counts: dict[str, int] = {}
        if kg is not None:
            try:
                for e in kg.entities():
                    kg_counts[e.type] = kg_counts.get(e.type, 0) + 1
            except Exception:
                pass
        g = lambda a, d: getattr(st, a, d) if st is not None else d
        return cls(
            target=g("target", None),
            phase=g("current_phase", "recon") or "recon",
            open_ports=list(g("open_ports", []) or []),
            services=dict(g("services", {}) or {}),
            versions=dict(g("versions", {}) or {}),
            vulnerabilities=list(g("vulnerabilities", []) or []),
            credentials=list(g("credentials", []) or []),
            flags=list(g("flags", []) or []),
            kg_counts=kg_counts,
        )

    @property
    def has_flag(self) -> bool:
        return bool(self.flags) or self.kg_counts.get("flag", 0) > 0

    @property
    def has_vulns(self) -> bool:
        return bool(self.vulnerabilities) or self.kg_counts.get("vulnerability", 0) > 0

    @property
    def has_creds(self) -> bool:
        return bool(self.credentials) or self.kg_counts.get("credential", 0) > 0

    def signature(self) -> str:
        """A compact fingerprint used to detect 'no progress' between rounds."""
        return "|".join([
            self.target or "-", self.phase,
            ",".join(sorted(self.open_ports)),
            f"v{len(self.vulnerabilities)}", f"c{len(self.credentials)}",
            f"f{len(self.flags)}",
            ",".join(f"{k}{v}" for k, v in sorted(self.kg_counts.items())),
        ])


# --------------------------------------------------------------------------- #
# Router (tier 1 — deterministic)
# --------------------------------------------------------------------------- #

@dataclass
class RouteCandidate:
    operator: str
    subtask: str
    score: float
    reason: str


# Phase → the default operator to run when nothing more specific fires.
_PHASE_DEFAULT = {
    "recon": "recon_operator",
    "enumeration": "web_operator",
    "exploitation": "exploit_operator",
    "post": "post_operator",
    "analysis": "analyst",
    "report": "analyst",
}

# Per-operator subtask templates. `{tgt}`/`{ports}` are filled from the state; the
# fallback uses the operator's own description.
_SUBTASK = {
    "recon_operator": "Enumerate {tgt}: scan for open ports and identify the running "
                      "services and versions. Record everything you find.",
    "web_operator": "Enumerate and test the web service(s) on {tgt} ({ports}) for "
                    "vulnerabilities (auth flaws, injection, IDOR, misconfig). Confirm "
                    "and record each finding.",
    "exploit_operator": "Exploit a confirmed vulnerability on {tgt} to gain access or "
                        "retrieve the objective. Capture exact evidence.",
    "post_operator": "Using the access/credentials already obtained, escalate privileges "
                     "and collect loot and flags on {tgt}.",
    "analyst": "Analyze the current findings on {tgt} and construct the next concrete "
               "exploitation step or vulnerability chain.",
}


class OperatorRouter:
    """Deterministic tier-1 router: current state → ranked operator candidates.

    Wires up the dormant `Operator.triggers` (service/port tokens) and layers phase
    + finding-type signals on top. Operators whose engagement constraints can't be
    satisfied here (remote hardware, RoE-gated, blue-team deconfliction) are skipped
    unless explicitly enabled."""

    def __init__(self, *, allow_remote: bool = False, allow_gated: bool = False,
                 allow_deconfliction: bool = False) -> None:
        self.allow_remote = allow_remote
        self.allow_gated = allow_gated
        self.allow_deconfliction = allow_deconfliction

    def _eligible(self, op) -> bool:
        if op is None:
            return False
        if op.requires_remote and not self.allow_remote:
            return False
        if op.roe_gated and not self.allow_gated:
            return False
        if op.requires_deconfliction and not self.allow_deconfliction:
            return False
        return True

    @staticmethod
    def _subtask_for(op, state: RoutingState) -> str:
        tgt = state.target or "the in-scope target"
        ports = ", ".join(state.open_ports) if state.open_ports else "unknown ports"
        tmpl = _SUBTASK.get(op.name)
        if tmpl:
            return tmpl.format(tgt=tgt, ports=ports)
        return (f"As the {op.title}, advance the engagement against {tgt} using your "
                f"specialty: {op.description}")

    def select(self, state: RoutingState) -> list[RouteCandidate]:
        best: dict[str, RouteCandidate] = {}

        def consider(name: str, score: float, reason: str) -> None:
            op = get_operator(name)
            if not self._eligible(op):
                return
            cur = best.get(name)
            if cur is None or score > cur.score:
                best[name] = RouteCandidate(name, self._subtask_for(op, state),
                                            score, reason)

        # Scores encode kill-chain ADVANCEMENT: once a stage's preconditions are met,
        # the next stage must outrank re-doing the previous one, or routing stalls
        # (e.g. re-enumerating a web service forever instead of exploiting a vuln it
        # already found). Order of precedence: post > exploit > enumerate > recon.

        # 1) Nothing discovered yet → recon first.
        if not state.open_ports and not state.has_vulns and not state.has_creds:
            consider("recon_operator", 10.0, "no ports known — run reconnaissance")

        # 2) Findings drive the chain forward (these dominate once their
        #    preconditions hold, so the supervisor advances rather than loops).
        if state.has_creds:
            consider("post_operator", 9.0,
                     "credentials present — post-exploitation")
        if state.has_vulns:
            consider("exploit_operator", 8.0,
                     "vulnerabilities present — attempt exploitation")

        # 3) Service/port triggers — strong for INITIAL enumeration, but ranked
        #    below exploitation so a discovered vuln takes priority; stays available
        #    as a fallback (anti-loop can drop to it).
        for name in suggest_operators(state.open_ports, state.services):
            consider(name, 6.0, "service trigger match")

        # 4) Phase-aligned default (weak fallback when nothing else fires).
        default = _PHASE_DEFAULT.get(state.phase)
        if default:
            consider(default, 3.0, f"phase default ({state.phase})")

        return sorted(best.values(), key=lambda c: -c.score)


# --------------------------------------------------------------------------- #
# Supervisor (the control loop)
# --------------------------------------------------------------------------- #

@dataclass
class SupervisorRound:
    index: int
    operator: str
    subtask: str
    reason: str
    result: str


@dataclass
class SupervisorResult:
    rounds: list[SupervisorRound]
    stop_reason: str
    solved: bool

    @property
    def operators_run(self) -> list[str]:
        return [r.operator for r in self.rounds]


class Supervisor:
    """Autonomous routing loop over the existing operator specialists.

    Each round: snapshot state → route → dispatch the top new candidate through the
    controller's own `_spawn_and_run` (so delegation events, color routing, OPSEC,
    and knowledge-graph sharing all apply) → the operator's findings fold back into
    the shared AttackState/KG → re-route. Stops when the objective is met (a flag is
    known), no route remains, the state stops changing, or the round budget is spent.
    """

    def __init__(self, controller: Any, router: Optional[OperatorRouter] = None, *,
                 max_rounds: int = 12, max_per_operator: int = 4,
                 session_id: str = "supervisor") -> None:
        self.controller = controller
        self.router = router or OperatorRouter()
        self.max_rounds = max_rounds
        # Cap how many times any single operator may be dispatched in a run, so a
        # persistently-firing trigger can't monopolise the budget (global backstop
        # on top of the per-state anti-loop).
        self.max_per_operator = max_per_operator
        self.session_id = session_id

    async def _emit(self, kind: str, data: dict) -> None:
        bus = getattr(self.controller, "bus", None)
        if bus is None:
            return
        try:
            await bus.emit(kind, data, source="supervisor", session_id=self.session_id)
        except Exception:
            pass

    async def run(self, objective: str, session_id: Optional[str] = None) -> SupervisorResult:
        sid = session_id or self.session_id
        rounds: list[SupervisorRound] = []
        tried: set[tuple[str, str]] = set()   # (operator, state-signature) — anti-loop
        op_counts: dict[str, int] = {}        # per-operator dispatch budget
        stop = "round budget exhausted"

        for i in range(self.max_rounds):
            state = RoutingState.snapshot(self.controller)
            if state.has_flag:
                stop = "objective met (flag found)"
                break

            candidates = self.router.select(state)
            if not candidates:
                stop = "no route candidates for current state"
                break

            sig = state.signature()
            # Pick the top candidate that is new for this state AND under its budget.
            pick = next((c for c in candidates
                         if (c.operator, sig) not in tried
                         and op_counts.get(c.operator, 0) < self.max_per_operator),
                        None)
            if pick is None:
                # Either the state is unchanged and every candidate was already tried,
                # or the actionable operators have hit their per-operator budget.
                stop = "no new route (state unchanged / operator budgets spent)"
                break
            tried.add((pick.operator, sig))
            op_counts[pick.operator] = op_counts.get(pick.operator, 0) + 1

            await self._emit("supervisor.route", {
                "round": i, "operator": pick.operator, "reason": pick.reason,
                "subtask": pick.subtask,
            })
            logger.info("Supervisor round %d → %s (%s)", i, pick.operator, pick.reason)

            full_task = (f"Engagement objective: {objective}\n\n"
                         f"Your focused task: {pick.subtask}")
            try:
                result = await self.controller._spawn_and_run(
                    full_task, pick.operator, sid, f"sup{i}", target=state.target)
            except Exception as exc:  # a failed operator shouldn't kill the loop
                result = f"[operator error] {exc}"
                logger.warning("Supervisor operator %s failed: %s", pick.operator, exc)

            rounds.append(SupervisorRound(
                index=i, operator=pick.operator, subtask=pick.subtask,
                reason=pick.reason, result=str(result)[:4000]))

        final = RoutingState.snapshot(self.controller)
        await self._emit("supervisor.done", {"rounds": len(rounds),
                                             "solved": final.has_flag, "stop": stop})
        return SupervisorResult(rounds=rounds, stop_reason=stop, solved=final.has_flag)
