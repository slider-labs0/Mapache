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

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from core.operators import all_operators, get_operator, suggest_operators
from core.learning_store import fingerprint_of

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
    endpoints: list[str] = field(default_factory=list)
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
            endpoints=list(g("endpoints", []) or []),
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
            f"f{len(self.flags)}", f"e{len(self.endpoints)}",
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
                 allow_deconfliction: bool = False, explore: bool = True,
                 learning: Any = None) -> None:
        self.allow_remote = allow_remote
        self.allow_gated = allow_gated
        self.allow_deconfliction = allow_deconfliction
        # Emit the low-priority exploration ladder (P3): keeps the supervisor trying
        # different specialists when findings-driven routing stalls, instead of
        # stopping after one operator. Disable for purely findings-driven routing.
        self.explore = explore
        # Cross-engagement learning (optional): a LearningStore that biases routing
        # toward operators which historically won against similar targets. The bonus is
        # small (< a kill-chain stage) so it reorders/ties-breaks without overriding
        # advancement.
        self.learning = learning

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

        # 5) Exploration ladder (P3) — low-priority speculative fallbacks so the
        #    supervisor keeps trying DIFFERENT specialists when the findings-driven
        #    routes are exhausted (a stalled operator surfaced nothing), rather than
        #    stopping after one. Each is still capped by the per-state anti-loop and
        #    the per-operator budget, so this can't spin.
        if self.explore:
            consider("web_operator", 2.6, "explore: enumerate the web surface")
            consider("exploit_operator", 2.4, "explore: speculative exploitation")
            consider("analyst", 2.2, "explore: analyze the state for a next step")
            consider("recon_operator", 2.0, "explore: re-scan the target")

        # Cross-engagement learning: nudge operators that won on similar targets before.
        if self.learning is not None:
            try:
                fp = fingerprint_of(state.services, state.open_ports)
                bias = self.learning.operator_bias(fp)
            except Exception:
                bias = {}
            for name, bonus in bias.items():
                cand = best.get(name)
                if cand is not None and bonus > 0:
                    cand.score += bonus
                    cand.reason += f" (+{bonus} learned)"

        return sorted(best.values(), key=lambda c: -c.score)


# Distinct technique angles for parallel fan-out (Fix #3). When several operators are
# deployed at once on a stall, each gets a DIFFERENT angle from the phase-aware menu so
# the batch explores separate surfaces instead of all repeating the same recon.
_FANOUT_ANGLE_MENUS: dict[str, list[str]] = {
    "recon": [
        "map the full endpoint/param surface: dir & param fuzzing, robots.txt/sitemap, "
        "and read linked JS files for hidden routes/keys.",
        "probe authentication & access control: login, session handling, IDOR/BOLA, and "
        "forced browsing to restricted paths.",
        "test injection classes: SQLi, OS-command, template/SSTI, and XXE on every input.",
        "focus on client-side & app config: reflected/stored XSS, CSRF, and secrets/URLs "
        "exposed in JavaScript.",
    ],
    "post": [
        "escalate privileges from the current access.",
        "harvest credentials/tokens/secrets reachable from this foothold.",
        "enumerate internal/lateral surface reachable from here.",
        "locate and read the objective (flag/sensitive data).",
    ],
}
# enumeration shares the recon menu; exploitation shares the post menu.
_FANOUT_ANGLE_MENUS["enumeration"] = _FANOUT_ANGLE_MENUS["recon"]
_FANOUT_ANGLE_MENUS["exploitation"] = _FANOUT_ANGLE_MENUS["post"]


def _fanout_angles(phase: str, n: int) -> list[str]:
    """n distinct technique angles for a fan-out batch (round-robin over the menu)."""
    menu = _FANOUT_ANGLE_MENUS.get(phase or "recon") or _FANOUT_ANGLE_MENUS["recon"]
    return [menu[j % len(menu)] for j in range(n)]


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


# A tier-2 planner: (objective, state, roster) -> (operator, subtask) or None.
Planner = Callable[[str, "RoutingState", list], Awaitable[Optional[tuple[str, str]]]]


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
                 planner: Optional["Planner"] = None, opplan: Any = None,
                 fanout: bool = False, fanout_width: int = 3, fanout_after: int = 1,
                 route_enum: bool = True, session_id: str = "supervisor") -> None:
        self.controller = controller
        self.router = router or OperatorRouter()
        self.max_rounds = max_rounds
        # Active route enumeration (Fix #2): once, before routing, probe common web
        # routes and fold the real ones into the SHARED attack_state so every sub-agent
        # sees real paths instead of guessing. Best-effort; no-op without a dispatcher.
        self.route_enum = route_enum
        # Cap how many times any single operator may be dispatched in a run, so a
        # persistently-firing trigger can't monopolise the budget (global backstop
        # on top of the per-state anti-loop).
        self.max_per_operator = max_per_operator
        # Parallel operator fan-out (#5): when a single operator has stalled (its
        # round left the state signature unchanged) for `fanout_after` rounds, deploy
        # the top `fanout_width` DISTINCT usable specialists CONCURRENTLY to break the
        # plateau, then re-route on the merged findings — instead of trying one more
        # single operator. Off by default (single-dispatch behaviour preserved).
        self.fanout = fanout
        self.fanout_width = max(2, int(fanout_width or 2))
        self.fanout_after = max(1, int(fanout_after or 1))
        # Soft anti-loop: how many times one operator may be re-dispatched at the SAME
        # state signature before it's benched. A hard 1 (the old permanent ban) exhausts
        # the tiny web-operator roster in a single solo+fanout cycle and quits at ~4
        # rounds; allowing a couple of steered retries lets the per-operator budget
        # (max_per_operator) actually be spent exploring. Still globally capped.
        self.per_sig_cap = max(1, min(int(max_per_operator), 2))
        # Tier-2 routing brain (P1): an async callable that, when the deterministic
        # router runs dry, picks the next (operator, subtask) from the state + roster.
        # See `make_model_planner`. Optional — omitted keeps routing purely rule-based.
        self.planner = planner
        # Optional OPPLAN (P1): when set, a pending objective that names an owning
        # operator is routed first (plan-driven), and its status is folded back.
        self.opplan = opplan
        self.session_id = session_id

    def _usable(self, name: Optional[str], sig: str, tried: set, op_counts: dict) -> bool:
        """An operator is dispatchable if it's eligible, new for this exact state,
        and still under its per-operator budget."""
        if not name:
            return False
        return (self.router._eligible(get_operator(name))
                and tried.get((name, sig), 0) < self.per_sig_cap
                and op_counts.get(name, 0) < self.max_per_operator)

    async def _maybe_enumerate_routes(self, session_id: str) -> None:
        """Fix #2: one active route-enumeration pass before routing. Populates the
        SHARED attack_state.endpoints so every sub-agent sees real paths. Best-effort:
        silently no-ops without a dispatcher or a derivable web base URL."""
        if not self.route_enum:
            return
        disp = getattr(self.controller, "tool_dispatcher", None)
        st = getattr(getattr(self.controller, "chain", None), "attack_state", None)
        if disp is None or st is None:
            return
        if len(getattr(st, "endpoints", []) or []) >= 4:
            return
        try:
            from core.agent_middlewares import (enumerate_routes, base_url_from_state,
                                                make_dispatcher_prober)
            base = base_url_from_state(st)
            if not base:
                return
            found = await enumerate_routes(make_dispatcher_prober(disp, session_id), base, st)
            if found:
                await self._emit("supervisor.route_enum",
                                 {"base": base, "found": [p for p, _ in found]})
                logger.info("Supervisor route-enum found %d paths on %s", len(found), base)
        except Exception as exc:  # never let enumeration break the engagement
            logger.warning("Supervisor route-enum failed: %s", exc)

    async def _emit(self, kind: str, data: dict) -> None:
        bus = getattr(self.controller, "bus", None)
        if bus is None:
            return
        try:
            await bus.emit(kind, data, source="supervisor", session_id=self.session_id)
        except Exception:
            pass

    async def _spawn_safe(self, task: str, operator: str, sid: str, suffix: str,
                          target: Optional[str]) -> str:
        """Dispatch one operator, converting a failure into a result string so a
        crashing operator never takes down the (possibly parallel) round."""
        try:
            return str(await self.controller._spawn_and_run(
                task, operator, sid, suffix, target=target))
        except Exception as exc:
            logger.warning("Supervisor operator %s failed: %s", operator, exc)
            return f"[operator error] {exc}"

    def _fanout_picks(self, state: "RoutingState", sig: str, tried: set,
                      op_counts: dict) -> list["RouteCandidate"]:
        """Top-N DISTINCT usable operators to deploy concurrently on a stall."""
        picked: list[RouteCandidate] = []
        seen: set[str] = set()
        for c in self.router.select(state):
            if c.operator in seen:
                continue
            if not self._usable(c.operator, sig, tried, op_counts):
                continue
            seen.add(c.operator)
            picked.append(c)
            if len(picked) >= self.fanout_width:
                break
        return picked

    async def run(self, objective: str, session_id: Optional[str] = None) -> SupervisorResult:
        sid = session_id or self.session_id
        await self._maybe_enumerate_routes(sid)
        rounds: list[SupervisorRound] = []
        tried: dict[tuple[str, str], int] = {}  # (operator, state-signature) → #dispatches
        op_counts: dict[str, int] = {}        # per-operator dispatch budget
        stall_streak = 0                      # consecutive rounds with no state change
        stop = "round budget exhausted"

        for i in range(self.max_rounds):
            state = RoutingState.snapshot(self.controller)
            if state.has_flag:
                stop = "objective met (flag found)"
                break
            sig = state.signature()

            # Parallel fan-out (#5): a single operator has stalled — deploy several
            # distinct specialists at once to break the plateau, then re-route on the
            # merged findings. Takes precedence over another single dispatch.
            if self.fanout and stall_streak >= self.fanout_after:
                picks = self._fanout_picks(state, sig, tried, op_counts)
                if len(picks) >= 2:
                    for c in picks:
                        tried[(c.operator, sig)] = tried.get((c.operator, sig), 0) + 1
                        op_counts[c.operator] = op_counts.get(c.operator, 0) + 1
                    names = [c.operator for c in picks]
                    # Fix #3: give each fanned-out operator a DISTINCT technique angle so
                    # the parallel batch explores different surfaces instead of repeating
                    # the same recon. Angles are drawn from a phase-aware menu, round-robin.
                    angles = _fanout_angles(state.phase, len(picks))
                    await self._emit("supervisor.fanout", {
                        "round": i, "operators": names,
                        "reason": f"stall x{stall_streak} — parallel fan-out"})
                    logger.info("Supervisor round %d → FAN-OUT %s", i, names)
                    results = await asyncio.gather(*(
                        self._spawn_safe(
                            f"Engagement objective: {objective}\n\n"
                            f"Your focused task: {c.subtask}"
                            + (f"\n\nDISTINCT ANGLE for this parallel branch — {angles[j]}"
                               if angles[j] else ""),
                            c.operator, sid, f"fan{i}_{j}", state.target)
                        for j, c in enumerate(picks)))
                    for c, res in zip(picks, results):
                        rounds.append(SupervisorRound(
                            index=i, operator=c.operator, subtask=c.subtask,
                            reason=f"fan-out: {c.reason}", result=str(res)[:4000]))
                    new_sig = RoutingState.snapshot(self.controller).signature()
                    stall_streak = 0 if new_sig != sig else stall_streak + 1
                    continue
                # Too few candidates to fan out → fall through to single dispatch.

            # Choose the next operator, in precedence order:
            #   1) plan-driven — a pending OPPLAN objective that names an owner,
            #   2) deterministic router (triggers/phase/findings),
            #   3) LLM supervisor fallback when the rules run dry.
            operator = subtask = reason = None
            plan_obj = None

            if self.opplan is not None:
                try:
                    obj = self.opplan.next_pending()
                except Exception:
                    obj = None
                owner = getattr(obj, "operator", None) if obj is not None else None
                if owner and self._usable(owner, sig, tried, op_counts):
                    operator, subtask, plan_obj = owner, getattr(obj, "text", ""), obj
                    reason = f"OPPLAN objective #{getattr(obj, 'id', '?')}"
                    try:
                        self.opplan.update(obj.id, status="in_progress")
                    except Exception:
                        pass

            if operator is None:
                for c in self.router.select(state):
                    if self._usable(c.operator, sig, tried, op_counts):
                        operator, subtask, reason = c.operator, c.subtask, c.reason
                        break

            if operator is None and self.planner is not None:
                try:
                    choice = await self.planner(objective, state, all_operators())
                except Exception as exc:
                    logger.warning("Supervisor planner failed: %s", exc)
                    choice = None
                if choice and self._usable(choice[0], sig, tried, op_counts):
                    operator = choice[0]
                    subtask = choice[1] or f"Advance the objective as the {operator}."
                    reason = "LLM supervisor"

            if operator is None:
                stop = "no route (plan + deterministic + LLM exhausted)"
                break

            # Fix #2: a re-dispatch of the same operator at the same signature means its
            # last turn didn't advance — steer it to a materially different technique
            # rather than repeating what already stalled.
            retry_n = tried.get((operator, sig), 0)
            tried[(operator, sig)] = retry_n + 1
            op_counts[operator] = op_counts.get(operator, 0) + 1
            steer = ""
            if retry_n >= 1:
                steer = ("\n\nNOTE: a previous attempt here made NO new progress. Do NOT "
                         "repeat the same requests/commands — switch technique or attack a "
                         "different part of the surface (new endpoints, params, auth, or "
                         "an entirely different vulnerability class).")
            await self._emit("supervisor.route", {
                "round": i, "operator": operator, "reason": reason, "subtask": subtask,
            })
            logger.info("Supervisor round %d → %s (%s)", i, operator, reason)

            full_task = (f"Engagement objective: {objective}\n\n"
                         f"Your focused task: {subtask}{steer}")
            result = await self._spawn_safe(full_task, operator, sid, f"sup{i}",
                                            state.target)

            rounds.append(SupervisorRound(index=i, operator=operator, subtask=subtask,
                                          reason=reason, result=str(result)[:4000]))

            # Track whether this operator advanced the state, for both the stall/fan-out
            # trigger and the OPPLAN status fold below.
            advanced = RoutingState.snapshot(self.controller).signature() != sig
            stall_streak = 0 if advanced else stall_streak + 1

            # Fold OPPLAN status: a plan objective is 'passed' once its operator moves
            # the state forward, or 'blocked' once it's exhausted its budget with none.
            if plan_obj is not None and self.opplan is not None:
                try:
                    if advanced:
                        self.opplan.update(plan_obj.id, status="passed",
                                           note=f"{operator} advanced the state")
                    elif op_counts[operator] >= self.max_per_operator:
                        self.opplan.update(plan_obj.id, status="blocked",
                                           note=f"{operator} made no progress within budget")
                except Exception:
                    pass

        final = RoutingState.snapshot(self.controller)
        await self._emit("supervisor.done", {"rounds": len(rounds),
                                             "solved": final.has_flag, "stop": stop})
        return SupervisorResult(rounds=rounds, stop_reason=stop, solved=final.has_flag)


def make_model_planner(controller: Any) -> Planner:
    """A tier-2 planner backed by the controller's model: given the current state and
    the operator roster, it returns the next (operator, subtask) as JSON, or None if
    nothing useful remains. Best-effort — any model or parse error yields None, so the
    supervisor falls back cleanly to 'no route' rather than crashing."""
    async def planner(objective: str, state: "RoutingState", ops: list):
        roster = "\n".join(f"- {o.name} ({o.phase}): {o.description}" for o in ops)
        summary = (f"target={state.target} phase={state.phase} "
                   f"ports={state.open_ports} services={list(state.services.values())} "
                   f"vulns={len(state.vulnerabilities)} creds={len(state.credentials)} "
                   f"flags={len(state.flags)}")
        prompt = (
            "You are the SUPERVISOR routing specialist sub-agents in an AUTHORIZED "
            "penetration test. Choose the single best operator to deploy next.\n\n"
            f"OBJECTIVE: {objective}\nCURRENT STATE: {summary}\n\n"
            f"OPERATORS:\n{roster}\n\n"
            'Reply ONLY as JSON: {"operator": "<name or null>", '
            '"subtask": "<one focused sentence>"}. Use null if no operator can help.')
        try:
            resp = await controller.model.chat(
                messages=[{"role": "user", "content": prompt}], json_mode=True)
            content = getattr(resp, "content", resp)
            data = json.loads(content) if isinstance(content, str) else (content or {})
            name = (data or {}).get("operator")
            if not name or str(name).strip().lower() in ("null", "none", ""):
                return None
            return (str(name).strip(), str((data or {}).get("subtask") or "").strip())
        except Exception:
            return None
    return planner
