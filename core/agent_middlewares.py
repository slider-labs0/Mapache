"""
agent_middlewares.py — concrete loop middlewares (built on core/middleware.py)

Standard, opt-in policies that plug into the agent loop's slots. Kept separate
from the framework so the framework stays dependency-free.

  - BudgetMiddleware — engagement-level token/time budget with a graceful stop
    (Decepticon-parity: budget enforcement).
  - HITLMiddleware — human-in-the-loop checkpoint gate: pause the loop at
    milestones and let a human approve / deny / steer (Decepticon-parity: real
    HITL slot).
  - VaccineMiddleware — defensive follow-up: when the engagement confirms a new
    vulnerability, generate a detection signature + remediation ("vaccine") and
    record it (Decepticon-parity: blue-cell / offensive-vaccine loop).
  - ReflectionMiddleware — every N steps, inject a structured self-critique and name
    the current tactical stage, so the agent reasons about what it has learned and
    picks the highest-value next action instead of drifting (frontier-loop parity).
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from core.middleware import AgentMiddleware, LoopContext

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Active route enumeration (gap #2: discover real routes, don't invent them)
# --------------------------------------------------------------------------- #

# A small, high-signal list of routes to probe on a web target — the kind an agent
# would otherwise guess (and get wrong). Hits are folded into attack_state.endpoints
# so they show up in the state block as REAL paths for every (sub-)agent to use.
COMMON_ROUTES = [
    "/robots.txt", "/sitemap.xml", "/login", "/logout", "/register", "/signup",
    "/admin", "/administrator", "/dashboard", "/account", "/profile", "/user",
    "/users", "/api", "/api/users", "/orders", "/order", "/cart", "/checkout",
    "/search", "/upload", "/uploads", "/files", "/download", "/config", "/settings",
    "/backup", "/.git/config", "/.env", "/flag", "/flag.txt", "/index.php",
    "/home", "/static/", "/assets/", "/server-status", "/phpinfo.php", "/console",
]


async def enumerate_routes(prober: "Callable[[str], Awaitable[Optional[int]]]",
                           base_url: str, state: Any, *, cap: int = 40) -> list:
    """Probe COMMON_ROUTES against base_url with `prober(url)->status|None`. A route
    'exists' if its status is a real response other than a hard miss (400/404) or a
    5xx. Discovered paths are recorded into state.endpoints. Returns [(path, status)]."""
    base = (base_url or "").rstrip("/")
    if not base:
        return []
    found: list[tuple[str, int]] = []
    for path in COMMON_ROUTES[:cap]:
        try:
            status = await prober(base + path)
        except Exception:
            status = None
        if status and 200 <= status < 500 and status not in (400, 404):
            found.append((path, status))
    if found and state is not None:
        try:
            state.record_endpoints([p for p, _ in found])
        except Exception:
            pass
    return found


def base_url_from_state(state: Any) -> str:
    """Best-effort base URL for a web target from the attack-state blackboard."""
    tgt = (getattr(state, "target", None) or "").strip()
    if not tgt:
        return ""
    if tgt.startswith("http://") or tgt.startswith("https://"):
        return tgt
    host = tgt.split("/")[0]
    scheme, port = "http", None
    for p, svc in (getattr(state, "services", {}) or {}).items():
        s = str(svc).lower()
        if "https" in s or "ssl" in s:
            scheme, port = "https", p
            break
        if "http" in s:
            scheme, port = "http", p
    if port is None:
        for raw in (getattr(state, "open_ports", []) or []):
            m = re.match(r"(\d+)", str(raw))
            if m:
                port = m.group(1)
                break
    if port and str(port) not in ("80", "443"):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def make_dispatcher_prober(dispatcher: Any, session_id: str = ""):
    """A prober that issues a real GET through the tool dispatcher (so probes respect
    scope + the persistent session) and reads the Status code the tool echoes back."""
    async def prober(url: str) -> Optional[int]:
        out = await dispatcher.dispatch("http_request", {"url": url, "method": "GET"},
                                        session_id)
        m = re.search(r"Status:\s*(\d+)", out or "")
        return int(m.group(1)) if m else None
    return prober


class RouteEnumMiddleware(AgentMiddleware):
    """Single-agent loop: once, if the web target has few discovered endpoints, probe
    the common routes and inject the real ones so the agent stops guessing /dashboard."""
    name = "route_enum"

    def __init__(self, prober=None, *, min_endpoints: int = 4) -> None:
        self._prober = prober
        self._min = min_endpoints
        self._done = False

    async def on_iteration_start(self, ctx: LoopContext) -> None:
        if self._done:
            return
        st = ctx.attack_state
        if st is None:
            return
        if len(getattr(st, "endpoints", []) or []) >= self._min:
            self._done = True
            return
        base = base_url_from_state(st)
        if not base:
            return
        self._done = True
        prober = self._prober
        if prober is None:
            disp = getattr(ctx.controller, "tool_dispatcher", None)
            if disp is None:
                return
            prober = make_dispatcher_prober(disp, ctx.session_id)
        found = await enumerate_routes(prober, base, st)
        if found:
            ctx.inject.append(
                "Route enumeration found REAL paths (use these, do not guess): "
                + ", ".join(f"{p} [{s}]" for p, s in found[:15]))


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


@dataclass
class Vaccine:
    """A defensive artifact generated from a confirmed vulnerability."""
    vulnerability: str
    detection: str = ""     # a detection signature / rule / log query
    remediation: str = ""   # how to fix or mitigate
    notes: str = ""

    def as_text(self) -> str:
        parts = [f"# Vaccine — {self.vulnerability}"]
        if self.detection:
            parts.append(f"\n## Detection\n{self.detection}")
        if self.remediation:
            parts.append(f"\n## Remediation\n{self.remediation}")
        if self.notes:
            parts.append(f"\n## Notes\n{self.notes}")
        return "\n".join(parts)


def _coerce_vaccine(vuln: str, result: Any) -> Vaccine:
    """Normalise a generator's return (Vaccine | dict | str) into a Vaccine."""
    if isinstance(result, Vaccine):
        if not result.vulnerability:
            result.vulnerability = vuln
        return result
    if isinstance(result, dict):
        return Vaccine(
            vulnerability=result.get("vulnerability") or vuln,
            detection=str(result.get("detection", "")).strip(),
            remediation=str(result.get("remediation", "")).strip(),
            notes=str(result.get("notes", "")).strip())
    return Vaccine(vulnerability=vuln, notes=str(result).strip())


VaccineGenerator = Callable[[str, dict], Awaitable[Any]]
VaccineSink = Callable[[LoopContext, Vaccine], Awaitable[None]]


class VaccineMiddleware(AgentMiddleware):
    """Defensive follow-up loop ('offensive vaccine' / blue-cell).

    Every time the engagement confirms a NEW vulnerability, generate a defensive
    artifact for it — a detection signature and a remediation — and record it, so
    each offensive finding yields a blue-team deliverable. This is Decepticon's
    blue-cell node expressed as a composable loop slot.

    Vulnerabilities are read from the attack-state blackboard; each is vaccinated
    exactly once (tracked across turns). A `generator` produces the artifact
    (async `(vuln, context) -> Vaccine | dict | str | None`); a returned None is
    skipped. Recording emits a `vaccine.generated` bus event, adds a `note` to the
    knowledge graph linked to the vulnerability, and calls the optional `sink`
    (e.g. write a file / print). `per_step_cap` bounds how many are generated in a
    single slot invocation so a burst of findings doesn't stall the loop; the rest
    are picked up on the next step.
    """

    name = "vaccine"

    def __init__(self, generator: VaccineGenerator,
                 sink: Optional[VaccineSink] = None, per_step_cap: int = 3) -> None:
        self.generator = generator
        self.sink = sink
        self.per_step_cap = int(per_step_cap or 0) or 3
        self._seen: set[str] = set()   # vulnerabilities already vaccinated

    @staticmethod
    def _vulns(ctx: LoopContext) -> list:
        st = ctx.attack_state
        return list(getattr(st, "vulnerabilities", []) or []) if st is not None else []

    @staticmethod
    def _context(ctx: LoopContext) -> dict:
        st = ctx.attack_state
        return {
            "target": getattr(st, "target", None) if st is not None else None,
            "phase": getattr(st, "current_phase", None) if st is not None else None,
        }

    async def _sweep(self, ctx: LoopContext) -> None:
        made = 0
        for vuln in self._vulns(ctx):
            if vuln in self._seen:
                continue
            if made >= self.per_step_cap:
                break
            self._seen.add(vuln)
            made += 1
            try:
                result = await self.generator(vuln, self._context(ctx))
            except Exception as exc:
                logger.warning("Vaccine generator failed for %r: %s", vuln, exc)
                continue
            if result is None:
                continue
            await self._record(ctx, _coerce_vaccine(vuln, result))

    async def _record(self, ctx: LoopContext, vaccine: Vaccine) -> None:
        controller = ctx.controller
        bus = getattr(controller, "bus", None)
        if bus is not None:
            try:
                await bus.emit("vaccine.generated",
                               {"vulnerability": vaccine.vulnerability,
                                "detection": vaccine.detection,
                                "remediation": vaccine.remediation,
                                "session_id": ctx.session_id},
                               source="vaccine", session_id=ctx.session_id)
            except Exception:
                pass
        kg = getattr(controller, "knowledge_graph", None)
        if kg is not None:
            try:
                note = kg.add("note", f"vaccine: {vaccine.vulnerability}",
                              attrs={"kind": "vaccine",
                                     "detection": vaccine.detection,
                                     "remediation": vaccine.remediation,
                                     "notes": vaccine.notes},
                              source="vaccine")
                vuln_ent = kg.add("vulnerability", vaccine.vulnerability, source="vaccine")
                if note is not None and vuln_ent is not None:
                    kg.relate(vuln_ent.id, "mitigated-by", note.id)
            except Exception as exc:  # a findings-store hiccup must not break the loop
                logger.debug("Vaccine KG record failed: %s", exc)
        if self.sink is not None:
            try:
                await self.sink(ctx, vaccine)
            except Exception as exc:
                logger.warning("Vaccine sink failed: %s", exc)

    async def on_iteration_start(self, ctx: LoopContext) -> None:
        await self._sweep(ctx)

    async def on_turn_end(self, ctx: LoopContext, response: Any) -> None:
        # Catch a vulnerability confirmed on the final step of the turn.
        await self._sweep(ctx)


def make_model_vaccine_generator(controller: Any) -> VaccineGenerator:
    """A default generator that asks the controller's model for the vaccine JSON.

    Best-effort: any model/parse failure yields None (skip) so the loop is never
    broken by the defensive follow-up. Returns an async `(vuln, context) -> Vaccine`.
    """
    async def _gen(vuln: str, context: dict) -> Optional[Vaccine]:
        target = context.get("target") or "the target"
        prompt = [
            {"role": "system", "content":
                "You are a blue-team detection engineer supporting an AUTHORIZED "
                "security engagement. Given a confirmed vulnerability, produce a "
                "concise DEFENSIVE artifact. Reply with ONLY one JSON object: "
                '{"detection": "<a concrete detection signature, log query, or rule>", '
                '"remediation": "<how to fix or mitigate>", "notes": "<optional>"}.'},
            {"role": "user", "content":
                f"Target: {target}\nConfirmed vulnerability: {vuln}\n"
                "Produce the vaccine JSON now."},
        ]
        try:
            raw = await controller.model.chat(messages=prompt)
        except Exception as exc:
            logger.debug("Vaccine model call failed: %s", exc)
            return None
        try:
            content = (controller._parse_model_response(raw).get("content", "") or "").strip()
        except Exception:
            content = raw.strip() if isinstance(raw, str) else ""
        parsed: dict = {}
        try:
            start, end = content.index("{"), content.rindex("}") + 1
            parsed = json.loads(content[start:end])
        except Exception:
            parsed = {"notes": content[:500]}
        return Vaccine(
            vulnerability=vuln,
            detection=str(parsed.get("detection", "")).strip(),
            remediation=str(parsed.get("remediation", "")).strip(),
            notes=str(parsed.get("notes", "")).strip())

    return _gen


class ReflectionMiddleware(AgentMiddleware):
    """Periodic self-critique + tactical staging (frontier-loop parity).

    Frontier agent loops don't just react step to step — every so often they stop to
    reflect: what have I actually learned, what's my current hypothesis, and what is the
    highest-value thing I haven't tried? This middleware injects exactly that prompt
    every `every` iterations, and names the current TACTICAL STAGE derived from live
    state (recon → find a primitive → exploit → extract), so the agent drives a
    kill-chain instead of drifting. It costs no extra model call — the reflection rides
    on the next call as a steering message.
    """

    name = "reflection"

    def __init__(self, every: int = 6) -> None:
        self.every = int(every or 0)
        self._last = 0

    @staticmethod
    def _stage(state: Any) -> str:
        """The tactical kill-chain stage implied by the current findings."""
        if state is None:
            return "reconnaissance — map the target"
        flags = getattr(state, "flags", None) or []
        creds = getattr(state, "credentials", None) or []
        vulns = getattr(state, "vulnerabilities", None) or []
        ports = getattr(state, "open_ports", None) or []
        if flags:
            return "extraction — you have the objective in hand; verify and report it"
        if creds:
            return "escalation — use the access/credentials you have to reach the objective"
        if vulns:
            return "exploitation — turn a confirmed weakness into access or the objective"
        if ports:
            return "find a primitive — enumerate the surface for an exploitable weakness"
        return "reconnaissance — map the target's ports, services, and entry points"

    async def on_iteration_start(self, ctx: LoopContext) -> None:
        it = ctx.iteration
        if self.every <= 0 or it < self.every or (it - self._last) < self.every:
            return
        self._last = it
        stage = self._stage(ctx.attack_state)
        ctx.inject.append(
            "CHECKPOINT — reflect before your next action. In three short lines state: "
            "(1) CONFIRMED — the concrete facts you have actually verified from tool "
            "output; (2) HYPOTHESIS — your current best theory for reaching the "
            "objective; (3) NEXT — the single highest-value action you have NOT yet "
            f"tried. Your tactical stage looks like: {stage}. Then take that NEXT "
            "action — do not repeat anything already tried, and do not restate the plan "
            "without acting on it.")
        bus = getattr(ctx.controller, "bus", None)
        if bus is not None:
            try:
                await bus.emit("agent.reflection",
                               {"iteration": it, "stage": stage,
                                "session_id": ctx.session_id},
                               source="reflection", session_id=ctx.session_id)
            except Exception:
                pass
