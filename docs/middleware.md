# Middleware

Cross-cutting concerns (budget, human approval, defensive follow-up, reflection, route
enumeration) are not hand-wired into the loop. They are composable middleware that hook
well-defined slots, so they can be added or removed without touching the controller.

## The framework

`core/middleware.py` defines the contract:

- **`AgentMiddleware`** - a base class with three optional async hooks:
  - `on_turn_start(ctx)` - once, before the first model call of a turn.
  - `on_iteration_start(ctx)` - the top of every loop step.
  - `on_turn_end(ctx, response)` - once, after the turn produces its answer.
- **`LoopContext`** - the mutable per-turn state passed to every hook. A middleware
  influences the loop by setting:
  - `ctx.stop = True` (with `ctx.stop_reason`) to end the turn now, or
  - `ctx.inject.append("...")` to add a user message before the next model call
    (steering, nudges, approvals).
  It also exposes `ctx.controller`, `ctx.session_id`, `ctx.iteration`, and a `scratch`
  dict middlewares can share within a turn.
- **`MiddlewareChain`** - runs the registered middlewares at each slot, in order. A hook
  that raises is logged and swallowed, so one bad middleware cannot break the engagement.
  A `ctx.stop` short-circuits the remaining middlewares at that slot.

The default chain is empty; middleware is inert until registered (usually from a CLI
flag). Register with `controller.add_middleware(...)`.

## Built-in middlewares

All live in `core/agent_middlewares.py`.

### BudgetMiddleware
Stops the engagement once it exceeds a token or wall-clock budget. Checks the controller's
cumulative token usage and elapsed time at each iteration and sets a graceful
`ctx.stop`/`ctx.stop_reason` with a `budget.exceeded` event. Wired by
`--budget-tokens N` / `--budget-seconds S`.

### HITLMiddleware
A human-in-the-loop checkpoint gate. Fires on an `every`-N iterations cadence and/or on a
phase change; a callback returns approve, deny (stop), or steer (inject a new instruction).
Fail-open on a callback error, and the first iteration never gates. Distinct from
per-tool dangerous-action confirmation. Wired by `--hitl` / `--hitl-every N`.

### VaccineMiddleware
Defensive follow-up. On each newly confirmed vulnerability it generates a detection plus
remediation note (a "vaccine"), records it to the knowledge graph as mitigating the
vulnerability, and writes it to the workspace. Vaccinated once per vulnerability; a
per-step cap bounds bursts. Wired by `--vaccine`.

### ReflectionMiddleware
Every N steps it injects a structured self-critique: confirmed facts, current hypothesis,
and the highest-value next action, so the agent reasons about what it has learned instead
of drifting. Wired by `--reflect` / `--reflect-every N`.

### RouteEnumMiddleware
Active route enumeration. Once, when a web target has few discovered endpoints, it probes
a curated list of common routes through the tool dispatcher and folds the real hits
(non-404) into the shared endpoints, then injects them so the agent uses real paths
instead of guessing. Wired by `--route-enum`; the swarm runs the equivalent enumeration
in the supervisor before routing.

## Where the supervisor fits

The multi-agent supervisor is not a loop middleware; it is a control loop that drives
sub-agent turns. Its anti-loop, fan-out, and route enumeration are described in
[agents](agents.md). A sub-agent is itself an `AgentController`, so any middleware
registered on it hooks that sub-agent's loop.
