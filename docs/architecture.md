# Architecture

A concise overview. `STATUS.md` in the repo root is the authoritative, always-current
description; this page is the map.

## The loop

Mapache runs one execution path: an observe-act (ReAct) loop in
`core/agent_controller.py`. Each step, the model reads the current context (system
prompt, attack state, prior tool output) and emits exactly one tool call. The real
result is fed back and the model decides the next step. There is no discarded planning
pass and no double-firing of tools.

State lives in a shared blackboard, `AttackState` (`core/conversation_chain.py`):
target, open ports, services, versions, vulnerabilities, credentials, flags, discovered
endpoints, forms, disclosed credentials, and dead vectors. Tool results update it
automatically, so the model does not have to restate what it found.

## Single agent vs swarm

A generalist agent works the whole kill chain. When the supervisor is enabled
(`--fanout` or `/swarm`, `core/orchestrator.py`), it instead routes a bounded objective
to a specialist sub-agent (recon, web, exploit, post, cloud, AD, binary, mobile, and
more). Each sub-agent runs with a focused prompt and a small tool subset, sharing the
lead's AttackState and knowledge graph. Routing advances by findings; on a stall the
supervisor fans out several distinct specialists in parallel and re-routes on the merged
results.

Sub-agents reuse the lead's tool dispatcher, so a persistent HTTP session and the request
history carry across the whole engagement.

## Middleware

Cross-cutting concerns plug into loop slots (`core/middleware.py`,
`core/agent_middlewares.py`): budget enforcement, human-in-the-loop checkpoints,
defensive vaccine generation, periodic self-reflection, and active route enumeration.
They are opt-in and inert until registered.

## Model routing

The controller talks to a model provider. Under a routed strategy it can pick a model
per role (planner vs executor), and per-operator tiering can send high-volume discovery
work to a cheaper model while keeping the hacking-critical operators on the strong one
(`models/tiered_model.py`, `Operator.tier`).

## Safety

- Rules-of-engagement scope (`core/engagement_scope.py`): out-of-scope targets and
  forbidden tools/patterns are refused before they run.
- Prompt-injection shield (`core/injection_shield.py`): tool output is fenced as
  untrusted data, an active detector flags hijack attempts, and injection attempts are
  logged as an auditable event.
- Engagement log (`core/engagement_log.py`): an append-only JSONL audit trail, with an
  optional replayable asciicast recording (`core/asciicast.py`).

## Reporting

Confirmed weaknesses become structured findings (`core/findings.py`) and are rendered as
a report (`reporting/`). See [reporting.md](reporting.md).
