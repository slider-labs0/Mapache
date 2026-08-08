# Architecture

This is the in-depth tour. For the always-current summary see `STATUS.md` in the repo
root. Related deep-dives: [agents](agents.md), [middleware](middleware.md),
[reporting](reporting.md).

## One execution path

Mapache runs a single execution path: an observe-act (ReAct) loop in
`core/agent_controller.py` (`AgentController._agent_loop`). It previously carried two
other, dead pipelines (an event-bus planner and a ModelManager pipeline); both were
removed so there is exactly one place a turn executes and no risk of double-firing a
tool against a live target.

## The agent loop, step by step

Each iteration of the loop:

1. **Build context.** `core/context_builder.py` assembles the prompt: the system prompt,
   the current attack-state block, recent conversation, and any middleware injections. It
   applies phase-based tool subsetting so the model sees a small, relevant tool set rather
   than all ~60 (a large set overflows small-model context and invites drift).
2. **Fence untrusted input.** Every prior tool result is wrapped as untrusted data (see
   Safety) so a hostile target cannot smuggle instructions into context.
3. **Model call.** The model returns either a final answer or exactly one tool call.
   One tool per step keeps the loop observable: the real result is read before the next
   decision.
4. **Dispatch.** `tools/tool_dispatcher.py` runs the tool, gated by the granted
   permissions and the engagement scope. The result updates the shared attack state.
5. **Fold in findings.** New ports, services, vulns, credentials, flags, endpoints,
   forms, and disclosed credentials are recorded automatically and emitted as events
   (the engagement log and knowledge graph subscribe).
6. **Guardrails.** Stall detection, the progress ledger, and duplicate suppression run
   before the next step.

### Stall detection and the progress ledger

Weak models spin: they repeat a call or make no progress. The loop tracks two streaks
(`AgentController` constants):

- `STALL_ABORT_DUP` (4) consecutive all-duplicate steps, and
- `STALL_ABORT_NOPROG` (8) consecutive steps that discover nothing.

A step that discovers something resets both. On a stall the turn is aborted early with an
`agent.stall` event, so a fruitless turn ends cheaply instead of burning the whole
budget. The **progress ledger** (`core/progress_ledger.py`) persists dead-end actions
across turns and injects a "do not repeat" block, so the model stops re-spraying
endpoints it already tried.

## The attack-state blackboard

`AttackState` (`core/conversation_chain.py`) is the shared source of truth. It holds the
target, open ports, services, versions, vulnerabilities, credentials, flags, and the
web-tradecraft signals added for grounding:

- **endpoints** - normalized path+param-name keys discovered in responses. Surface and
  parameter discovery advance a routing "progress" signal; value iteration over one
  parameter collapses to a single key and reads as no progress.
- **forms** - each response's real form method, action, and input field names, so the
  agent submits the actual form instead of inventing an endpoint like `/login`.
- **disclosed_creds** - credentials leaked in HTML comments or JS (a `user:pass` token or
  a labeled value), surfaced as a directive to try them first.
- **dead_vectors** - path templates that returned an identical body across several
  distinct requests (an ignored parameter). A working IDOR returns different bodies and
  is never flagged.

`to_prompt_block()` renders this state into the prompt each step so the model acts on
what is actually there.

## Grounding: read, do not guess

The observed failure mode of a naive agent is inventing endpoints, field names, and
payloads. Mapache counters this deterministically:

- `web_fetch`/`http_request` parse the response and record the real forms, endpoints, and
  disclosed credentials into state.
- `search_payloads` looks up real payloads from an offline corpus by vuln class.
- The dead-vector detector tells the agent when a parameter is doing nothing so it changes
  approach.
- The Burp-style `http_repeater` records every request so the agent can replay one with a
  single value changed and diff the responses - the IDOR/broken-access-control primitive.

## Model routing

The controller talks to a model provider through a uniform `chat`/`chat_stream` surface,
so the provider can be a single model or a router:

- **RoutedModel** (`models/routed_model.py`) scores installed models per role
  (planner vs executor) under a routing strategy (single, pipeline, auto, hybrid).
- **TieredModel** (`models/tiered_model.py`) routes by an explicit per-operator tier:
  low-tier discovery operators (recon, OSINT, scanning) run on a cheaper model while the
  hacking-critical operators stay on the strong one. Each `Operator` carries a `tier`
  (`high` by default so nothing critical is downgraded by accident).

When the supervisor spawns a sub-agent it applies both hooks (`for_role`, `for_tier`), so
routing is per specialist.

## Safety

- **Rules of engagement** (`core/engagement_scope.py`): a `scope.json` defines in-scope
  targets and forbidden tools/patterns. A call that would act out of scope is refused
  before it runs, with an `agent.scope_refused` event. Loopback and local utility commands
  are allowed by default.
- **Prompt-injection shield** (`core/injection_shield.py`): the `SHIELD_CLAUSE` tells the
  model that tool output is untrusted data; `wrap_untrusted` fences each result between
  hard-to-forge sentinels; and `detect_injection` actively scans for hijack attempts
  (instruction override, persona hijack, system-prompt leak, target pivot, and so on),
  prepending an inline warning and emitting an auditable `agent.injection_detected` event.
- **Engagement log** (`core/engagement_log.py`): an append-only JSONL audit trail of every
  tool call, finding, scope refusal, delegation, and injection attempt. It seeds the
  report and can be exported as a Markdown timeline.
- **Session recording** (`core/asciicast.py`): an optional replayable asciicast of the
  whole engagement, for debrief or court-ready evidence (`--cast`).

## Persistence

- **Knowledge graph** (`core/knowledge_graph.py`): a typed entity/relation findings store
  on disk that sub-agents read and write via `kg_query`/`kg_add`, so a freshly-spawned
  specialist knows what earlier stages found without the lead re-explaining. Attack-state
  findings are auto-ingested.
- **Findings store** (`core/findings.py`): the evidence-first deliverable. See
  [reporting](reporting.md).
- **Memory**: durable user facts and per-target notes persist across sessions.
- **Cross-engagement learning**: outcomes are recorded by target fingerprint and bias the
  operator router toward what has worked on similar targets before.
