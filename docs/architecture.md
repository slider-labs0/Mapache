# Architecture

Mapache runs one execution path: a ReAct (reason and act) loop. There is no hidden
planner pipeline and no separate executor. The agent observes, acts with one tool,
reads the real result, and decides the next step. This page explains the moving parts.

## The agent loop

`core/agent_controller.py` holds `AgentController`, the orchestrator. Its `_agent_loop`
is the heart of Mapache:

1. Build the prompt (system prompt, attack state, task list, relevant playbooks, recent
   history) with the context builder.
2. Ask the model for the next action. Native tool-calling models return a structured
   tool call; models without native tool-calling return JSON that the loop parses.
3. Dispatch the chosen tool, enforce the rules-of-engagement scope first, and capture
   the real output.
4. Fold the result back into the attack state and the conversation, then loop.

The loop is bounded by `MAX_ITERATIONS` so it can never run away, and it stops early
when the model produces a final answer, when a loop policy halts it, or when a budget
is exhausted.

### One tool per step

Reading each real result before choosing the next step is what keeps Mapache grounded.
It does not invent endpoints or assume a scan result. It acts, observes, and adapts.
The model can still batch several independent tool calls in a single turn (for example,
scanning two hosts at once); those dispatch concurrently and fold back in the order the
model stated.

## Attack state and the conversation chain

`core/conversation_chain.py` holds `ConversationChain`, which tracks the attack state
across turns: the target, open ports, services, the current phase, discovered
vulnerabilities, captured credentials, and flags. Key behaviors:

- A freshly typed IP that differs from the current target overrides it and clears stale
  findings. This handles a lab machine getting a new IP mid-session.
- Rescan keywords clear cached ports so a fresh scan is not skipped.
- Tool outputs are compressed before they are re-injected, which prevents the context
  from overflowing on a long engagement.
- A persistent task list (todos) survives across turns. The model seeds it with a plan,
  updates item status, and the loop re-injects a `=== TASK LIST ===` block every
  iteration so the model always sees mid-turn progress.

## Phases and tool subsetting

Mapache models an engagement as phases: recon, enumeration, exploitation, post, and
report. `ConversationChain.active_tool_names` exposes only the tools relevant to the
current phase. This keeps the function-calling payload small enough for local models,
which otherwise choke on a large tool schema. Certain tools (delegation, memory,
generated tools, MCP tools) are pinned so subsetting never hides them.

The attack system prompt encodes a default workflow: recon, then enumerate, then
exploit, then post, then report. It blocks exploitation before a scan has returned open
ports, so the agent does not fire an exploit at a host it has not looked at yet.

## The context builder

`core/context_builder.py` assembles the prompt and enforces a token budget
(`max_context_tokens`, default 16384). It injects the system prompt, the live attack
state, the task list, any relevant playbooks, and recent history. When native
tool-calling is available, tool schemas go in the dedicated `tools` field; otherwise the
tools are described in the prompt and the model is asked for JSON output.

## Context compaction

When raw history outgrows its token budget, the controller summarizes the oldest turns
into a running summary with a model call and drops those messages, instead of silently
trimming them. The summary is prepended to the system prompt as "CONVERSATION SO FAR".
Durable facts (targets, ports, versions, credentials, vulnerabilities, flags, paths, and
what is pending) are kept verbatim. Compaction only fires when actually over budget and
keeps a recent window, and it fails open to a plain trim if anything goes wrong.

## Robust tool-call parsing

Local models mangle output in predictable ways. `_parse_model_response` tolerates JSON
fenced in code blocks, JSON embedded in prose (a balanced, string-aware brace scan), and
a missing type tag (inferred from the keys present). Output that clearly intended the
protocol but is unusable is flagged as malformed; the loop feeds the error back and asks
for a clean retry, bounded by `MAX_REASKS`. Incidental braces in a normal answer are not
reasked.

## Loop safety rails

- No-progress and duplicate-call guard: within a turn, an identical tool call (same name
  and args) runs once; later repeats are short-circuited with the cached result and a
  nudge to change approach. This fixes the "fetch the same URL five times" loop.
- Stall and loop detection aborts a turn early when the model spams duplicates or makes
  no progress, so a weak model does not burn the whole iteration budget going in
  circles.
- Answer general knowledge directly: definitions and facts the model already knows are
  answered in plain text without tools, and a blocked lookup falls back to the model's
  own knowledge rather than being reported as the final answer.

## The event bus

`core/event_bus.py` is the pub/sub backbone. The loop emits events (tool calls,
findings, delegations, scope refusals, steering, duplicate calls). Observers subscribe
without driving the loop. The audit log and the TUI dashboard are both event consumers,
which is why they never slow the agent down.

## Mid-run steering

A frontend can call `AgentController.steer(text)` to redirect a turn already in progress.
Queued messages are drained at the top of each loop iteration and injected as operator
steering. A freshly typed target or a rescan updates the attack state without disturbing
the in-progress turn. This lets you correct the agent live without restarting the
session.

## Middleware

`core/middleware.py` provides composable loop middleware. Shipped middleware includes
budget enforcement (stop gracefully at a token or time cap), a human-in-the-loop
checkpoint slot, an offensive-vaccine loop (turn each confirmed vulnerability into a
detection and remediation note), and a reflection and tactical-staging step. Middleware
is opt-in and inert unless configured.
