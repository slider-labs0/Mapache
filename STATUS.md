# Mapache — Phase Status

> Full-spectrum offensive-security AI agent (web, network, cloud, AD, binary, mobile,
> social engineering). Local-model (Ollama) or cloud ReAct loop with phase-aware
> attack-state tracking, composable loop middleware, an autonomous multi-agent
> supervisor, a ~50-tool offensive toolchain, persistent + cross-engagement memory,
> and Telegram/Discord operation.

This document reflects the **current** architecture after the execution-path
consolidation (see "Architecture note" below). It is the source of truth — if
code and this file disagree, fix one of them.

---

## Architecture note — one execution path

Mapache previously carried **three** ways to execute a turn; two were dead and
have been removed:

- **ReAct loop (LIVE):** `AgentController._agent_loop` — observe → act, one tool
  per step, reading each real result before deciding the next step. This is the
  agent.
- **Event-bus plan pipeline (REMOVED):** `core/planner.py` + `core/task_manager.py`
  fired a synchronous planning model call every turn whose output was discarded,
  and an orphaned executor re-dispatched the same tools the ReAct loop already
  ran (a double-fire risk against live targets). Deleted.
- **ModelManager pipeline (REMOVED):** `models/model_manager.py` + `models/pipelines/`
  — a planner→executor→verifier→synthesizer wrapper whose `run_turn` was never
  called. Deleted. `model_registry.py` and `routing_engine.py` were **kept** as
  salvage for wiring real per-role routing into the loop later.

---

## ✅ Phase 1 — Core Runtime

```
core/
  agent_controller.py    ← orchestrator + ReAct agent loop, ConversationChain wired in
  context_builder.py     ← prompt assembly, token budget, phase-based tool subsetting
  conversation_chain.py  ← attack-state persistence across turns
  executor.py            ← shell/tool execution utility (used by !cmd + dispatch)
  event_bus.py           ← pub/sub backbone (logging/observability)
  logger.py              ← colored console + file logging
  project_context.py     ← injects MAPACHE.md / project context
cli/
  mapache_cli.py         ← full attack-mode CLI
```

Milestone: CLI input → AI → shell tool → real output.

## ✅ Phase 2 — Tool Layer

```
tools/
  tool_registry.py
  tool_dispatcher.py
  tool_schema.py
plugins/sdk/
  base_tool.py
security_tools/
  shell_tool.py
  recon/nmap_tool.py
```

Milestone: structured Nmap scan with schema validation and self-correction.

## ✅ Phase 3 — Browser & Tor

```
browser/
  http_client.py
  scraping_tools.py      ← web_fetch, web_search, tor_fetch
  tor_controller.py
  chromium_controller.py
```

Milestone: agent browses surface web; Tor detected and guided.

## ✅ Phase 4 — Memory System

```
memory/
  session_memory.py
  note_store.py
  knowledge_store.py
  vector_store.py
  memory_manager.py      ← agent-callable memory tools
```

Milestone: findings persist across sessions; semantic recall working.

## ✅ Phase 5 — Messaging Integrations

```
integrations/messaging/
  gateway.py             ← central router
  telegram_bot.py        ← working
  discord_bot.py         ← working
  bot_launcher.py        ← single command launches both
integrations/social/
  moltbook_tool.py       ← AI social network integration
```

Milestone: Mapache operates over Telegram and Discord with the full toolset.

## ✅ Phase 6 — Advanced Security Tools

```
security_tools/
  exploitation/
    metasploit_tool.py   ← MSFRPC integration
    burpsuite_tool.py    ← REST API + proxy
  cracking/
    john_tool.py         ← hash identification + cracking
  kali/
    kali_tools_interface.py ← kali_list, kali_run, searchsploit
```

Milestone: full offensive toolchain registered and callable.

## ✅ Phase 7 — Multi-Model Routing (LIVE)

```
models/
  model_registry.py      ← scores known models by role
  routing_engine.py      ← per-role model selection, skips embedding-only models
  model_pool.py          ← lazy OllamaProvider cache, one per model id
  routed_model.py        ← provider facade; routes each call to the best model
  providers/ollama_provider.py
```

**Status:** routing is **wired into the live turn path**. The CLI builds a
`RoutedModel` as the agent's `model_provider`; every call consults the
`RoutingEngine` and dispatches to the best installed model for the role. The
ReAct loop runs as the EXECUTOR role. `--strategy` and the `/pipeline` command
now take real effect, and `/models` shows the live routing table plus a
per-model call count. With a single model installed, routing collapses to that
model (no behaviour change).

Routing by strategy (default is `single`, so the chosen `--model` is always
honored; routing is opt-in):
- `single`   — one model for everything (the `--model` you pass)
- `auto`     — best role score per role
- `pipeline` — quality-weighted planner/verifier, speed-weighted executor
- `hybrid`   — cloud planner/verifier + local executor (needs `--allow-cloud`)

**Verifier:** see Phase 8 below — wired as an opt-in (`--verify`).

## ✅ Phase 8 — Verifier / Reflection (LIVE, opt-in)

Enabled with `--verify` (off by default — zero added latency on normal runs).
After the ReAct loop produces a final answer, a VERIFIER-role model call judges
whether it actually addresses the goal. On a failed verdict the loop resumes
once with the verifier's suggested next step; on pass (or after the retry
budget) it returns. Bounded by `verify_max_retries` (default 1) and the overall
`MAX_ITERATIONS`, so it can never deadlock or run away. Any verifier error or
unparsable verdict passes through (fail-open).

```
core/agent_controller.py   ← _verify() + loop integration, enable_verifier flag
cli/mapache_cli.py         ← --verify flag, routes the check to the VERIFIER role
```

`--no-verifier` is now a deprecated no-op (the verifier is off unless `--verify`).

---

## ✅ Post-Phase-8 — Differentiators, Decepticon parity & the agent-loop upgrade

Everything past Phase 8 (2026-06 → 2026-08). This is a digest; **`ROADMAP.md`
sections J–S carry the per-item detail, touchpoints, and tests.** All on branch
`feature/agent-loop-upgrades`; the core unit suite (`tests/test_core.py`) is at **168
passing**.

**Differentiators J–P (shipped 2026-06):** Rules-of-Engagement guardrails (J), an
auditable engagement log (K), automated reporting/deliverables (L), exploit/CVE
grounding (M), skill synthesis from proven chains (N), hybrid OPSEC routing — pin
sensitive work to a local model (O), and multi-agent engagement orchestration —
operator specialists over a shared blackboard (P).

**Q — Decepticon-parity convergence (2026-07 → 08):** disk-persisted knowledge graph
+ OPPLAN + a vuln-research pipeline; an autonomous **supervisor/router**
(`core/orchestrator.py`) that deploys specialists from state; and the user-ordered
**1–7 middleware sequence** — composable loop middleware (`core/middleware.py`), budget
enforcement, a formal HITL slot, the offensive-vaccine loop, parallel operator fan-out,
the SKILL.md formatter, and full sub-agent trace streaming (`ScopedBus`) — plus a
persistent progress ledger.

**R — Frontier-loop capability upgrades (2026-08):** a real **headless-browser tool**
(Playwright; JS/SPA rendering — live-verified), **response-grounded acting** (nudge off
blind endpoint spraying), disciplined **sqlmap + ffuf** wrappers, a **reflection +
tactical-staging** middleware, and **multi-attempt / self-consistency** solving
(`--attempts`).

**S — Full-spectrum coverage + cross-engagement learning (2026-08):** built-in
just-in-time playbooks now span web, network, credential, AD, **cloud**, **binary-pwn**,
**mobile**, and **social-engineering** (Mapache is no longer web-only); a **format-aware
candidate-flag verifier**; and a **cross-engagement learning store** that biases routing
toward what won on similar targets before.

---

## Current tool count: ~50 registered + core meta-tools

Beyond the Phase-1–6 base (shell/file*/nmap/web*/msf*/burp*/john*/kali*/searchsploit/
memory*), the offensive toolchain now includes **browser** (headless Chromium),
**sqlmap**, **fuzz** (ffuf), plus the meta-tools **create_tool**, **delegate** /
**delegate_parallel**, **kg_query** / **kg_add**, **opplan_add/update/show**,
**cve_lookup**, **synthesize_skill**, and **vuln_research**. Operators drive
domain-specific CLIs (aws/kubectl/frida/ghidra/jadx/gophish) through `shell`/`kali_run`.

---

## Key behaviors

- **ConversationChain** tracks attack state (target, open ports, services, phase,
  vulns, credentials, flags) across turns. A freshly typed IP that differs from
  the current target overrides it and clears stale findings (handles HTB machine
  IP reassignment mid-session). Rescan keywords clear cached ports. Tool outputs
  are compressed before re-injection to prevent context overflow.
- **Persistent TODO list** — the model owns a task list that survives across
  turns (`ConversationChain` todos). A `plan` response seeds it
  (`{"type":"plan","todos":[...],"first_tool":...,"first_args":...}`) and
  dispatches the first action; the agent revises it with `todo_update`
  (`{"completed":[1,2]}`) or by re-emitting a plan with per-item status.
  Completed items are preserved across re-emits. A `=== TASK LIST ===` block
  (`[ ]`/`[~]`/`[x]`) is re-injected every loop iteration so the model always
  sees mid-turn progress; the list clears on a target change. This is what makes
  a `plan` actionable instead of a dead-end final answer (the dispatch bug fix).
- **Phase-based tool subsetting** (`ConversationChain.active_tool_names`) exposes
  only the tools relevant to the current attack phase, keeping the function-
  calling payload small enough for local models (avoids the Ollama tool-schema
  overflow). This — not `--no-verifier` — is the fix for the 33-schema overflow.
- **MCP client** — Mapache connects OUT to Model Context Protocol servers
  (`integrations/mcp/`) and exposes their tools as ordinary Mapache tools.
  stdio transport: each server is launched as a subprocess and spoken to over
  newline-delimited JSON-RPC 2.0 (`initialize` → `tools/list` → `tools/call`).
  Servers are listed in a Claude-Desktop-style `mcp.json` (`--mcp-config`,
  default `mcp.json`; absent = off). Remote tools are wrapped as `MCPTool`
  (a `BaseTool`), registered into the same `ToolRegistry`/dispatcher as
  built-ins, and namespaced `mcp__<server>__<tool>`. Their names are pinned in
  `ConversationChain.always_tools` so phase-based subsetting keeps them exposed.
  Connection is fail-soft (a bad server never breaks startup) and clients are
  closed on exit.
- **Self-authored tools (Hermes-style)** — a `create_tool` meta-tool lets the
  model author a brand-new reusable tool at runtime: it writes the body of
  `async def run(args, shell)`, which is compiled (errors handed back for self-
  correction) and persisted as a hub-installable package under
  `plugins/generated/<name>/` (`tool.py` + `manifest.json` carrying origin,
  usage, lifecycle `state`, phase, and a sha256). The tool registers into the
  ToolRegistry + model context + `ConversationChain.generated_tools` (phase-
  tagged so it respects subsetting) and becomes callable the *next* loop
  iteration — never dispatched in the response that created it. Trust model:
  `origin:self` (agent-written) loads freely; `origin:hub` (downloaded) is
  sha256-verified before compile and refuses to load if tampered. `GeneratedTool`
  instances self-track `last_used`/`use_count`. The startup loader
  (`GeneratedToolManager.load_all`) is fail-soft (a bad tool never breaks
  startup, per the MCP precedent). See `tools/generated_tool.py` +
  `tools/generated_tool_manager.py`. Model tools: `create_tool`,
  `tool_list_generated`, `tool_delete` (all in `CORE_TOOLS`).
- **Curator (tool-library GC)** — self-authored tools move through a reversible
  `active → stale → archived` lifecycle so the create-tools loop can't pile up.
  A usage rule auto-demotes unused tools to *stale* (a non-destructive label;
  using one auto-promotes it back to active). The only permissioned step is
  *stale → archived*: `/curate` proposes stale tools one at a time and, on the
  operator's per-tool approval, unregisters them and moves their folder to
  `plugins/archived/` (out of the load path). `/restore <name>` reverses it;
  `/purge <name>` hard-deletes an already-archived tool (a deliberate two-step).
  A non-blocking startup notice reports stale tools.
- **Sub-agent delegation + operator specialists (feature P)** — a built-in
  `delegate(task, operator=…)` tool lets the model spawn a focused child
  `AgentController` for one bounded subtask and get back only its conclusion.
  Recursion is bounded by `MAX_DELEGATION_DEPTH` (1) — a sub-agent isn't offered
  the delegate tool. `delegate` is in `CORE_TOOLS` so phase-subsetting keeps it
  exposed; `agent.delegate.start/end` events fire (with the operator label).
  - **Shared blackboard:** the child references the lead's `AttackState` by
    reference (`shared_state`), so its findings are live in the lead's state with
    no merge-back; `allow_state_reset=False` stops a child's task wording from
    reassigning the target / wiping the shared findings. The child also shares
    the lead's event bus, so its tool calls / findings / RoE refusals land in the
    same engagement log (K). Parallel-safe (asyncio-atomic state mutations);
    dispatch is sequential for now (single-GPU), `gather` fan-out is a later
    drop-in once cloud routing (G) carries the load.
  - **Operators** (`core/operators.py`): a Decepticon-style roster (recon, web,
    exploit, post, osint, cloud_hunter, contract_auditor, reverser, analyst,
    phisher, mobile/wireless/iot/ics, forensicator, supply_chain). Naming one in
    `delegate` runs the child with that operator's **focused system prompt + a
    small curated tool subset** instead of the lead's generalist prompt + full
    toolset — the local-model win (smaller payload, narrower decisions). The
    specialist tooling each names (frida, binwalk, semgrep, evilginx2, modbus…)
    runs through `kali_run`/`shell` or is authored with `create_tool`. Role
    constraints (read-only, RoE-gated, needs-hardware, deconflict-first) render
    into the prompt and reinforce the RoE gate. `/operators` lists the roster;
    `suggest_next_step` nudges the right specialist from open ports/services.
  - **Parallel fan-out:** `delegate_parallel(tasks=[{task, operator}…])` runs
    several operators concurrently (`asyncio.gather`, capped at `MAX_FANOUT`) over
    the shared blackboard — several angles on the current host at once. A
    correctness/orchestration win on a single GPU (model calls serialize at the
    provider) that becomes a wall-clock win once cloud routing (G) serves them
    concurrently. Same-host by design (children share one AttackState); per-host
    sub-states for true multi-host parallel are the remaining P item.
- **Mid-run steering** — a frontend can call `AgentController.steer(text)` (thread-
  safe) to redirect a turn already in progress. Queued messages are drained at
  the top of each loop iteration, injected as `[operator steering] …`, and run
  through `apply_input_signals` so a freshly typed target / rescan updates the
  attack state without disturbing the in-progress turn's bookkeeping; an
  `agent.steer` event fires. The CLI now uses one background stdin reader → async
  queue with a single consumer (REPL when idle, steering loop during a turn), so
  the operator can type to steer (or answer a `--confirm` prompt) without a
  second reader racing for stdin. The async messaging frontends can call
  `steer()` directly.
- **Context compaction** — when raw history outgrows its token budget, the
  controller summarizes the oldest turns into a running summary (a model call
  via `_maybe_compact`) and drops those messages, instead of silently trimming
  them. The summary is prepended to the system prompt as "CONVERSATION SO FAR",
  preserving continuity over a long engagement; durable facts (targets, ports,
  versions, creds, vulns, flags, paths, what's pending) are kept verbatim. Only
  fires when actually over budget, keeps a ~50% recent window, caps the summary,
  and fails open (`_trim_history` remains the safety net). Toggle:
  `enable_compaction` (default on).
- **Token streaming (unified)** — the live turn path streams model tokens to
  the caller via an optional `on_token` callback on `run()`/`_agent_loop`. A
  single streaming-aware `_chat` helper reassembles streamed pieces into the
  same shape `chat()` returns, so todos/reask/verifier/multi-tool all behave
  identically streamed or not. Streaming engages only for native tool-calling
  models (JSON-mode models would stream raw protocol JSON, so they fall back to
  a normal call). The CLI prints tokens live; the old `stream()` generator is
  now a thin queue wrapper over `run()`, so there is one turn implementation.
- **Multi-tool calls per turn** — the model can issue several independent tool
  calls in one turn via `{"type":"tool_calls","calls":[{tool,args}, ...]}` (or
  native multi `tool_calls`). `_execute_tool_calls` confirms dangerous ops
  sequentially, dispatches the batch concurrently (`asyncio.gather`), then folds
  results back into the chain/context serially in the model's stated order.
  Saves model round-trips for independent actions (e.g. scanning two hosts). A
  single-element batch collapses to a normal `tool_call`.
- **Robust tool-calling** — `_parse_model_response` tolerates the ways local
  models mangle output: JSON fenced in ```json blocks, JSON embedded in prose
  (balanced, string-aware brace scan), and a missing `"type"` tag (inferred
  from the keys present). Output that clearly intended the protocol but is
  unusable (unknown `type`, a tool call with no tool name) is flagged
  `malformed`; the loop then feeds the error back and asks for a clean retry,
  bounded by `MAX_REASKS` (default 2) and fail-open on exhaustion. Incidental
  braces in a normal answer are NOT reasked. This is the general fix for the
  bug class behind the original plan-dispatch failure.
- **No-progress / duplicate-call guard** — within a turn, an identical tool call
  (same name + args) is run once; later repeats are short-circuited and handed
  the cached result with a "don't repeat — use it, change approach, or answer"
  nudge (`_seen_calls` + `_call_signature`). Fixes the "fetch the same URL 5×"
  loop. Emits `agent.duplicate_call`.
- **Answer general knowledge directly** — the system prompt now carves out an
  exception to the execute-don't-discuss rule: definitions / acronym expansions /
  facts the model already knows are answered in plain text without tools, and a
  blocked/failed lookup must fall back to the model's own knowledge rather than
  be reported as the final answer (fixes the "what does VM stand for?" run that
  over-tooled and then parroted a robots.txt refusal).
- **nmap target enforcement** — `_apply_arg_fallbacks` backfills `target` from
  attack state when the model omits it; the system prompt also mandates it.
- **Rules-of-Engagement guardrails (feature J)** — an optional `scope.json`
  (`--scope`, mirrors `mcp.json`) defines the engagement: an in-scope target
  allowlist (IPs/CIDRs via `ipaddress`, hostnames with subdomain match), plus
  forbidden tools and forbidden argument patterns. The gate runs in the dispatch
  path — in the controller's `_execute_tool_calls`, **after** `_apply_arg_fallbacks`
  so the backfilled target is checked — and **refuses** an out-of-scope/forbidden
  call before it runs: it's never dispatched, the refusal is fed back to the
  model, and `agent.scope_refused` fires (the first input to a future audit log).
  A defense-in-depth re-check in `ToolDispatcher` covers generated-tool shell
  calls that bypass the controller; sub-agents inherit the scope so delegation
  stays bounded. **Inactive when no `scope.json` is present**, so default
  behavior is unchanged. Loopback / local utility calls allowed by default. Host
  extraction favors precision (IPs from any arg; bare hostnames only from
  target-shaped keys / URLs) to avoid mistaking a wordlist path for a target.
  CLI shows a startup banner, a `/scope` command, and a live `⛔ RoE: refused …`
  line. `core/engagement_scope.py`; example in `scope.example.json`.
- **Auditable engagement log (feature K)** — an append-only JSONL trail
  (`core/engagement_log.py`, `EngagementLog`) of the whole session, fed purely by
  the `EventBus` (it subscribes, never drives). Records every tool call (with
  args + outcome), finding (flag/credential/vuln/open-port), and RoE refusal,
  plus delegate/verify/duplicate events — a curated topic allowlist, one flushed
  line per record (crash-safe), frozen after `close()`. Two small controller
  emits make it faithful: `task.result`/`.error` now carry `args`, and
  `_emit_new_findings` fires `agent.finding` when the attack state gains a
  flag/cred/vuln/port (so the trail records *when* each was found). On by default
  (writes to `engagements/`, gitignored; `--no-engagement-log` to disable);
  `export_markdown()` renders a findings list + timeline (the seed for reporting,
  L). CLI: startup path, exit summary, `/log` and `/log export`.
- **Automated reporting (feature L)** — `reporting/report_builder.py` turns the
  engagement log (K) records + the attack-state blackboard into a structured
  pentest report: findings for vulns, captured credentials, notable exposed
  services (telnet/SMB/RDP/Redis/…), and flags, each with a severity and concrete
  remediation; first-seen timestamps from the log; an executive-summary severity
  tally; a methodology timeline; a tool-activity appendix. **Deterministic and
  offline** — no LLM call, so it is reproducible, testable, and never sends
  findings to a third party (the local-first OPSEC story holds end to end). An
  LLM narrative pass and precise CVSS scoring (feature M) are layered
  enhancements. Markdown + self-contained HTML export (PDF = print the HTML);
  optional secret redaction. CLI: `/report [md|html|both]` → `engagements/`.
- **Attack system prompt** — explicit intent→tool mapping table and a default
  recon → enumerate → exploit → post → report workflow that blocks exploitation
  before a scan returns open ports.

---

## HTB benchmark — issue tracker

| # | Issue (first run) | Status |
|---|---|---|
| 1 | Machine IP changed mid-session | ✅ Fixed — new IP overrides target + clears stale state |
| 2 | `nmap_scan` called without `target=` | ✅ Handled — arg backfill + prompt enforcement |
| 3 | Ollama XML error, 33 schemas overflow | ✅ Handled — phase-based tool subsetting |
| 4 | Metasploit attempted before scan | ✅ Mitigated — phase gating + workflow prompt |
| 5 | No open ports found | ✅ Was a symptom of #1 (scanning the dead IP) |

`max_context_tokens` is already `16384` (default in `context_builder.py` and the
`AgentController` constructor).

### Next run

```powershell
python -m cli --model qwen2.5:14b
you > target is 10.129.x.x — nmap scan with -Pn flag
```

Note: `--strategy` is live (per-role routing). `--no-verifier` is still inert
(the verifier step is Phase 8). With multiple tool-capable models installed,
`--strategy pipeline` will run the loop on the fastest one.

---

## What's left

The feature roadmap (A–S) is essentially complete. What remains is **proof and
breadth**, not core subsystems:

```
PROOF (the dominant open item)
   [ ] Solve-rate LIFT measurement — the whole loop/capability wave is UNMEASURED.
       Needs a capable PAID model + enough benchmarks: baseline vs
       `benchmark_xbow.py --strategy swarm --fanout --reflect --attempts N`.
       (grok-4 ~12% too weak; the $2–3 budget so far is insufficient for signal.)
   [ ] Live validation of the non-web domains (cloud / binary-pwn / mobile / AD)
       against real targets — the playbooks + operators are built and unit-tested
       but exercised only on web so far. Browser tool IS live-verified; sqlmap/ffuf
       still need live runs.

SMALL DEFERRED (ROADMAP)
   [ ] G 🟡 — end-to-end verification against a real OpenRouter/Nous key.
   [ ] Generated-tool startup loader (verify manifests/checksums at boot).
   [ ] CLI fully consumes MapacheConfig (replace scattered args.*) + a config command.
   [ ] Per-target execution backend; RAG over the vector store; ExploitDB feed.

Phase 9 🟡  Voice + Hardware + Mobile
   [x] Voice I/O — voice/voice_io.py (2026-06-28): TTS/STT behind a null default;
       optional pyttsx3 + faster-whisper; VoiceManager + --voice/--say + config.voice.
   [ ] Hardware — arduino_controller / wifi_camera_controller. DEFERRED: needs a
       physical board/camera to verify (no device in-env).
   [ ] Mobile — ios_api_bridge. DEFERRED: Telegram/Discord already cover remote op.
```
