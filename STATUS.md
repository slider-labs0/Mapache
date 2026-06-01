# Mapache — Phase Status

> Offensive-security AI agent. Local-model (Ollama) ReAct loop with phase-aware
> attack-state tracking, a 33-tool offensive toolchain, persistent memory, and
> Telegram/Discord operation.

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

**Not yet wired:** a verifier/reflection step. `verifier_score` exists in the
registry and the VERIFIER role routes correctly, but no turn currently issues a
verifier call. `--no-verifier` remains inert until that lands (see Phase 8).

---

## Current tool count: 33

```
shell, file_read, file_write, file_edit, file_list, file_search,
nmap_scan, web_fetch, web_search, tor_fetch,
msf_search, msf_run, msf_sessions,
burp_scan, burp_proxy,
john_crack, john_identify,
kali_list, kali_run, searchsploit,
memory_recall, memory_save, memory_note_create,
memory_note_search, memory_note_list,
memory_target_store, memory_target_get,
moltbook_register, moltbook_status, moltbook_post,
moltbook_feed, moltbook_comment, moltbook_search
```

---

## Key behaviors

- **ConversationChain** tracks attack state (target, open ports, services, phase,
  vulns, credentials, flags) across turns. A freshly typed IP that differs from
  the current target overrides it and clears stale findings (handles HTB machine
  IP reassignment mid-session). Rescan keywords clear cached ports. Tool outputs
  are compressed before re-injection to prevent context overflow.
- **Phase-based tool subsetting** (`ConversationChain.active_tool_names`) exposes
  only the tools relevant to the current attack phase, keeping the function-
  calling payload small enough for local models (avoids the Ollama tool-schema
  overflow). This — not `--no-verifier` — is the fix for the 33-schema overflow.
- **nmap target enforcement** — `_apply_arg_fallbacks` backfills `target` from
  attack state when the model omits it; the system prompt also mandates it.
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

```
Phase 8 ⬜  Verifier / reflection — issue a VERIFIER-role call after a turn
              (or on empty/error tool output) to catch dead ends and retry.
              Routing for the role is already in place; default-on vs opt-in
              is an open decision (latency vs reliability).

Phase 9 ⬜  Voice + Hardware + Mobile
              voice/speech_to_text.py     (Whisper)
              voice/text_to_speech.py     (Coqui/ElevenLabs)
              hardware/arduino_controller.py
              hardware/wifi_camera_controller.py
              mobile/ios_api_bridge.py
```
