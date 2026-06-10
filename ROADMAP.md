# Mapache — Feature Roadmap (post-Phase-8)

> New feature backlog requested 2026-06-08. Grounded against the current
> single-execution-path architecture (`core/agent_controller._agent_loop`).
> `STATUS.md` remains the source of truth for *shipped* phases; this file tracks
> *planned* work. Move an item into `STATUS.md` once it lands.

Legend: ⬜ not started · 🟡 in progress · ✅ done

## Scope decisions (2026-06-08)

- **Audience: built to be shared.** Setup (C), updater (D), and hub (I) are real
  product scaffolding, not local convenience. Implies a config layer, a versioned
  update channel, and eventually pushing to a remote. Design clean, shareable
  abstractions now.
- **Cloud posture: warn, don't block.** Cloud providers (G) and remote exec (H)
  are allowed freely, but Mapache shows a visible warning whenever target/exploit
  data is about to leave the local machine. No hard offline gate.
- **CLI: Rich (enhanced scroll), not Textual.** Keep the scrolling REPL +
  background-stdin steering reader; add panels/color/live tokens on top.
- **Build order: A first.** Self-authored tools, designed so the artifact is
  hub-installable from day one (A and I share one package format).

---

## A. Self-authored tools (Hermes-style)  ✅  ← shipped 2026-06-08
Let the model write, register, and persist a brand-new tool at runtime. The
persisted artifact is **hub-installable from day one** (same package the hub (I)
distributes — A and I share one format).

**Package format** — one directory per tool under a tools home:
```
plugins/generated/<tool_name>/
  tool.py        # generated body, templated into a GeneratedTool(BaseTool)
  manifest.json  # name, version, description, args schema, origin, author,
                 # created, last_used, use_count, deps, sha256(tool.py)
```

**Trust model (resolves the "is generated code dangerous?" question):**
- `origin: "self"` — authored locally by the agent. Trusted at the same level as
  the rest of Mapache (which already runs arbitrary shell/exploits). Loads freely.
- `origin: "hub"` — downloaded third-party code. Checksum-verified against the
  manifest; stays **dormant** until explicitly enabled. This is where the real
  gate lives — verify strangers, trust your own agent.

**Code contract (decision: templated body, not a full file):** the model supplies
the body of `async def run(self, args) -> str`; we template it into a
`GeneratedTool(BaseTool)` subclass. Reason: local models mangle whole files, and a
fixed contract makes validation + the hub format uniform. The body gets a small
documented surface — `await self.shell(cmd)` routed through `core/executor.py`
(so generated tools inherit the SSH/Docker backends from H for free) plus stdlib.
Exceptions are caught and the traceback handed back to the model to self-correct
(same philosophy as the reask loop).

**Exposure (decision: phase-tagged):** `create_tool` takes an optional `phase`
(default = current phase); the tool joins that phase's set so it respects the
existing phase-based subsetting. This keeps the function-calling payload small
even once a library of dozens accumulates (critical once the hub exists) — avoids
re-triggering the 33-schema overflow.

**Invocation (decision: next-turn):** a freshly created tool lands, registers, and
appears in the *next* turn's tool list — the model does not dispatch a tool that
was registered mid-turn. Simpler and safer for v1; revisit if the round-trip
feels sluggish in practice.

**Curator (tiered GC for self-authored tools):** the create-tools loop only adds,
so without curation the library bloats, fills the schema budget, and collects dead
one-off experiments. The curator moves tools through a reversible lifecycle —
**active → stale → archived** — and only the capability-removing step needs
permission.

Manifest carries `state: active | stale | archived` (+ `last_used`, `use_count`,
`state_changed`). The dispatcher bumps `last_used`/`use_count` on every generated-
tool run.

- **active → stale** (automatic, non-destructive): a usage rule demotes a tool
  (defaults: *never used* and >7 days old; or *unused* 30 days). It's just a label
  — the tool stays loaded and callable. **Using a stale tool auto-promotes it back
  to active**, so a rule that fires too early self-corrects.
- **stale → archived** (the permissioned step): `curate_tools` / `/curate` presents
  stale tools with a per-tool reason ("created 2026-06-01, never called") and asks
  the user per item via the existing confirm mechanism. On approval the tool's
  folder **moves to `plugins/archived/`**, it is unregistered, and it drops out of
  the startup load path. Rejected tools stay stale and get a `state_changed` touch
  so they aren't re-proposed immediately.
- **archived → active** (restore): `/restore <tool>` (or agent request) moves the
  folder back and re-registers it. Nothing is lost by archiving.
- **delete** is separate and explicit — only operates on already-archived tools
  (`tool_purge`), so a hard delete is always a deliberate two-step act.
- Trigger: `/curate`, plus a non-blocking startup notice ("N stale tools —
  review? /curate") when stale tools exist or the count exceeds a threshold. Never
  archives or deletes automatically. Primarily targets `origin: "self"`; `hub`
  tools are only flagged stale if never used since install.
- Stretch: near-duplicate detection (same description/args → flag the older,
  less-used one).

- [x] `create_tool(name, description, parameters, code, phase?)` — validates name
      (collision + snake_case), validates the JSON-schema arg object, `compile()`s
      the code (errors returned to the model), writes tool.py + manifest.json, and
      registers live. (`tools/generated_tool.py`, `tools/generated_tool_manager.py`)
- [x] `tool_list_generated` (name/origin/state/phase/use_count) and `tool_delete`
      (soft — archives, reversible).
- [x] Startup loader: `GeneratedToolManager.load_all()` scans the library, verifies
      `hub` checksums, registers fail-soft, and applies the staleness rule.
- [x] **Curator (active → stale → archived):** GeneratedTool self-tracks
      `last_used`/`use_count` and auto-promotes stale→active on use; `refresh_states`
      auto-demotes active→stale; `/curate` proposes stale→archived (folder moves to
      `plugins/archived/`, unregistered) per-tool with user approval; `/restore` and
      `/purge` round it out; startup notice when stale tools exist.
- [x] Phase-tagged exposure via `ConversationChain.generated_tools`; meta-tools in
      `CORE_TOOLS`. Tests: 5 in `tests/test_core.py`.
- Not done (deferred): `--allow-tool-creation` gate (authoring is on for self-use,
      consistent with "trust your own agent"); near-duplicate detection stretch.
- [ ] Startup loader: scan the tools home, verify manifests (+ checksum for
      `hub` origin), register fail-soft (a bad tool never breaks startup, per the
      MCP precedent). `hub` tools failing checksum/enable show as "needs review".
- [ ] Tag generated tools in `/tools`; `--allow-tool-creation` flag still gates
      whether the *agent* may author tools at all (default on for self-use).
- Touchpoints: `plugins/sdk/base_tool.py`, `tools/tool_registry.py`,
  `tools/tool_dispatcher.py`, `tools/tool_schema.py`, `core/agent_controller.py`,
  `core/conversation_chain.py` (phase sets / always_tools), `core/executor.py`.

## B. Nicer CLI  ⬜
Upgrade `cli/mapache_cli.py` from line-printing to a real TUI surface.

- [ ] Adopt `rich` (panels, tables, syntax highlight, spinners) — render the
      `=== TASK LIST ===` block as a live panel, tool calls as cards.
- [ ] Streamed tokens rendered in a live region (hook the existing `on_token`).
- [ ] Color-coded phase banner (recon/enum/exploit/post/report) + target/ports
      status line pulled from `ConversationChain`.
- [ ] Keep a `--plain` fallback for piping / dumb terminals.
- Touchpoints: `cli/mapache_cli.py`, `core/logger.py`.

## C. Setup wizard  ⬜
First-run `mapache setup` that gets a fresh machine ready.

- [ ] Detect/validate Ollama, pull a default model, check optional bins
      (nmap, msfconsole, john, tor).
- [ ] Prompt for + store provider API keys (OpenRouter, Nous — see G) and
      Telegram/Discord tokens into a config file (not committed).
- [ ] Write a starter `mapache.json` / `.env`; verify with a smoke test turn.
- [ ] Idempotent re-run that reports what's already configured.
- Touchpoints: new `setup/` or `cli/setup_wizard.py`, config loader.

## D. Update manager  ⬜
Keep an installed Mapache current.

- [ ] `mapache update` — check current vs latest (git tag / VERSION file),
      show changelog, `git pull` or download + apply.
- [ ] Version stamp (`VERSION`) + `mapache --version`; startup "update available"
      notice (non-blocking).
- [ ] Back up config before updating; dependency-drift check (`pip install -r`).
- Touchpoints: new `core/updater.py`, `VERSION`, CLI entry.

## E. `soul.md` — user-editable persona  ⬜
A human-owned file that shapes the agent's personality/values/voice.

- [ ] Load `soul.md` and inject it into the system prompt (same mechanism as
      `MAPACHE.md` via `project_context.py`).
- [ ] Hot-reload each turn so edits take effect without restart.
- [ ] Ship a documented default; `/soul` command to print/open it.
- Touchpoints: `core/project_context.py`, `core/context_builder.py`.

## F. `user.md` — agent-maintained user profile  ⬜
Agent records what the user has done / prefers over time.

- [ ] Agent-callable tool to append/update durable user facts (engagements run,
      targets, habits, preferences) to `user.md`.
- [ ] Inject a compact summary into the prompt for continuity (distinct from
      attack-state `ConversationChain` and from `soul.md`).
- [ ] Dedup / size-cap so it doesn't grow unbounded (reuse compaction ideas).
- Touchpoints: `memory/` (new store), `core/context_builder.py`.

## G. More LLM providers — OpenRouter + Nous Portal  ⬜
Currently only `providers/ollama_provider.py` exists.

- [ ] `providers/openrouter_provider.py` and `providers/nous_provider.py`
      implementing the same provider facade (chat, streaming, tool-calling).
- [ ] Register them in `models/model_pool.py` / `routed_model.py` so the routing
      engine can pick them; honor `--allow-cloud` for any non-local provider.
- [ ] Key handling via the setup wizard (C); model-id namespacing per provider.
- [ ] Update `model_registry.py` role scores to know about the new model ids.
- Touchpoints: `models/providers/`, `models/model_pool.py`,
  `models/routed_model.py`, `models/model_registry.py`.

## H. Remote execution — SSH + Docker  ⬜
Run tools/commands somewhere other than the local shell.

- [ ] Execution-backend abstraction behind `core/executor.py` (local / ssh /
      docker) so `shell_tool` and other bins dispatch through it.
- [ ] SSH backend (paramiko or `ssh` subprocess): host/key config, run the
      offensive toolchain from a remote box.
- [ ] Docker backend: run a command inside a named/ephemeral container (e.g. a
      Kali image), stream output back.
- [ ] Surface the active backend in the CLI status line; per-target backend.
- Touchpoints: `core/executor.py`, `security_tools/shell_tool.py`, config.

## I. Community hub — downloadable skills  ⬜
Browse + install community "skills" (tools / prompt packs / MCP configs).

- [ ] Define a skill manifest format (name, version, type, deps, checksum).
- [ ] Hub client: `skill_search` / `skill_install` / `skill_list` against a
      registry (URL or GitHub repo index to start).
- [ ] Install into the right home: generated tool (A), MCP server entry
      (`mcp.json`), or prompt/persona pack.
- [ ] **Safety** — checksum + signature verify, sandbox review before enabling,
      explicit confirm (installs run third-party code).
- Touchpoints: new `hub/`, ties into A (tools), MCP config, `soul.md`.

---

## Suggested ordering (dependencies)

1. **C (setup)** + **G (providers)** — providers need key storage; do together.
2. **E (soul.md)** + **F (user.md)** — small, high value, share the inject path.
3. **B (nicer CLI)** — independent, improves everything else's UX.
4. **H (SSH/Docker)** — backend refactor; isolate before it touches many tools.
5. **A (self-authored tools)** — safety-sensitive; needs the confirm/flag plumbing.
6. **I (community hub)** — depends on A's tool-install path + MCP config.
7. **D (update manager)** — last; benefits from a settled file layout.
