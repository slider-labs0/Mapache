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

## C. Setup wizard + config layer  ✅  ← shipped (C0 2026-06-10, C1 2026-06-15)
The config layer is the shared foundation C and G both stand on. Today there is
**no config file** — settings come from argparse + a few `os.environ` reads. MCP's
`load_mcp_config(mcp.json)` is the precedent to mirror.

**Scope decisions (2026-06-10):**
- **Config home: global + project override.** Secrets/providers live in user-global
  `~/.mapache/config.json`; an optional project-local `mapache.json` overrides
  non-secret prefs. Precedence: **CLI flag > project > global > env > built-in
  default**. Keys stay out of repos.
- **Secrets: plaintext in the user-dir JSON + `${ENV_VAR}` interpolation.** A value
  like `"${OPENROUTER_KEY}"` is resolved from the environment at load, so the
  security-conscious can keep keys in env only; others can paste them into the
  user-dir file (chmod 600 / documented .gitignore). No keyring dependency.
- **Full wizard now** (not just the loader): detect Ollama + offer to pull a default
  model, check optional bins, prompt provider keys + Telegram/Discord tokens, write
  the config, and smoke-test.

**C0 — config loader (`core/config.py`):**  ✅ shipped 2026-06-10
- [x] Typed load/merge across the precedence chain (CLI > project > global > env >
      default); `${ENV}` interpolation (unresolved → empty, never a literal token);
      `MapacheConfig` / `ProviderConfig` / `MessagingConfig` typed view.
- [x] Schema: `providers` (ollama + openrouter + nous entries with base_url, key,
      model list, enabled), `default_model`, `default_strategy`, `allow_cloud`,
      `max_vram_gb`, `messaging` tokens. Helpers: `provider_for_model`,
      `cloud_models`, `usable_providers`, `ollama_url`.
- [x] Fail-soft file loads; `redacted()` for display. Tests: 5 in `tests/test_core.py`.
- [ ] CLI consumes `MapacheConfig` (replace scattered `args.*`) and `mapache config
      show` — lands with the C1 subcommand layer / G bootstrap, not standalone.

**C1 — wizard (`cli/setup_wizard.py`, `mapache setup`):**  ✅ shipped 2026-06-15
- [x] Detect/validate Ollama, offer to pull a default model; check optional bins
      (nmap, msfconsole, john, tor, …) and report what's missing.
- [x] Prompt for provider API keys (OpenRouter, Nous — G) + exposed model ids and
      Telegram/Discord tokens; write them to `~/.mapache/config.json`.
- [x] Smoke-test one turn against the chosen default model; idempotent re-run that
      shows each current value as the default and preserves secrets on Enter.
- [x] Subcommand layer in `cli/mapache_cli.main()`: `setup` + `config show|path`
      dispatched before the REPL flag parser (bare `python -m cli` unchanged).
      Config writers `load_global_raw`/`save_global_config` (raw-edit so `${ENV}`
      placeholders survive; 0600 perms).
- [x] **REPL consumes `MapacheConfig`.** `MapacheCLI.__init__` resolves
      model/strategy/ollama_url/max_vram/allow_cloud through `load_config` with a
      sparse `_cli_overrides` layer, so a wizard-saved `default_model` takes
      effect on a bare `python -m cli` launch while an explicit flag still wins.
      Config-backed flags default to `None` (env vars now flow through the config
      env layer, fixing precedence to CLI > project > global > env). Tests: 4 in
      `tests/test_core.py`.
- Touchpoints: `core/config.py` (writers), `cli/setup_wizard.py`,
  `cli/mapache_cli.py` (subcommand dispatch + config-driven REPL).

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

## G. More LLM providers — OpenRouter + Nous Portal  🟡  ← core shipped 2026-06-11
Only `providers/ollama_provider.py` exists, and `ModelPool.get()` hardcodes it.
The routing layer is already cloud-aware (`local_only`, HYBRID,
`_best_cloud_for_role`) and the `Provider` enum already lists OPENROUTER/OPENAI/
ANTHROPIC — so the gap is just the provider class + a provider-aware pool, fed by
the config layer (C0).

**Scope decisions (2026-06-10):**
- **One `OpenAICompatibleProvider`, two config entries.** OpenRouter and Nous are
  both OpenAI `/chat/completions`-shaped; they differ only by `base_url` + key, so
  one class covers both (base URLs configurable, since Nous's endpoint isn't pinned).
- **Normalize to the existing shape.** The provider translates OpenAI's
  `choices[0].message` into the `{"message": {...}}` dict the controller already
  parses (`raw["message"]["tool_calls"]/["content"]`) — a true drop-in, no
  controller changes. SSE streaming reassembled the same way for `chat_stream`.
- **Fix `ModelProfile.is_local`.** It currently returns True when
  `cost_per_1k_tokens == 0.0`, so a *free* cloud model would bypass `--allow-cloud`.
  Tighten to `provider == Provider.OLLAMA` so the OPSEC gate actually holds.
- **Warn, don't block (OPSEC).** Startup banner when any cloud model is active for a
  role; a one-time per-session warning the first time a call routes to a cloud
  provider (`RoutedModel` emits `model.cloud_call`; CLI prints the warning).

- [x] `models/providers/openai_compatible.py` — `OpenAICompatibleProvider` matching
      the OllamaProvider surface; normalizes to `{"message": {...}}`; SSE streaming.
- [x] Provider-aware `ModelPool` — builds the right provider per model id from the
      config's provider entries; Ollama-only without a config.
- [x] Cloud `ModelProfile`s registered from config (`_register_cloud_models`) so
      routing + the `local_only`/`--allow-cloud` gate see them; CLI bootstrap takes
      a cloud-primary path (no "is Ollama running" gate) and refuses a cloud primary
      unless `--allow-cloud` + a key are present. `is_local` fixed (local == Ollama).
- [x] OPSEC warning wiring — startup banner (`_warn_cloud_roles`) for any cloud
      role + one-time per-session warning on first cloud call (`RoutedModel.on_cloud_call`).
- [ ] **Remaining:** end-to-end verification against a real OpenRouter/Nous key
      (can't be tested until a key is configured) — local bootstrap re-verified via
      the create_tool smoke. C1 wizard will prompt for the keys.
- Touchpoints: `models/providers/openai_compatible.py`, `models/model_pool.py`,
  `models/routed_model.py`, `models/model_registry.py`, `cli/mapache_cli.py`,
  `core/config.py`.

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

# Differentiators vs Hermes Agent (J–P)

Hermes Agent (Nous Research, Feb 2026) is the general-purpose analogue of much of
A–I: self-improving skills, layered memory, multi-platform, model-agnostic. We do
**not** out-general it. Mapache's edge is depth where a generic assistant
structurally won't follow: **offensive security + local-first OPSEC + auditable,
signed artifacts.** J–P are the features that widen that gap.

> **Status: J–P all ✅ shipped (2026-06-19 → 2026-06-26)** on branch
> `feature/agent-loop-upgrades`. Suite 72/72. The A–I foundation still has open
> items — see each section (unstarted: B, D, E, F, H, I; G core done).

## J. Rules-of-Engagement guardrails  ✅  ← shipped 2026-06-19
Authorized-pentest scoping the agent enforces itself.

- [x] Engagement scope (`core/engagement_scope.py`): in-scope target allowlist
      (IPs/CIDRs via `ipaddress`, hostnames with subdomain match) + forbidden
      tools + forbidden arg patterns. Loaded per engagement from `scope.json`
      (`--scope`, mirrors `mcp.json`); fail-soft + **inactive when absent** so
      existing behavior is unchanged until limits are defined. Loopback/local
      utility calls allowed by default (`allow_loopback`). Example:
      `scope.example.json`.
- [x] Enforced in the dispatch path. Primary gate is in the controller's
      `_execute_tool_calls`, **after `_apply_arg_fallbacks`** so the backfilled
      `target` is checked too; refused calls are never dispatched, the refusal is
      fed back to the model, and `agent.scope_refused` is emitted on the bus
      (first raw material for K). Defense-in-depth re-check in `ToolDispatcher`
      catches generated-tool shell calls that bypass the controller gate.
      Sub-agents inherit the scope, so delegation stays bounded.
- [x] CLI: `--scope`, startup banner (`RoE: ENFORCED …`), `/scope` command, and a
      live `⛔ RoE: refused …` line on each refusal. Host extraction favors
      precision (IPs from any arg; bare hostnames only from target-shaped keys /
      URLs) so a wordlist path isn't mistaken for a target. Tests: 6 in
      `tests/test_core.py` (5 unit + 1 controller-gate).
- Touchpoints: `core/engagement_scope.py` (new), `core/agent_controller.py`,
  `tools/tool_dispatcher.py`, `cli/mapache_cli.py`, `scope.example.json`.

## K. Auditable engagement log  ✅  ← shipped 2026-06-19
A structured, timestamped, exportable trail of everything the agent did.

- [x] Append-only JSONL trail (`core/engagement_log.py`, `EngagementLog`) fed by
      the `EventBus`: every tool call (with args + outcome), finding
      (flag/cred/vuln/port), and RoE refusal, plus delegate/verify/duplicate
      events. Subscribes to a curated topic allowlist (signal, not noise); each
      line is flushed (crash-safe) and frozen after `close()` (an audit trail
      isn't retro-edited).
- [x] Two small controller emits make the trail faithful: `task.result`/`.error`
      now carry `args`, and `_emit_new_findings` fires `agent.finding` for newly
      discovered flags/creds/vulns/ports (timestamps *when* each was found, which
      the attack-state snapshot can't). This is also where J's
      `agent.scope_refused` lands.
- [x] Exportable: `export_markdown()` renders a findings list + readable timeline
      — the seed L (reporting) builds on. CLI: on by default (writes to
      `engagements/`, gitignored), `--no-engagement-log` to disable, `/log` and
      `/log export` commands, path shown at startup + summary on exit.
- [x] Tests: 2 in `tests/test_core.py` (log capture/JSONL/export + controller
      emits). Suite 47/47.
- Touchpoints: `core/engagement_log.py` (new), `core/agent_controller.py`
  (`task.result` args + `agent.finding`), `cli/mapache_cli.py`, `.gitignore`.

## L. Automated reporting / deliverables  ✅  ← shipped 2026-06-19
Turn the `reporting` phase into an actual pentest report.

- [x] `reporting/report_builder.py` (`build_report`, `EngagementReport`,
      `Finding`): structured report from the engagement log (K) records + the
      attack-state blackboard. Findings for vulns, captured credentials, notable
      exposed services (telnet/SMB/RDP/Redis/…), and flags, each with a severity
      and concrete remediation; first-seen timestamps wired from the log;
      executive-summary severity tally; methodology timeline; tool-activity
      appendix.
- [x] **Deterministic + offline** — no LLM call, so it is reproducible, testable,
      and never sends findings to a third party (local-first OPSEC holds end to
      end). An LLM narrative pass and precise CVSS scoring (via M) are layered
      enhancements, not prerequisites.
- [x] Markdown + self-contained HTML export (PDF = print the HTML; a weasyprint
      backend can drop in later, kept dependency-free). Optional secret redaction.
      CLI `/report [md|html|both]` writes to `engagements/`. Tests: 2.
- Touchpoints: `reporting/` (new), `cli/mapache_cli.py`; consumes K records +
  `AttackState`.

## M. Exploit / CVE grounding  ✅  ← shipped 2026-06-25
Recon → prioritized attack plan, not just raw scan output.

- [x] Correlate discovered service versions → known CVEs/exploits. Shipped as an
      **offline, deterministic** core (`core/cve_grounding.py`): a curated
      in-process `CVE_CATALOG` (CVSS + exploit availability + bulletin aliases),
      `ground_services()` prioritizing version-confirmed > CVSS > exploit-available,
      `lookup()`/`severity_for_cve()`, `attack_plan()`, and a `cve_lookup` meta-tool
      — deeper than a one-off `searchsploit` call.
- [x] Feed correlations into attack-state vulns + the suggested-next-step logic.
      `AttackState.versions` captures nmap -sV banners; version-confirmed CVEs are
      auto-added to `vulnerabilities` and surfaced in `suggest_next_step`. Report
      (L) now scores CVE findings by real CVSS. CLI `/cve`. Tests: 3.
- [ ] Deferred (layered enhancements behind `ground_services()`/`lookup()`): a live
      NVD/ExploitDB feed + RAG over the vector store. Kept default-offline so scan
      output never leaves the box just to be scored (OPSEC, ties O).
- Touchpoints: `core/cve_grounding.py` (new), `core/conversation_chain.py`,
  `reporting/report_builder.py`, `cli/mapache_cli.py`.

## N. Skill synthesis from exploit chains  ✅  ← shipped 2026-06-24  (extends A + I)
Close the self-improvement loop, the offensive way.

- [x] After a successful chain (recon→vuln→exploit→root), the agent auto-authors a
      reusable tool via `create_tool` that replays it. `core/skill_synthesis.py`
      (`synthesize_from_log` / `persist_skill` + `synthesize_skill` meta-tool):
      the logged chain (K) up to the first flag becomes a parameterized replay
      tool with the target swapped for `__TARGET__`; non-runnable steps survive in
      the methodology. CLI `/synthesize`.
- [x] Hub **signing/provenance** lives here (extends I's checksum-only safety to
      signatures): `core/provenance.py` — dependency-free HMAC-SHA256 over the
      code sha256, per-machine key (`~/.mapache/skill_key`, 0600), `sign()/verify()`
      surface ready for an ed25519 swap when the hub (I) lands. Synthesized skills
      are signed at birth. Tests: 1.
- Touchpoints: `core/skill_synthesis.py` (new), `core/provenance.py` (new),
  `tools/generated_tool*.py` (A), `core/engagement_log.py` (K).

## O. Hybrid OPSEC routing  ✅  ← shipped 2026-06-24  (extends G)
Make "target data never leaves the box" a guarantee, not a warning.

- [x] Sensitive work is **pinned to a local model** even when cloud is allowed —
      enforced at the delegation boundary (P), not left to a warning.
      `core/opsec_routing.py` (`OpsecPolicy.decide()`, pure logic): pins when the
      operator is OPSEC-sensitive (`Operator.prefer_local`) OR credentials are in
      the shared attack state; no-op when cloud is disabled. Only recon/osint/web/
      analyst are cloud-eligible.
- [x] Builds on G's provider awareness: `RoutingEngine.local_clone()` (local-only
      sibling) + `RoutedModel.local_variant()` (shares the pool). Controller pins
      the child model at `_spawn_and_run`, inherits the policy to children, tags
      `delegate.start` (K records it). CLI `/opsec`. Tests: 3.
- Note: the lead's own cloud use is unchanged (its `--allow-cloud` choice + the G
  warn hook); O governs delegations — by design.
- Touchpoints: `core/opsec_routing.py` (new), `models/routing_engine.py`,
  `models/routed_model.py`, `core/agent_controller.py`, `cli/mapache_cli.py`.

## P. Multi-agent engagement orchestration  ✅  ← fully shipped 2026-06-26 (Decepticon-inspired)
Specialist sub-agents coordinated by a lead over a shared blackboard.

- [x] **Shared attack-state blackboard** (1/3). Sub-agents reference the lead's
      `AttackState` directly (`shared_state` + `allow_state_reset`), so findings
      are live with no copy-down/merge-back; `_merge_subagent_state` removed. A
      shared event bus means operator actions land in the engagement log (K).
      Parallel-safe (asyncio-atomic mutations); dispatch sequential for now.
- [x] **Operator specialists** (2/3, `core/operators.py`). Decepticon-style
      roster: recon/web/exploit/post + osint, cloud_hunter, contract_auditor,
      reverser, analyst, phisher, mobile/wireless/iot/ics operators,
      forensicator, supply_chain. `delegate(task, operator=…)` runs the subtask
      with the operator's **focused prompt + small curated tool subset** (the
      local-model win); domain tooling runs via kali_run/shell or create_tool.
      Role constraints (read-only, RoE-gated, needs-hardware, deconflict-first)
      render into the prompt and reinforce J.
- [x] **Surfacing** (3/3). `/operators` roster, `delegate` enum, attack-state
      `suggest_next_step` nudges the right specialist from open ports/services
      (`suggest_operators`). Tests: 4 in `tests/test_core.py`.
- [x] **Parallel fan-out** (`delegate_parallel`): runs several operators
      concurrently (`asyncio.gather`) over the shared blackboard, capped at
      `MAX_FANOUT`. A correctness win now (single-GPU serializes at the provider),
      a wall-clock win once cloud routing (G) serves calls concurrently. Same-host
      / multi-angle by design — children share one AttackState.
- [x] **Per-host sub-states** for true multi-host engagements (shipped 2026-06-26).
      `delegate`/`delegate_parallel` tasks accept a `target`; a task whose host
      differs from the lead's gets an isolated `AttackState` (created once, reused)
      so parallel multi-host sweeps don't collide on one blackboard. `host_states()`
      + `_render_host_states()` roll-up; CLI `/hosts`. Tests: 2.
- [x] **Per-operator model routing** (shipped 2026-06-26). Each operator runs its
      loop under the model ROLE its work needs — reasoning-heavy specialists as
      PLANNER (quality model), action ones as EXECUTOR (fast). `Operator.model_role`
      + `RoutedModel.for_role()`, applied after the O OPSEC pin. Tests: 2.
- Touchpoints: `core/agent_controller.py`, `core/conversation_chain.py`,
  `core/operators.py` (new), `core/engagement_log.py`, `cli/mapache_cli.py`.

---

## Suggested ordering (dependencies)

1. **C (setup)** + **G (providers)** — providers need key storage; do together.
2. **E (soul.md)** + **F (user.md)** — small, high value, share the inject path.
3. **B (nicer CLI)** — independent, improves everything else's UX.
4. **H (SSH/Docker)** — backend refactor; isolate before it touches many tools.
5. **A (self-authored tools)** — safety-sensitive; needs the confirm/flag plumbing.
6. **I (community hub)** — depends on A's tool-install path + MCP config.
7. **D (update manager)** — last; benefits from a settled file layout.

**Differentiators (J–P)** — ✅ ALL SHIPPED (J→K→L→N→O→M→P, 2026-06-19 → 06-26).
Original leverage-vs-effort ranking, for the record:
1. **J (RoE guardrails)** — cheap, high-trust, unlocks safe autonomy; builds on attack-state.
2. **K (engagement log)** — cheap (subscribe to the bus); compounds into L + N.
3. **L (automated reporting)** — high client value, medium effort; needs K.
4. **N (skill synthesis) + I signing** — the network-effect play; extends A + I.
5. **O (hybrid OPSEC routing)** — the defining guarantee; extends G.
6. **M (CVE grounding)** and **P (multi-agent orchestration)** — higher effort, done last.
