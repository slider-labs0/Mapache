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

## B. Nicer CLI  ✅  ← shipped 2026-06-27
Upgrade `cli/mapache_cli.py` from line-printing to a real TUI surface.

- [x] Adopt `rich` (panels, colour, styled streaming) behind a `Renderer`
      abstraction (`cli/render.py`): `RichRenderer` draws the agent response as a
      panel and the meta line dimmed; `PlainRenderer` preserves the exact historical
      output. `rich` is an OPTIONAL dependency — absent, the plain path is chosen
      automatically. The TASK-LIST renders as a status-coloured panel after each
      turn (2026-06-28); a persistent `Live` region stays out by design (it fights
      the concurrent-stdin steering loop).
- [x] Streamed tokens routed through the renderer (`on_token` → `render.stream`):
      styled "agent" prefix + verbatim tokens in rich, identical inline print in plain.
- [x] Colour-coded phase banner (RECON/ENUM/EXPLOIT/POST/REPORT) + target/ports/
      vulns status line pulled from `AttackState`, shown at the top of each turn.
- [x] `--plain` fallback; also auto-selected for pipes/dumb terminals (`isatty`)
      and when `rich` isn't installed. Tests: 3 (pure selection + phase-style +
      plain-output parity).
- Touchpoints: `cli/render.py` (new), `cli/mapache_cli.py`.

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

## D. Update manager  ✅  ← shipped 2026-06-27
Keep an installed Mapache current.

- [x] `mapache update [--check]` — `core/updater.py`: compares local `VERSION` to
      the highest semver tag on the git remote (`git ls-remote --tags`), numeric
      segment compare (`v1.2.10 > v1.2.9`); `--check` reports status, bare `update`
      applies (see below).
- [x] Version stamp (`VERSION` = 0.7.0) + `mapache version` / `mapache --version`;
      **non-blocking** startup "update available" notice — reads an offline cache
      (`~/.mapache/.update_check.json`, written by the last check) so startup never
      hits the network.
- [x] Backs up the config before updating; the apply is conservative — ff-only
      `git pull` (says so if it can't, never forces), and a `pip install -r`
      reinstall is **flagged** for the user, not run silently. Tests: 3.
- Touchpoints: `core/updater.py` (new), `VERSION` (new), `cli/mapache_cli.py`.

## E. `soul.md` — user-editable persona  ✅  ← shipped 2026-06-26
A human-owned file that shapes the agent's personality/values/voice.

- [x] Load `soul.md` and inject it into the system prompt. `core/soul.py`
      (`load_soul`/`soul_file`/`init_soul`); `ContextBuilder.set_persona` prepends
      it at the very top of the system prompt (above memory/summary/base), in both
      function-calling and JSON modes. Resolution mirrors config: project
      `./soul.md` over global `~/.mapache/soul.md`.
- [x] Hot-reload each turn — the controller calls a `persona_provider` every turn
      (`persona_provider=lambda: load_soul(working_dir)`), so edits take effect on
      the next message with no restart. Not propagated to sub-agents (operators
      carry their own focused prompts).
- [x] Ship a documented default (`DEFAULT_SOUL`, used when no file exists); `/soul`
      prints the active persona + source, `/soul init` writes an editable default
      to the global path. Tests: 3.
- Touchpoints: `core/soul.py` (new), `core/context_builder.py`,
  `core/agent_controller.py`, `cli/mapache_cli.py`.

## F. `user.md` — agent-maintained user profile  ✅  ← shipped 2026-06-27
Agent records what the user has done / prefers over time.

- [x] Agent-callable tool to append durable user facts. `memory/user_profile.py`
      (`UserProfile` + `user_remember` tool): facts are `- ` bullets under
      `## Category` headings (Identity/Preferences/Engagements/Habits/Notes) in the
      global `~/.mapache/user.md` — the markdown file IS the store (user-editable).
- [x] Inject a compact summary into the prompt for continuity — distinct from the
      attack state (`profile_provider` on the controller, injected each turn as a
      "USER PROFILE" memory block alongside the chain context, separate from
      `soul.md`'s persona). Not propagated to sub-agents.
- [x] Dedup / size-cap so it doesn't grow unbounded: exact (case-insensitive)
      dedup + per-category and total caps evict the oldest (the compaction idea).
      CLI `/user [forget <fact>]`. Tests: 3.
- Touchpoints: `memory/user_profile.py` (new), `core/agent_controller.py`,
  `core/conversation_chain.py` (CORE_TOOLS), `cli/mapache_cli.py`.

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

## H. Remote execution — SSH + Docker  ✅  ← shipped 2026-06-27
Run tools/commands somewhere other than the local shell.

- [x] Execution-backend abstraction (`core/exec_backend.py`): `ExecBackend` +
      `LocalBackend`/`SSHBackend`/`DockerBackend`, `build_backend(spec)` factory,
      `backend_from_config` (warn-don't-block fallback). `shell` dispatches through
      the active backend (local fast-path unchanged).
- [x] SSH backend via the system `ssh` binary (dependency-free, key/agent auth):
      `ssh [-p] [-i key] -o BatchMode=yes user@host "<cmd>"`, working-dir wrapped
      as `cd … && <cmd>`.
- [x] Docker backend: `docker exec <container> sh -c` (long-lived) or
      `docker run --rm <image> sh -c` (ephemeral, e.g. a Kali image), `-w` workdir.
- [x] Config `execution` block (backend + host/user/port/key / container/image/
      workdir); `--exec-backend` override; active non-local backend shown in the
      status line + `/backend` command. Tests: 3 (argv build, real local run +
      ShellTool routing, config parse).
- [x] `kali_run` adopts the backend (2026-06-28): a remote backend runs the bare
      tool name (no local `shutil.which`) so the remote/container PATH resolves it.
- [ ] Still deferred: per-target backend (one active backend for now).
- Touchpoints: `core/exec_backend.py` (new), `security_tools/shell_tool.py`,
  `core/config.py`, `cli/mapache_cli.py`.

## I. Community hub — downloadable skills  ✅  ← shipped 2026-06-28
Browse + install community "skills" (tools / MCP configs).

- [x] Skill manifest format (`hub/manifest.py`, `SkillManifest`): name, version,
      type (generated_tool | mcp_server), description, deps, checksum, optional
      signature/signer; `make_*_manifest` publisher helpers.
- [x] Hub client (`hub/client.py`) + registry (`hub/registry.py`, `LocalRegistry`
      reading `index.json`): `skill_search` / `skill_list` / `skill_install` agent
      tools (in CORE_TOOLS) + CLI `/hub`. `UrlRegistry` (HTTP/raw-GitHub index)
      added 2026-06-28 behind the same surface (injectable fetch; `make_registry`
      routes by scheme).
- [x] Install into the right home: generated tool → `write_generated_tool` (A,
      origin="hub" so the loader re-verifies sha256); MCP server → an `mcpServers`
      entry in `mcp.json`. (prompt/persona pack: documented future type, no
      consumer wired.)
- [x] **Safety** — checksum verify is the mandatory integrity gate (recomputed
      before any write; a tampered package is refused); signature verified when a
      trusted key is set (reuses N's `core.provenance`); installs don't hot-load
      (take effect next start = review gate); the install tool flags third-party
      code. Tests: 3.
- Touchpoints: `hub/` (new: manifest/registry/client/tools), A (generated tools),
  `mcp.json`, `core/config.py` (hub.registry), `cli/mapache_cli.py`.

---

# Differentiators vs Hermes Agent (J–P)

Hermes Agent (Nous Research, Feb 2026) is the general-purpose analogue of much of
A–I: self-improving skills, layered memory, multi-platform, model-agnostic. We do
**not** out-general it. Mapache's edge is depth where a generic assistant
structurally won't follow: **offensive security + local-first OPSEC + auditable,
signed artifacts.** J–P are the features that widen that gap.

> **Status: J–P all ✅ shipped (2026-06-19 → 2026-06-26)** on branch
> `feature/agent-loop-upgrades`. The A–I foundation is now also complete
> (A,B,C,D,E,F,G,H,I shipped 2026-06-08 → 06-28; G live-key e2e verification is
> the only loose end). Phase 9 voice shipped + deferred sub-items cleared
> (hub URL registry, live NVD, kali_run backend, task-list panel, ed25519).
> Suite 96/96.

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
- [x] Live NVD enrichment (2026-06-28): `enrich_from_nvd(keyword)` + `parse_nvd`
      over the NVD 2.0 API — opt-in, injectable fetch, fails to [] so the offline
      catalog stays default; only a low-sensitivity keyword leaves the box.
- [ ] Still deferred: RAG over the vector store; ExploitDB feed.
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

## Q. Decepticon-parity convergence  ✅  ← 1–7 sequence complete (2026-07 → 2026-08)
A second wave toward Decepticon parity: a durable knowledge graph, an operations
plan, a vuln-research pipeline, an autonomous supervisor, and a composable
middleware architecture around the loop. The 1–7 items are the user-set build
order (middleware → budget → HITL → vaccine → fan-out → skill.md → trace-streaming).

- [x] **Knowledge graph + OPPLAN + vuln-research pipeline** (`core/knowledge_graph.py`,
      `core/opplan.py`, staged operators + `VulnResearchTool`). Disk-persisted findings
      store inherited by sub-agents; an orchestration-facing plan injected to the lead.
- [x] **Autonomous supervisor** (`core/orchestrator.py`): `RoutingState` → `OperatorRouter`
      → `Supervisor` deploys/routes specialists from state (deterministic + LLM + OPPLAN
      tiers, exploration ladder). CLI `/swarm`, `benchmark_xbow --strategy swarm`.
- [x] **1. Composable loop middleware** (`core/middleware.py`): `AgentMiddleware` /
      `LoopContext` / `MiddlewareChain` run at turn_start / iteration_start / turn_end.
- [x] **2. Budget enforcement** (`BudgetMiddleware`): engagement token/wall-clock cap
      with a graceful stop. `config.budget` + `--budget-tokens` / `--budget-seconds`.
- [x] **3. Formal HITL slot** (`HITLMiddleware`): loop-level approve / deny / steer at
      every-N and phase-change checkpoints. `config.hitl` + `--hitl` / `--hitl-every`.
- [x] **4. Vaccine loop** (`VaccineMiddleware`): each confirmed vuln yields a
      detection+remediation artifact → KG note + `<workspace>/vaccines/`. `--vaccine`.
- [x] **5. Parallel operator fan-out**: on a supervisor stall, deploy the top-N distinct
      operators concurrently (`Supervisor(fanout=…)`, emits `supervisor.fanout`). `--fanout`.
      Live-verified on grok-4 / XBEN-001 (2026-08-01): 1 solo op → 3 parallel on stall.
- [x] **6. SKILL.md formatter** (`core/skill_format.py`): author playbooks as Markdown with
      frontmatter (name/description/when_to_use/ports/keywords/target_scheme/phase/tools);
      parse ↔ format round-trip (no PyYAML), predicate BUILT from the frontmatter, and
      `load_skill_dir` registers `~/.mapache/skills/` + `<workspace>/skills/` into the JIT
      injection set alongside the built-ins. Ships `skills/lfi_ssrf.md` as an example.
- [x] **7. Full sub-agent trace streaming** (`ScopedBus`): tags every delegated event with
      operator/depth so the CLI streams the sub-agent's attributed `⤷ [op]` trace, not just
      the delegate start/end banners.
- [x] **Progress ledger** (`core/progress_ledger.py`, from the XBOW loop plan): persists
      dead-end actions across turns and injects a "do NOT repeat" block each step.
- Touchpoints: `core/middleware.py`, `core/agent_middlewares.py`, `core/progress_ledger.py`,
  `core/orchestrator.py`, `core/event_bus.py`, `core/knowledge_graph.py`, `core/opplan.py`,
  `core/agent_controller.py`, `cli/mapache_cli.py`. Tests in `tests/test_core.py` (suite 154).

---

## R. Frontier-loop capability upgrades  ← in progress (2026-08)
The evidence-backed gaps after the XBOW diagnosis ("gap is the loop + tooling, not the
model"). Ordered by leverage; 1–5 shipped 2026-08-01.

- [x] **1. Headless browser tool** (`browser/browser_tool.py`): exposes the existing
      Playwright ChromiumController as the `browser` tool (JS/SPA rendering, form fill,
      recon on the RENDERED DOM). Persistent context = login carries across calls.
      Unlocks the modern-web-app class raw HTTP can't see. Optional dep — degrades to
      install guidance.
- [x] **2. Response-grounded acting** (agent_controller): a per-turn grounding corpus
      flags web calls to invented paths (never seen in any response) as blind probes;
      after a short streak, nudges the model to act on what a real response contained.
      Kills the #1 failure mode (blind spraying). Emits agent.grounding.
- [x] **3. Disciplined heavy tools** (`security_tools/kali/heavy_tools.py`): guided
      SqlmapTool + FuzzTool (ffuf) that build correct invocations from structured args
      and summarise output — real SQLi/discovery instead of hand-sprayed payloads.
- [x] **4. Reflection + tactical staging** (`ReflectionMiddleware`): every N steps,
      inject CONFIRMED/HYPOTHESIS/NEXT self-critique + the kill-chain stage from live
      state. `--reflect`. No extra model call.
- [x] **5. Multi-attempt / self-consistency** (`core/multi_attempt.py`): retry up to N
      times with a fresh context (findings persist) + a different-approach directive +
      the ledger's dead ends; stop on first solve. `--attempts N`.
- [ ] **6. Measure the swarm/fanout + capability lift** — plumbing ready
      (`benchmark_xbow --strategy swarm --fanout --reflect --attempts N`); a meaningful
      A/B needs a capable PAID model and enough benchmarks (free tier gives no signal).
- [ ] **7. Base model** — data shows DeepSeek V4 Pro > grok-4 by ~42% on XBOW; a
      frontier model raises the floor and compounds 1–5. Config choice, not code.
- Touchpoints: `browser/browser_tool.py`, `browser/chromium_controller.py`,
  `security_tools/kali/heavy_tools.py`, `core/agent_controller.py`,
  `core/agent_middlewares.py`, `core/multi_attempt.py`, `cli/mapache_cli.py`,
  `tests/benchmark_xbow.py`. Tests in `tests/test_core.py` (suite 164).

---

## S. Full-spectrum coverage + cross-engagement learning  ← 2026-08
Making Mapache a true multi-domain operator, not a web agent, and one that improves
over time.

- [x] **Multi-domain playbooks** (`core/skills_playbook.py`): built-in just-in-time
      playbooks now span web, network service, credential, AD, **cloud** (IMDS/bucket/
      IAM/k8s), **binary-pwn** (checksec→pwntools ROP), **mobile** (apktool/jadx/frida),
      and **social-engineering** (deconfliction-gated GoPhish/evilginx). The 22 domain
      operators were already tool-backed (they drive aws/kubectl/frida/ghidra/gophish via
      shell/kali_run); this gives them the injected method web already had.
- [x] **Candidate-flag verifier** (`core/flag_verifier.py`): format-aware — a candidate
      is verified only when grounded in tool output AND matching the expected format;
      catches a captured-but-wrong-format token and recognises custom (non-FLAG{})
      formats. `--flag-format` / config.flag_format.
- [x] **Cross-engagement learning** (`core/learning_store.py`): records outcomes by
      target fingerprint; biases the OperatorRouter toward operators that won on similar
      targets and injects a "prior wins" hint. Persisted; wired into benchmark (swarm)
      + CLI (record at session end, inject via profile provider).
- [ ] **Still open:** live validation of the non-web domains against real targets;
      richer outcome→technique extraction; sqlmap/ffuf live runs.
- Touchpoints: `core/skills_playbook.py`, `core/flag_verifier.py`,
  `core/learning_store.py`, `core/orchestrator.py`, `core/agent_controller.py`,
  `cli/mapache_cli.py`, `tests/benchmark_xbow.py`. Tests in `tests/test_core.py` (suite 168).

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
