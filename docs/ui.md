# User interface

Mapache has three faces: the line-based CLI, an opt-in full-screen TUI with a live agent
dashboard, and the setup wizard. It can also be operated remotely over Telegram and
Discord. This page covers each, plus every slash command.

## Launching

```bash
mapache serve                     # classic CLI
mapache serve --tui               # full-screen TUI with the dashboard
mapache serve --model qwen2.5:32b # pin a model
mapache setup                     # the setup wizard
mapache config show               # print the effective config
mapache version                   # print the version
```

The startup banner shows a large ANSI wordmark and the mascot, then a compact box of
session facts (model, tool count, confirm and verifier state, memory counts, the rules of
engagement, and the working directory).

## The classic CLI

You type an objective at the prompt and the agent works it, streaming its reasoning and
tool activity. A single background reader handles input, so you can type to steer a
running turn (or answer a confirmation) without a second reader competing for the
keyboard. The transcript is colored by the active specialist during delegation, so you can
see which operator is working. In the classic CLI the strategy and per-role model
routing print inline at startup.

## The full-screen TUI dashboard

`--tui` opens a two-column layout:

- Left column: the ANSI mascot and the scrolling transcript, over a bordered input box.
- Right column: a live agent dashboard, a fixed-width stack of panels.

The dashboard panels:

- Agent: the active operator and its accent color, the current phase, and the team size.
- Models: the routing strategy and the per-role model map (planner, executor, verifier).
  This is where the model details live in the TUI, rather than front and center.
- Target: the target, the open ports, and the vulnerability count.
- Budget: elapsed time and tokens against any configured caps, and the tool-call count.
- Running shells: any in-flight shell commands, with a spinner.
- Recent tools: the last handful of tool calls.

The dashboard is fed by the same events the transcript uses, plus the status clock, so it
updates live as the agent works without slowing it down. The full-screen view needs a
real console; if the terminal cannot start a full-screen app, Mapache falls back to the
classic CLI automatically.

## The setup wizard

`mapache setup` walks you through configuration, with every question in its own titled
panel:

- Model provider: pick from local Ollama or a cloud provider.
- API key: paste a key for a cloud provider, or leave it to an environment variable.
- Model: pick a model id (a suggested list, or type your own).
- Roles: use one model for everything, or customize per role (lead, executor, verifier),
  which writes the per-role model map.
- Strategy: Auto (smart routing), Solo (one model), or Swarm (a multi-agent team).
- Toolchain, Ollama, and a smoke test are shown as compact panels.

The wizard is idempotent: every prompt shows the current value as its default, and
pressing Enter keeps it. Secrets are preserved: a key kept as an environment placeholder
is never rewritten as a literal.

## Remote operation

Mapache can run over Telegram and Discord with the full toolset. A single command launches
both bots, and the async frontends can steer a running turn the same way the CLI can.
Configure the bot tokens in the wizard or the config file.

## Voice

Optional voice input and output are available behind a null default (`--voice`, `--say`,
and the voice config section). Text-to-speech and speech-to-text are opt-in and require
their optional packages.

## Slash commands

Type these at the prompt during a session.

### Session and help

- `/help` shows the command list.
- `/clear` clears the screen.
- `/exit`, `/quit` end the session.
- `/history` shows the conversation history.
- `/context` shows what is in the current prompt context.
- `/debug` toggles debug output.

### Models and routing

- `/models` shows the live routing table and per-model call counts.
- `/pipeline <strategy>` switches the strategy (single, pipeline, auto, hybrid).
- `/swarm [on|off]` toggles the multi-agent supervisor.
- `/opsec` shows which operations are pinned to a local model.
- `/operators` lists the operator roster.

### State and memory

- `/chain` shows the attack-state chain.
- `/hosts` lists discovered hosts.
- `/memory` shows memory state.
- `/user` records a durable fact about you.
- `/cve` looks up CVEs for a discovered service.
- `/synthesize` saves the current proven chain as a skill.

### Scope, logging, and reporting

- `/scope` shows the active rules of engagement.
- `/log`, `/log export` show and export the audit log.
- `/report [md|html|both]` generates a report.

### Execution and egress

- `/backend` shows or sets the execution backend.
- `/egress` shows or sets traffic anonymization.
- `/cwd` shows the working directory.

### Extensions and tools

- `/tools` lists registered tools.
- `/integrations` lists configured external tools.
- `/hub` browses and installs from the skill hub.
- `/curate` reviews stale self-authored tools for archiving.
- `/restore <name>` restores an archived tool.
- `/purge <name>` hard-deletes an archived tool.

### Confirmation and voice

- `/confirm` toggles per-action confirmation for dangerous operations.
- `/voice`, `/say` control voice output.
- `/soul` shows the agent persona.

## Useful flags

- `--allow-cloud` permits routing to cloud models.
- `--strategy <name>` sets the routing strategy.
- `--verify` enables the opt-in verifier step.
- `--scope <path>` sets a rules-of-engagement file.
- `--mcp-config <path>` sets the MCP server list.
- `--budget-tokens N`, `--budget-seconds S` cap the engagement.
- `--attempts N` enables multi-attempt self-consistency solving.
- `--tui` opens the full-screen dashboard.
