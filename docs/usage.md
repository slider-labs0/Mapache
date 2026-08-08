# Usage

## Launching

```bash
python -m cli                          # interactive REPL, uses the configured default model
python -m cli --model qwen2.5:32b      # pick a local Ollama model
python -m cli --model claude-opus-4-8 --allow-cloud   # a cloud model (needs an API key)
```

Set up once with the wizard (chooses provider + model, writes `~/.mapache/config.json`):

```bash
python -m cli setup
python -m cli config show              # inspect the merged config
```

At the prompt, type a natural-language objective ("pentest 10.0.0.5", "find the IDOR
in the app at http://target/"). The agent works one tool call at a time, reading each
real result before the next step.

## Launch flags

| Flag | Purpose |
|------|---------|
| `--model <id>` | Primary model id. |
| `--allow-cloud` | Permit routing to a cloud model (off by default; keeps data local). |
| `--strategy single\|pipeline\|auto\|hybrid` | Per-role model routing (default single). |
| `--tier-model <id>` | (benchmark) cheaper model for low-tier discovery operators. |
| `--fanout` | Swarm: on a stall, deploy several specialists in parallel. |
| `--scope <file>` | Enforce rules-of-engagement from a `scope.json`. |
| `--budget-tokens N` / `--budget-seconds S` | Stop the engagement at a token or time cap. |
| `--hitl` / `--hitl-every N` | Human-in-the-loop checkpoints. |
| `--reflect` | Inject a self-critique every few steps. |
| `--route-enum` | Probe common web routes on a sparse target. |
| `--cast` | Record the engagement as a replayable asciicast. |
| `--exec-backend local\|ssh\|docker` | Where shell tools run. |
| `--egress tor\|<proxy-url>` | Hide the operator IP behind Tor or a proxy. |
| `--vaccine` | Generate a detection + remediation note per confirmed vulnerability. |

Run `python -m cli --help` for the full list.

## Slash commands (inside the REPL)

| Command | Purpose |
|---------|---------|
| `/swarm` | Toggle the autonomous multi-agent supervisor. |
| `/report [md\|html\|both\|sarif\|bounty\|all]` | Write the findings report. |
| `/scope` | Show the active rules-of-engagement. |
| `/memory`, `/memory search <q>`, `/memory targets` | Inspect persistent memory. |
| `/cve [CVE-id]` | Ground discovered services to CVEs. |
| `/log export` | Write a Markdown engagement-log timeline. |
| `/synthesize` | Save a proven attack chain as a reusable skill. |
| `/history`, `/clear` | Show or reset conversation + attack state. |

Prefix a line with `!` to run a shell command in the session, or `/` for a command.

## Configuration

`~/.mapache/config.json` holds providers, keys, default model/strategy, execution
backend, egress, and integrations. Keys can be inline or referenced from the
environment (for example `"api_key": "${OPENROUTER_API_KEY}"`). A per-engagement
`mapache.json` in the working directory overrides non-secret settings.
