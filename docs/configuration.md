# Configuration

Mapache reads a layered configuration: built-in defaults, then a global config file, then
a project-level file, then environment variables, then command-line flags. Later layers
win. This page documents the config file and the options.

## Where config lives

- Global: `~/.mapache/config.json`, written by `mapache setup`.
- Project: a config file in the working directory overrides the global one.
- View the effective config with `mapache config show`, and the path with
  `mapache config path`. Secrets are redacted in the printed output.

## Secrets

A value can be a literal, or an environment placeholder like `${DEEPSEEK_API_KEY}`. The
placeholder is resolved at load time, so a key supplied only by the environment is never
written to disk as plaintext. The setup wizard preserves an existing placeholder when you
press Enter.

## Options

```json
{
  "default_model": "qwen2.5:32b",
  "default_strategy": "single",
  "model_roles": {
    "planner": "deepseek-reasoner",
    "executor": "kimi-k2-0711-preview",
    "verifier": "glm-4.6"
  },
  "allow_cloud": false,
  "max_vram_gb": 12.0,
  "providers": {
    "ollama":   { "kind": "ollama",             "base_url": "http://127.0.0.1:11434", "enabled": true },
    "deepseek": { "kind": "openai_compatible", "base_url": "https://api.deepseek.com", "api_key": "${DEEPSEEK_API_KEY}", "models": ["deepseek-chat","deepseek-reasoner"], "enabled": true }
  },
  "messaging": { "telegram_token": "", "discord_token": "" },
  "execution": { "backend": "local" },
  "egress":    { "mode": "direct" },
  "integrations": [],
  "hub":       { "registry": "" },
  "voice":     { "enabled": false },
  "budget":    { "max_tokens": 0, "max_seconds": 0 },
  "hitl":      { "enabled": false, "every": 0, "on_phase_change": true },
  "vaccine":   { "enabled": false, "per_step_cap": 0 },
  "reflection":{ "enabled": false, "every": 0 },
  "flag_format": ""
}
```

### Core

- `default_model`: the model used when you do not pass `--model`.
- `default_strategy`: single (alias solo), auto, pipeline, hybrid, or swarm. See
  [Model routing](model-routing.md).
- `model_roles`: optional per-role model map (planner, executor, verifier), applied to the
  router at startup. Empty means every role uses the default model.
- `allow_cloud`: permit routing to cloud models. Also set by `--allow-cloud`.
- `max_vram_gb`: a hint for local routing.

### Providers

Each entry has a kind (ollama, openai_compatible, or anthropic), a base URL, an optional
API key, a list of model ids it serves, and an enabled flag. See [Providers](providers.md)
for the full list and the environment variables.

### Messaging

`telegram_token` and `discord_token` enable the remote bots.

### Execution and egress

- `execution.backend`: local, docker, or ssh (plus backend-specific fields).
- `egress.mode`: direct, proxy, or tor.

See [Execution and OPSEC](execution-and-opsec.md).

### Middleware

- `budget`: stop the loop gracefully at a token or wall-clock cap.
- `hitl`: human-in-the-loop checkpoints (every N steps, or on a phase change).
- `vaccine`: turn each confirmed vulnerability into a detection and remediation note.
- `reflection`: inject a reflect-and-refocus checkpoint every N steps.

### Extensions and other

- `hub.registry`: a local path or an http(s) URL for the skill hub.
- `integrations`: bring-your-own HTTP or command tool specs.
- `voice`: text-to-speech and speech-to-text settings.
- `flag_format`: an optional regex the candidate-flag verifier uses to recognize custom
  flags.

## Environment variables

- Provider keys: `DEEPSEEK_API_KEY`, `MOONSHOT_API_KEY` (or `KIMI_API_KEY`),
  `ZHIPU_API_KEY` (or `GLM_API_KEY`), `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`,
  `OPENAI_API_KEY`, `XAI_API_KEY`, `NOUS_API_KEY`, `NVIDIA_API_KEY`.
- Base URL overrides where supported, for example `MOONSHOT_BASE_URL`, `ZHIPU_BASE_URL`.
- `MAPACHE_STRATEGY` maps to `default_strategy`.
- `OLLAMA_NUM_CTX` sets the context window Mapache requests from Ollama (default 24576).
  See [Providers](providers.md).
- `NO_COLOR` disables colored output.

## Flags that override config

`--model`, `--strategy`, `--allow-cloud`, `--scope`, `--mcp-config`, `--budget-tokens`,
`--budget-seconds`, `--verify`, `--attempts`, and `--tui`. Flags win over the config file.
