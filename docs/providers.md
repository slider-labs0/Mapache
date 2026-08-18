# Providers

A provider is where a model runs. Mapache talks to local models, cloud providers, and
local gateways through one abstraction, so per-role routing can address local and cloud
models interchangeably. This page lists the providers, how to configure them, and their
model ids.

## How providers work

Each provider entry in the config carries a kind, a base URL, an API key, a list of model
ids it serves, and an enabled flag. A model id is routed to the provider that lists it; a
model that no cloud provider claims falls back to the local Ollama provider. Cloud calls
require `--allow-cloud` (or `allow_cloud: true` in config), and Mapache warns when a call
sends target, scan, or credential context to a cloud model.

You can set keys three ways: type them in `mapache setup`, put them in the config file,
or reference an environment variable with a `${VAR}` placeholder so nothing secret is
written to disk.

## Local models: Ollama

The default provider. Install [Ollama](https://ollama.com), run `ollama serve`, and pull a
model:

```bash
ollama pull qwen2.5:32b
mapache serve --model qwen2.5:32b
```

Any locally installed model works without listing it. Ollama is the recommended primary
test model source; `qwen2.5:32b` is a reliable tool-calling local model.

### Context window

Ollama defaults a model's context window to a small value (often 4096 tokens), so a full
Mapache prompt (system prompt plus tools plus attack state, roughly 12000 to 16000 tokens)
overflows it and Ollama returns HTTP 400 "exceeds the available context size". Mapache
requests a larger window automatically via `options.num_ctx` (default 25000), so any model
can hold a real engagement prompt with room left for its answer.

The window must exceed the prompt budget (around 16000 tokens) with headroom for the
model's output. If it does not, a large prompt fills the whole window and the model's
reply, including a tool call, gets truncated mid-generation. Loading many tools (for
example an MCP browser server) makes the prompt bigger, so raise the window for those:

```bash
OLLAMA_NUM_CTX=32768 mapache serve
```

A larger window uses more memory. If a big model runs short on memory, lower
`OLLAMA_NUM_CTX`, but keep it comfortably above your prompt size or replies will truncate.

## Cloud providers

| Provider | Kind | Base URL | Key env var |
|----------|------|----------|-------------|
| OpenRouter | openai-compatible | https://openrouter.ai/api/v1 | OPENROUTER_API_KEY |
| Anthropic | anthropic | https://api.anthropic.com | ANTHROPIC_API_KEY |
| OpenAI | openai-compatible | https://api.openai.com/v1 | OPENAI_API_KEY |
| Grok (xAI) | openai-compatible | https://api.x.ai/v1 | XAI_API_KEY |
| Nous | openai-compatible | (Nous endpoint) | NOUS_API_KEY |
| NVIDIA NIM | openai-compatible | (NIM endpoint) | NVIDIA_API_KEY |

OpenRouter is convenient because one key reaches many frontier models (for example
`anthropic/claude-sonnet-4.6`, `openai/gpt-4.1`, `x-ai/grok-4`).

## Native Chinese providers

DeepSeek, Moonshot (Kimi), and Zhipu (GLM) are first-class providers, so you can paste a
key straight from the vendor console without routing through an aggregator.

| Provider | Base URL | Key env vars | Model ids |
|----------|----------|--------------|-----------|
| DeepSeek | https://api.deepseek.com | DEEPSEEK_API_KEY | deepseek-chat, deepseek-reasoner |
| Moonshot (Kimi) | https://api.moonshot.ai/v1 | MOONSHOT_API_KEY or KIMI_API_KEY | kimi-k2-0711-preview, moonshot-v1-128k, moonshot-v1-32k, moonshot-v1-8k |
| Zhipu (GLM) | https://open.bigmodel.cn/api/paas/v4 | ZHIPU_API_KEY or GLM_API_KEY | glm-4.6, glm-4.5, glm-4-plus, glm-4-air, glm-4-flash |

All three are OpenAI-compatible, so Mapache speaks to them natively with no extra
dependency. They support native tool-calling, which the agent loop needs.

## Local gateways: OmniRoute

OmniRoute is a local OpenAI-compatible gateway that aggregates many providers, including
free tiers. Configure it as a provider with kind openai-compatible, base URL
`http://localhost:20128/v1`, and a dummy non-empty key (the gateway ignores auth on
localhost). Pin a fixed model id to avoid the gateway rotating the backend per request.

Free-tier models routed this way have two practical limits: some forbid native
tool-calling and some throttle aggressively. They are fine for light use but not for
driving the full agent loop at speed. A capable local model or a paid cloud model is the
right choice for real engagements.

## Tool-calling versus JSON mode

Native tool-calling models receive tool schemas in the dedicated `tools` field. A model
without native tool-calling (or a tier that forbids it) runs in JSON mode: the tools are
described in the prompt and the model is asked for JSON that the loop parses into tool
calls. Mapache selects the mode automatically per provider.

## Choosing a model

- For real engagements, use a capable local model (for example `qwen2.5:32b`) or a
  frontier cloud model.
- Small or free-tier models struggle to drive the loop reliably.
- For a multi-model team, see [Model routing](model-routing.md).
