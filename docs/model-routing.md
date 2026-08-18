# Model routing and multi-model agents

Mapache can run on a single model or orchestrate several models inside one engagement,
each owning a role. This page explains the routing strategies, how to configure a
multi-model team, and exactly how a sub-agent decides which model controls it.

## The mental model

Configuring several providers in `mapache setup` does not run them all at once. Nothing
runs until you start a session and give it a prompt, and each session runs one
engagement. Which model does the work is decided by three things:

1. The model you pin at launch (`--model`) or the `default_model` in config.
2. The routing strategy (`--strategy` or `default_strategy`).
3. The optional per-role model map (`model_roles`) and per-operator routing.

## Strategies

A strategy decides how roles map to models. Roles are `planner` (strategy and
decomposition), `executor` (runs the tools each turn, drives the loop), and `verifier`
(checks the final answer). The ReAct loop itself runs as the executor role.

| Strategy | Behavior |
|----------|----------|
| `single` (alias `solo`) | One model for every role: the model you pass with `--model`. No mixing. |
| `auto` | Best-scoring model per role, drawn from the registry of available models. |
| `pipeline` | Dedicated model per role: quality-weighted planner and verifier, speed-weighted executor. |
| `hybrid` | Cloud planner and verifier plus a local executor. Requires `--allow-cloud`. |
| `swarm` | Auto routing plus the multi-agent supervisor. Activates operator fan-out at launch. |

With a single model installed, every strategy collapses to that one model, so there is
no behavior change until you actually have more than one model available.

For a clean model-versus-model comparison, pin `--strategy solo` with each `--model` so
one model does the whole engagement. For a collaborative team, use per-role routing or
swarm as described below.

## Running one model per demo

```bash
mapache serve --model deepseek-chat        --strategy solo --allow-cloud
mapache serve --model kimi-k2-0711-preview --strategy solo --allow-cloud
mapache serve --model glm-4.6              --strategy solo --allow-cloud
```

Run them one after another. `solo` forces every role to the pinned model, so each run is
purely that model.

## Running several models as one team

Assign models to roles with `model_roles` in the config. The setup wizard offers this as
its "customize per role" option, or you can write it directly. A compelling split for a
cloud team:

```json
{
  "allow_cloud": true,
  "default_model": "kimi-k2-0711-preview",
  "default_strategy": "pipeline",
  "model_roles": {
    "planner":  "deepseek-reasoner",
    "executor": "kimi-k2-0711-preview",
    "verifier": "glm-4.6"
  },
  "providers": {
    "deepseek": { "kind": "openai_compatible", "base_url": "https://api.deepseek.com",           "api_key": "${DEEPSEEK_API_KEY}", "models": ["deepseek-chat","deepseek-reasoner"], "enabled": true },
    "moonshot": { "kind": "openai_compatible", "base_url": "https://api.moonshot.ai/v1",          "api_key": "${MOONSHOT_API_KEY}", "models": ["kimi-k2-0711-preview"],            "enabled": true },
    "zhipu":    { "kind": "openai_compatible", "base_url": "https://open.bigmodel.cn/api/paas/v4", "api_key": "${ZHIPU_API_KEY}",    "models": ["glm-4.6"],                         "enabled": true }
  }
}
```

The `${...}` placeholders read from the environment, so no secret is written to disk:

```bash
export DEEPSEEK_API_KEY=sk-... MOONSHOT_API_KEY=sk-... ZHIPU_API_KEY=...
mapache serve --allow-cloud --verify
```

`--verify` is important for a three-model team, because that is what fires the verifier
role. Without it, only the planner and executor participate. Explicit `model_roles`
overrides win regardless of strategy, because the router checks overrides before it
consults the strategy.

The TUI dashboard shows the live role-to-model map in a "Models" panel, which is a clean
on-screen proof that several models are working the same case.

## How a sub-agent chooses its model

When the lead delegates a subtask or the supervisor deploys a specialist, the child
agent's model is decided by a four-layer pipeline in `_spawn_and_run`, applied in order.

### 1. Inherit the lead's model

The child starts on the lead's routed model. By default it is on the same routed brain
as the lead.

### 2. OPSEC pin (sensitivity can force local)

`OpsecPolicy.decide` inspects the operator and the shared attack state. If the work is
sensitive, either because the operator prefers local (loot, credentials, post-exploit)
or because the shared state already holds captured credentials, the sub-agent is pinned
to a local model even when the lead is allowed cloud. This keeps loot and credentials on
the host. It is a no-op when cloud is disabled (everything is local anyway), and it
falls back to the current model with a warning if no local model is installed.

### 3. Per-operator role routing (the important layer)

Each operator declares a model role, and the child routes to that role's model through
the routing engine, which honors your `model_roles` map. Reasoning-heavy specialists
declare `planner`; action specialists default to `executor`:

| Operator | Declared role | Example model from the team above |
|----------|--------------|-----------------------------------|
| recon, web, exploit, post, cloud, mobile, wireless, iot, ics, general | `executor` | Kimi |
| osint, exploit_dev, contract_auditor, reverser, analyst, coder | `planner` | DeepSeek-Reasoner |
| verifier checkpoints (with `--verify`) | `verifier` | GLM |

Reasoning specialists get the reasoning model; action specialists get the fast
tool-caller. This happens automatically from the operator's declared role.

### 4. Cost and quality tier

Finally, `for_tier(operator.tier)` routes broad-discovery operators (recon, osint) to a
cheaper model and the rest to a strong model. This only takes effect if you have
configured a tiered provider; otherwise it is a no-op.

### The key point

Mapache does not assign models by operator name. There is no table that says "recon
always uses model X". It assigns by the role each operator declares, funneled through
your `model_roles` and routing. That is why setting the three roles is all you need to
orchestrate the whole swarm across three models.

## Commands

- `/models` shows the live routing table plus a per-model call count.
- `/pipeline <strategy>` switches the strategy mid-session.
- `/swarm [on|off]` toggles the multi-agent supervisor.
- `/opsec` shows which operations are pinned local.
