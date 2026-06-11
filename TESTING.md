# Mapache — Testing Playbook

How to verify Mapache's features, from fast automated checks to live runs against
a real model. Three tiers, cheapest first. On Windows, prefix Python commands with
`$env:PYTHONUTF8=1;` to avoid cp1252 console-encoding errors on log output.

Primary test model: **qwen2.5:32b** (native tool-calling). Swap with `--model`.

---

## Tier 1 — Unit suite (no Ollama, fast, deterministic)

The regression net. Run on every change; must stay green.

```powershell
$env:PYTHONUTF8=1; python tests/test_core.py
```

Expect: `All tests passed.` — currently **39 checks** covering:

| Area | What's verified |
|------|-----------------|
| EventBus / ContextBuilder | pub/sub, prompt assembly, token budget, tool-result shaping |
| AgentController | tool_call, JSON-mode, verifier retry, max-iterations, plan→todos, reask on malformed, multi-tool, streaming, compaction, steering, delegation, MCP client, duplicate-call guard |
| Model routing | pipeline executor pick, embedding-model exclusion, strategy switch |
| Self-authored tools (A) | create/dispatch, bad-input rejection, curator active→stale→archived, hub checksum |
| Config layer (C0) | precedence chain, `${ENV}` interpolation, provider resolution, redaction |

These use a scripted `MockModel` — they prove the *plumbing*, not real-model
behavior. That's Tier 2's job.

---

## Tier 2 — Live smoke (real model, the real proof)

Why it matters: every Tier-1 controller test feeds the loop scripted JSON. Only a
live model tells us whether a local model actually emits valid protocol — the
whole reason the reask / robust-parsing layer exists.

Prereqs: `ollama serve` running; `ollama list` shows the model. Launch:

```powershell
$env:PYTHONUTF8=1; python -m cli --model qwen2.5:32b
```

Drive each check by typing the prompt at `you >` and watching the behavior. Type
`/quit` to exit. (Ctrl+Z then Enter also sends EOF.)

### Core loop
| # | Type this | Expect |
|---|-----------|--------|
| 1 | `what does VM stand for?` | A direct text answer, **no tools** (general-knowledge carve-out). |
| 2 | `run whoami` | One `shell` tool call, real output, then a final answer. `(used: shell, N steps)`. |
| 3 | `whoami and also show the hostname` | A multi-tool turn (two shell calls batched) or two sequential calls. |

### Persistent TODO / plan
| 4 | `make a 3-step plan to enumerate example.com, then start` | A `=== TASK LIST ===` block appears and persists across turns; first action dispatches (not just printed). |

### Mid-run steering
| 5 | Start a long task, then **type a new line while it runs**, e.g. `actually focus on port 443` | `↪ steering:` line appears; the turn redirects without restarting. |

### Sub-agent delegation
| 6 | `delegate: enumerate the web service on this host and report back` | `agent.delegate.start/end`; a child runs and only its conclusion returns. |

### Self-authored tools (feature A) — the headline test
| 7 | `create a tool named add_one that takes an integer n and returns n+1, then use it on 41` | A `create_tool` call succeeds ("Created tool 'add_one'…"); **next turn** the model calls `add_one` and returns `42`. |
| 8 | `/tools` then look for `add_one` | Listed among registered tools (tagged generated). |
| 9 | `tool_list_generated` (ask the model to list its tools) | Shows `add_one` with state `active`, a use count. |
| 10 | `/curate` | If any tool is stale, it's proposed for archive one-by-one (y/N). Fresh tools: "library is clean." |
| 11 | `/restore <name>` / `/purge <name>` | Restore moves an archived tool back; purge refuses unless already archived. |

Verify persistence: `/quit`, relaunch, `/tools` → `add_one` is **still there**
(reloaded from `plugins/generated/`). Check `plugins/generated/add_one/` on disk
(tool.py + manifest.json).

### Routing / models
| 12 | `/models` | Live routing table + per-model call counts. |
| 13 | `/pipeline auto` then `/models` | Strategy switches; routing explanation updates. |

### Context compaction (long session)
| 14 | Hold a long multi-turn conversation (or paste large outputs) until history exceeds budget | A running "CONVERSATION SO FAR" summary forms; durable facts (targets, ports, creds) survive; no hard truncation errors. |

### Streaming
With a native tool-calling model (qwen2.5), normal answers stream token-by-token
(`agent > ` fills in live). JSON-mode models print the whole answer at once.

### MCP (optional)
With an `mcp.json` present and `--mcp-config mcp.json`, startup prints
`MCP : N tools from M server(s)`; those tools appear in `/tools` namespaced
`mcp__<server>__<tool>` and are callable.

---

## Tier 3 — Offensive end-to-end (the mission)

Non-deterministic; needs real targets + binaries (nmap, msfconsole, john) and
authorization. The HTB-style benchmark:

```powershell
$env:PYTHONUTF8=1; python -m cli --model qwen2.5:32b
you > target is 10.129.x.x — nmap scan with -Pn flag
```

Watch for: target captured into attack state, `nmap_scan` runs with `target=`,
open ports parsed, phase advances recon→enumeration, phase-appropriate tools
exposed. See `STATUS.md` "HTB benchmark — issue tracker" for known-good behavior.

Use `--confirm` to gate dangerous ops, `--verify` to enable the reflection step.

---

## Known coverage gaps (be honest about these)

- **CLI entrypoint** (`cli/mapache_cli.py`) — REPL, slash commands (`/curate`,
  `/restore`, `/purge`), the steering loop and stdin reader — is only
  construction-tested. Tier 2 is currently manual; a pipeable `tests/smoke_cli.py`
  harness (scripted stdin → grep output) would automate it.
- **C0 config layer** is unit-tested but **not yet wired into the CLI** — nothing
  consumes `MapacheConfig` until C1. Until then, `--model`/env flags still drive it.
- **Real offensive tools** (nmap/msf/john/burp/kali) and **messaging**
  (Telegram/Discord) need external services and aren't covered automatically.
- **Real-model protocol reliability** for `create_tool` (nested schema + code in
  one call) is exactly what Tier 2 #7 probes — the main unknown for feature A.
