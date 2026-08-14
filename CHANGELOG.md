# Changelog

All notable changes to Mapache are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] — 2026-08-14

First public release. Mapache is an autonomous offensive-security agent: you give
it an objective in plain language ("pentest 10.0.0.5", "find the IDOR in the app at
http://target/") and it works the engagement one tool call at a time — enumerate,
exploit, escalate — then hands back a report of proven findings with remediation.

### Highlights

- **Full-spectrum, not a CTF/web bot.** A single ReAct loop routes by target
  discipline across web, network, cloud, Active Directory, binary, mobile, wireless,
  ICS/OT, IoT, OSINT, supply-chain, social-engineering, and LLM targets — each with a
  specialist operator and a built-in playbook.
- **Evidence-first.** Success is a proven finding with severity, evidence, impact,
  and remediation — not a captured flag. Reports export to Markdown, HTML, SARIF, and
  bug-bounty drafts.
- **Grounded, not guessing.** Mapache reads a target's real forms, endpoints, and
  disclosed credentials into attack state, looks up payloads from an offline corpus,
  and detects dead attack vectors so it changes approach instead of spinning.
- **Local-first and safe to run unattended.** Runs fully on a local model if you
  want, enforces rules-of-engagement scope, defends itself with an active
  prompt-injection shield, and keeps an append-only audit log with an optional
  replayable recording.

### Added

- **Native Chinese model providers** — DeepSeek, Moonshot (Kimi), and Zhipu (GLM)
  as first-class OpenAI-compatible providers, so keys can be pasted directly from the
  vendor consoles without routing through an aggregator. Wired into the config layer,
  the setup wizard, and the model registry.
- **`code_run` compile-run-fix loop** — a backend-aware tool that writes, compiles,
  runs, and iteratively fixes real exploit/tooling code (Python, C, C++, Go, Rust,
  Bash, …), staging into the active local/Docker/SSH target and returning a structured
  `COMPILE FAILED` / `EXIT n` / `OK` verdict. Ships with a dedicated `exploit_dev`
  operator; the tools image gains `gcc`/`g++`/`radare2`.
- **Model Context Protocol (MCP) client** — connect Mapache out to any
  Claude-Desktop-style `mcp.json` server; remote tools are adapted into the agent's
  toolset as `mcp__<server>__<tool>` and pinned so phase-subsetting keeps them exposed.
- **Multi-agent supervisor / swarm** — autonomous operator routing that can split an
  engagement into specialist sub-agents sharing attack state and HTTP session.
- **Community skill hub** — browse/install generated tools and MCP servers with a
  sha256 integrity gate.
- **Benchmark harnesses** — Cybench (multi-category CTF) and Meta CyberSecEval 3,
  alongside the existing XBOW and real-world Dockerized discipline suites.

### Fixed

- **MCP launcher resolution on Windows** — bare launchers like `npx`/`uvx` (the way
  every Claude-Desktop-style `mcp.json` writes them) are now resolved through `PATH`
  honouring `PATHEXT` before exec. Previously `create_subprocess_exec("npx")` failed
  with `WinError 2` on the `.cmd` shim and MCP silently produced zero tools. Verified
  live against `@modelcontextprotocol/server-filesystem`.
- **Sub-agent stall/iteration tuning** — the lead agent's `MAX_ITERATIONS` and
  stall/loop-abort thresholds now propagate to delegated sub-agents, which previously
  reverted to class defaults.
- **Benchmark reliability** — Docker Compose paths are resolved to absolute (server
  tasks now come up), per-task `.trace.txt` captures failures, and provider errors
  (402/429/5xx) are graded as infrastructure faults rather than counted as model
  losses.

### Changed

- The agent loop is discipline-routed and evidence-first end to end, rather than
  network/CTF-biased; per-turn next-step guidance is target-kind aware.

### Known issues

- **Model choice matters a lot.** Small or free-tier models can't reliably drive
  the full agent loop — some free endpoints forbid native function-calling or throttle
  aggressively, and weak models flail with duplicate calls. For real engagements use a
  capable local model (e.g. `qwen2.5:32b`) or a frontier cloud model. Benchmark scores
  are dominated by the loop-plus-model combination, not the loop alone.
- **Offensive toolchain is assumed present.** Mapache drives external binaries
  (`nmap`, Metasploit, `hydra`, …). These are packaged on Kali/ParrotOS; on Windows or
  macOS install them yourself or point Mapache at a Linux target via the Docker/SSH
  execution backend. On Windows, host-side tools that lack a native port fall back to
  the tools container.
- **Dockerized/networked targets.** A tool running on the host may not resolve a
  Docker-internal service name — target services by an address reachable from where the
  tool actually runs (published port / container IP).
- **Third-party MCP servers vary.** Some community MCP servers are broken upstream
  independent of Mapache (e.g. a version-skew import error). Mapache fails soft — an
  unavailable server is logged and skipped rather than aborting startup.
- **Benchmarks are early.** Live cloud- and service-target benchmark runs are still
  being measured; published numbers so far come from a subset of runs and will move as
  coverage grows.
- **Cloud usage costs real money.** Frontier/cloud providers are billed per token and
  an autonomous engagement can make many calls — set budget limits and start against a
  scoped, disposable target.

### Licensing

- Released under the **Apache License 2.0**.

### Install

```bash
git clone https://github.com/slider-labs0/Mapache.git && cd Mapache
python3 -m venv .venv && source .venv/bin/activate
pip install -e .        # installs the `mapache` command
mapache setup           # interactive: pick a provider + model
mapache serve           # launch the agent
```

Requires Python 3.10+. Kali/ParrotOS is the recommended platform (the offensive
toolchain is packaged there). For local models use [Ollama](https://ollama.com); for
cloud models set the provider key and pass `--allow-cloud`.

### Safety

Mapache is for **authorized** security testing only — engagements you own or have
written permission to test. It enforces rules-of-engagement scope, but scope is a
guardrail, not a guarantee: you are responsible for staying in bounds and for
complying with applicable law.

[0.7.0]: https://github.com/slider-labs0/Mapache/releases/tag/v0.7.0
