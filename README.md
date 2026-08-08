<div align="center">
  <img src="assets/mapache-logo.png" alt="Mapache" width="1000">
</div>

<h1 align="center">Mapache</h1>

<p align="center"><i>Autonomous offensive-security agent. It does not just run nmap and write a report, it proves the finding.</i></p>

<div align="center">

<a href="https://github.com/slider-labs0/Mapache/stargazers">
  <img src="https://img.shields.io/github/stars/slider-labs0/Mapache?style=for-the-badge&color=yellow" alt="Stars">
</a>
<a href="https://github.com/slider-labs0/Mapache/commits">
  <img src="https://img.shields.io/github/last-commit/slider-labs0/Mapache?style=for-the-badge&color=orange" alt="Last commit">
</a>
<img src="https://img.shields.io/badge/python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+">

<br/>

<a href="https://your-website.example">
  <img src="https://img.shields.io/badge/Website-visit-6C5CE7?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Website">
</a>
<a href="https://youtube.com/@your-channel">
  <img src="https://img.shields.io/badge/YouTube-watch-FF0000?style=for-the-badge&logo=youtube&logoColor=white" alt="YouTube">
</a>
<a href="https://kickstarter.com/projects/your-project">
  <img src="https://img.shields.io/badge/Kickstarter-back%20us-05CE78?style=for-the-badge&logo=kickstarter&logoColor=white" alt="Kickstarter">
</a>

</div>

---

## What is Mapache?

Mapache is an autonomous offensive-security agent. You give it an objective in plain
language ("pentest 10.0.0.5", "find the IDOR in the app at http://target/") and it works
the engagement one tool call at a time: it enumerates, exploits, escalates, and hands back
a report of proven findings with remediation.

It runs an observe-act (ReAct) loop over a local model (via [Ollama](https://ollama.com))
or a frontier cloud model, tracks attack state across the kill chain, drives ~60 real
offensive tools, and can split into a swarm of specialist sub-agents coordinated by an
autonomous supervisor.

## Why Mapache?

- **Grounded, not guessing.** Most agents invent endpoints, field names, and payloads.
  Mapache reads a target's real forms, endpoints, and disclosed credentials into state,
  looks up payloads from an offline corpus, and detects dead attack vectors so it changes
  approach instead of spinning.
- **Evidence-first.** Success is a proven finding with severity, evidence, impact, and
  remediation, not a captured flag. Reports export to Markdown, HTML, SARIF, and
  bug-bounty drafts.
- **Local-first and safe to run unattended.** It runs fully on a local model if you want,
  enforces rules-of-engagement scope, defends itself with an active prompt-injection
  shield, and keeps an append-only audit log (and an optional replayable recording).
- **Full spectrum.** Web, network, cloud, Active Directory, binary, mobile, wireless,
  ICS/OT, IoT, OSINT, supply chain, and LLM targets - each with a specialist operator and
  playbook.

## Install

Kali/ParrotOS is the recommended platform (the offensive toolchain is packaged there).
Requires **Python 3.10+**. Installing the package provides the `mapache` command with
`setup`, `serve`, `config`, and `version` subcommands.

### Linux and macOS

```bash
git clone https://github.com/slider-labs0/Mapache.git && cd Mapache
python3 -m venv .venv && source .venv/bin/activate
pip install -e .        # installs the `mapache` command
mapache setup           # interactive: pick a provider + model
mapache serve           # launch the agent
```

For local models, install [Ollama](https://ollama.com), run `ollama serve`, and pull a
model (for example `ollama pull qwen2.5:32b`). For a cloud model, set the provider key and
add `--allow-cloud` (see below).

Offensive binaries on Debian/Kali, install what you need:

```bash
sudo apt update && sudo apt install -y nmap metasploit-framework exploitdb hydra john tor
```

### Windows

Mapache runs on Windows natively via PowerShell. Most offensive binaries are not available
on Windows, so route the agent's shell into a Kali container or a remote box for the real
toolchain (see the last step).

```powershell
git clone https://github.com/slider-labs0/Mapache.git; cd Mapache
py -3.11 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e .
mapache setup
mapache serve
```

Notes for Windows:

- Use Python 3.11 (`py -3.11`); avoid 3.14, which some optional dependencies do not yet
  support.
- If console output shows encoding errors, set `$env:PYTHONUTF8 = "1"` before running.
- For the full toolchain, point shell execution at a container or remote Kali:
  `mapache serve --exec-backend docker` (an attacker container) or the SSH backend
  configured in `~/.mapache/config.json`. WSL2 (Ubuntu/Kali) also works and gives you the
  native Linux toolchain.

### Cloud models

```bash
export ANTHROPIC_API_KEY=...     # or OPENAI_API_KEY / XAI_API_KEY / OPENROUTER_API_KEY
mapache serve --model claude-opus-4-8 --allow-cloud
```

Config lives at `~/.mapache/config.json` (see `mapache config show`). Keys can be inline
or referenced from the environment, for example `"api_key": "${OPENROUTER_API_KEY}"`.

## Highlights

- **Single agent or swarm.** A generalist works the kill chain, or an autonomous
  supervisor routes bounded objectives to specialists and fans out on a stall.
- **Burp-style HTTP repeater.** Record, replay, tamper, and diff requests. Replaying an
  authenticated request with one id changed and diffing the response is the
  IDOR/broken-access-control primitive.
- **Offensive arsenal.** JWT forging/cracking, GraphQL introspection to IDOR candidates,
  cloud metadata/IMDS credential theft, secret and tech-stack scanners, Active Directory
  and binary triage, an offline payload corpus, and prompt-injection testing of LLM
  targets.
- **Evidence-first reporting.** Findings with proof, exported as Markdown/HTML/SARIF and
  bug-bounty drafts.
- **Per-role model tiering.** Run high-volume discovery on a cheap model and keep the
  strong model for the hacking-critical operators.

## Models and tiering

Mapache works with a single model, or routes calls to the best model per role/tier.

| Mode | Behavior | Use case |
|------|----------|----------|
| Single (default) | One model runs every call. | Simplest; one local or cloud model. |
| Routed (`--strategy pipeline\|auto\|hybrid`) | Best installed model per role (planner vs executor); hybrid keeps reasoning in the cloud and execution local. | Mixed local/cloud fleets. |
| Tiered (`--tier-model <id>`) | Low-tier discovery operators (recon, OSINT, scanning) run on a cheaper model; hacking-critical operators stay on the strong one. | Cutting swarm cost. |

Providers: Anthropic, OpenAI-compatible, Grok, OpenRouter, and local Ollama.

## Documentation

| Topic | Doc |
|-------|-----|
| Running Mapache, CLI flags, slash commands, config | [Usage](docs/usage.md) |
| The offensive toolchain reference | [Tools](docs/tools.md) |
| The agent loop, state, model routing, safety | [Architecture](docs/architecture.md) |
| Agent roster, delegation, supervisor routing | [Agents](docs/agents.md) |
| The middleware framework and built-in middlewares | [Middleware](docs/middleware.md) |
| Evidence-first findings and report formats | [Reporting](docs/reporting.md) |

`STATUS.md` and `ROADMAP.md` cover internals and planned work.
