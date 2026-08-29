<div align="center">
  <img src="assets/mapache-logo.png" alt="Mapache" width="1000">
</div>

<h1 align="center">Mapache</h1>

<p align="center"><i>Autonomous offensive-security agent that runs the full kill chain across every discipline, then closes it with a working exploit, not a guess.</i></p>

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
<a href="https://youtube.com/@internetanarchy-s?si=kcu2YQKxeL0etik4">
  <img src="https://img.shields.io/badge/YouTube-watch-FF0000?style=for-the-badge&logo=youtube&logoColor=white" alt="YouTube">
</a>
<a href="https://github.com/sponsors/slider-labs0">
  <img src="https://img.shields.io/badge/Sponsor-GitHub-EA4AAA?style=for-the-badge&logo=githubsponsors&logoColor=white" alt="GitHub Sponsors">
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
export ANTHROPIC_API_KEY=...     # or OPENAI_API_KEY / XAI_API_KEY / OPENROUTER_API_KEY / NVIDIA_API_KEY
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

Providers: Anthropic, OpenAI-compatible, Grok, OpenRouter, NVIDIA NIM (hosted catalog or a
self-hosted container via `NVIDIA_NIM_URL`), and local Ollama.

## Documentation

Full reference lives in [docs/](docs/README.md). Highlights:

| Topic | Doc |
|-------|-----|
| The agent loop, state, phases, context, safety rails | [Architecture](docs/architecture.md) |
| Single, per-role, and swarm routing; how sub-agents pick a model | [Model routing](docs/model-routing.md) |
| Delegation, the operator roster, the autonomous supervisor | [Multi-agent](docs/multi-agent.md) |
| Built-in playbooks, SKILL.md authoring, hybrid activation | [Skills and playbooks](docs/skills-and-playbooks.md) |
| The offensive toolchain, meta-tools, self-authored tools | [Tools](docs/tools.md) |
| Local, cloud, and native providers | [Providers](docs/providers.md) |
| Execution backends, egress, rules of engagement, self-defense | [Execution and OPSEC](docs/execution-and-opsec.md) |
| Session, knowledge graph, cross-engagement learning | [Memory](docs/memory.md) |
| Middleware framework and built-in middlewares | [Middleware](docs/middleware.md) |
| Evidence-first findings and report formats | [Reporting](docs/reporting.md) |
| Model Context Protocol and the skill hub | [MCP and hub](docs/mcp-and-hub.md) |
| CLI, the full-screen TUI dashboard, the setup wizard, every command | [User interface](docs/ui.md) |
| The config file, environment variables, every option | [Configuration](docs/configuration.md) |
| End-to-end walkthroughs across disciplines | [Use cases](docs/use-cases.md) |

`STATUS.md` and `ROADMAP.md` cover internals and planned work.

## Contributing and reporting bugs

Found a bug, or something not behaving the way this README describes? Please
[open an issue](https://github.com/slider-labs0/Mapache/issues/new). A good report includes:

- what you ran (the command or objective) and what you expected,
- what happened instead, with the exact error text or a short transcript,
- your OS, Python version, and the model/provider in use,
- steps to reproduce, if you have them.

Feature ideas and questions are welcome as issues too.

Pull requests are welcome. Before opening one:

1. Run the test suite and make sure it stays green: `py -3.11 tests/test_core.py`
   (on Windows, prefix `PYTHONUTF8=1`). Use Python 3.11, not 3.14.
2. Add a test for any new behavior or fix, next to the existing ones in `tests/test_core.py`.
3. Keep changes evidence-first and full-spectrum: a new capability should produce a concrete,
   verifiable finding, and should not narrow Mapache to a single discipline.

See `docs/` for architecture and `ROADMAP.md` for where the project is headed.

## Security and responsible use

Mapache is for **authorized** security testing only: your own systems, engagements you have
written permission for, and lab or CTF targets. You are responsible for staying in scope and
within the law. The rules-of-engagement guardrails (see
[Execution and OPSEC](docs/execution-and-opsec.md)) help, but they do not replace authorization.

If you discover a security vulnerability **in Mapache itself**, please do not file it as a
public issue. Report it privately through
[GitHub's security advisories](https://github.com/slider-labs0/Mapache/security/advisories/new)
so it can be fixed before disclosure.
