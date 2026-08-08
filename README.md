<div align="center">
  <img src="assets/mapache-logo.png" alt="Mapache" width="450">
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

Mapache runs an observe-act (ReAct) loop over a local model (via [Ollama](https://ollama.com))
or a frontier cloud model, with phase-aware attack-state tracking, an autonomous
multi-agent supervisor, a large offensive toolchain, evidence-first reporting,
rules-of-engagement guardrails, and optional Telegram/Discord operation.

## Install

Kali/ParrotOS is the recommended platform (the offensive toolchain is packaged there).
Requires Python 3.10+.

```bash
git clone https://github.com/slider-labs0/Mapache.git && cd Mapache
python3 -m venv .venv && source .venv/bin/activate
pip install -e .        # installs the `mapache` command
mapache setup           # interactive: pick a provider + model
mapache serve           # launch the agent
```

For local models, install [Ollama](https://ollama.com) (`ollama serve`, then pull a
model). For a cloud model, set the provider key (for example `ANTHROPIC_API_KEY` or
`OPENROUTER_API_KEY`) and run with `--allow-cloud`. Missing offensive binaries degrade
gracefully; the tool reports it and the agent adapts. See [docs/usage.md](docs/usage.md)
for flags, slash commands, and config.

## What it does

- **Single agent or swarm.** A generalist agent works the kill chain, or an autonomous
  supervisor routes bounded objectives to specialist sub-agents (recon, web, exploit,
  post, cloud, AD, binary, mobile, and more) and fans out on a stall.
- **Real offensive toolchain.** ~60 tools: nmap, Metasploit, searchsploit, sqlmap, ffuf,
  hydra, john, a headless browser, plus specialist weapons (a Burp-style HTTP repeater
  with replay/diff, JWT forging/cracking, GraphQL introspection, cloud metadata/IMDS,
  secret and tech-stack scanners, Active Directory and binary-triage helpers). Anything
  not wrapped runs through `shell`/`kali_run`.
- **Grounded, not guessing.** It reads a target's real forms, endpoints, and disclosed
  credentials into state, looks up payloads from an offline corpus instead of inventing
  them, and detects dead attack vectors so it changes approach instead of spinning.
- **Evidence-first deliverable.** Confirmed weaknesses are recorded as findings with
  severity, evidence, impact, and remediation, and exported as a report (Markdown/HTML,
  plus SARIF and bug-bounty drafts). Success is a proven finding, not just a flag.
- **Safe to run unattended.** Rules-of-engagement scope gating, an always-on
  prompt-injection shield with active detection, an append-only engagement audit log,
  and an optional replayable session recording (asciicast).

## Documentation

- [Usage](docs/usage.md) - flags, slash commands, cloud models, config.
- [Tools](docs/tools.md) - the offensive toolchain reference.
- [Architecture](docs/architecture.md) - the loop, swarm, and safety layers.
- [Reporting](docs/reporting.md) - evidence-first findings and report formats.

`STATUS.md` and `ROADMAP.md` cover internals and planned work.
