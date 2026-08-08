<div align="center">

<img src="assets/mapache-logo.png" alt="Mapache" width="450">

# Mapache

**autonomous offensive-security agent**

[![Website](https://img.shields.io/badge/Website-visit-6C5CE7?style=for-the-badge&logo=googlechrome&logoColor=white)](https://your-website.example)
[![YouTube](https://img.shields.io/badge/YouTube-watch-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtube.com/@your-channel)
[![Kickstarter](https://img.shields.io/badge/Kickstarter-back%20us-05CE78?style=for-the-badge&logo=kickstarter&logoColor=white)](https://kickstarter.com/projects/your-project)

</div>

A full-spectrum offensive-security AI agent. Mapache runs an observe-act (ReAct) loop
over a local model (via [Ollama](https://ollama.com)) or a frontier cloud model, with
phase-aware attack-state tracking, an autonomous multi-agent supervisor, a large
offensive toolchain, evidence-first reporting, rules-of-engagement guardrails, and
optional Telegram/Discord operation.

> `STATUS.md` is the source of truth for architecture and progress; `ROADMAP.md` tracks
> planned work.

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

## Quickstart

```bash
pip install -r requirements.txt
python -m cli setup      # pick a provider + model (local via Ollama, or a cloud key)
python -m cli            # start the agent
```

Needs Python 3.10+. Kali/ParrotOS is the recommended platform (the offensive toolchain
is packaged there). Missing tools degrade gracefully.

## Documentation

- [Usage](docs/usage.md) - flags, slash commands, cloud models, config.
- [Tools](docs/tools.md) - the offensive toolchain reference.
- [Architecture](docs/architecture.md) - the loop, swarm, and safety layers.
- [Reporting](docs/reporting.md) - evidence-first findings and report formats.

`STATUS.md` and `ROADMAP.md` cover internals and planned work.
