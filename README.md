<div align="center">

<img src="assets/mapache-logo.png" alt="Mapache" width="220">

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

## Requirements

- **Python 3.10+**
- **[Ollama](https://ollama.com)** for local models (`ollama serve`, then pull a model).
  Cloud providers (Anthropic, OpenAI-compatible, Grok, OpenRouter) work instead via
  `--model <id> --allow-cloud`.
- The offensive tools shell out to their real binaries (`nmap`, `msfconsole`,
  `searchsploit`, etc.), pre-installed on Kali/ParrotOS. On other distros, install the
  ones you need; missing tools degrade gracefully and the agent adapts.

## Linux setup

Linux (especially Kali) is the recommended platform: the offensive toolchain is packaged
there and the POSIX shell avoids the quoting workarounds Windows needs.

```bash
# 1. Clone
git clone <your-fork-url> Mapache && cd Mapache

# 2. Virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Dependencies (core is just httpx; see requirements.txt for optional extras)
pip install -r requirements.txt

# 4. Local model backend
#    Install Ollama from https://ollama.com, then:
ollama serve &                 # start the daemon
ollama pull qwen2.5:32b        # or any model you like

# 5. Configure once (interactive wizard: pick provider + model), then run
python -m cli setup
python -m cli --model qwen2.5:32b
```

Handy alias so the subcommands read as documented (`mapache setup`, etc.):

```bash
alias mapache='python -m cli'      # add to ~/.bashrc to persist
mapache config show                # inspect the merged config
```

### Optional extras

Everything beyond the core is feature-gated; install per feature (uncomment the matching
line in `requirements.txt`):

```bash
pip install rich                      # nicer CLI panels/colour
pip install pymetasploit3             # msf_* tools via RPC
pip install playwright && playwright install chromium   # headless-browser scraping
pip install python-telegram-bot discord.py              # run Mapache from chat
```

Offensive binaries on Debian/Kali (install what you need):

```bash
sudo apt update && sudo apt install -y nmap metasploit-framework exploitdb hydra john tor
```

### Cloud models (optional)

Set the key for your provider and pass `--allow-cloud`:

```bash
export ANTHROPIC_API_KEY=...        # or OPENAI_API_KEY / XAI_API_KEY / OPENROUTER_API_KEY
python -m cli --model claude-opus-4-8 --allow-cloud
```

Config lives at `~/.mapache/config.json` (see `python -m cli config show`). Keys can be
stored there or referenced from the environment.

## Useful flags and commands

```bash
python -m cli --scope scope.json      # enforce rules-of-engagement (in-scope targets)
python -m cli --cast                  # record the engagement as a replayable asciicast
python -m cli --exec-backend docker   # run shell tools in an attacker container
python -m cli --strategy hybrid       # route model calls per role (local + cloud)
```

Inside a session, slash commands include `/swarm` (toggle the autonomous multi-agent
supervisor), `/report [md|html|both|sarif|bounty|all]` (write the findings report), and
`/scope` (show the active rules-of-engagement).

## Running the tests

```bash
python tests/test_core.py
```

On Windows, prefix with `PYTHONUTF8=1` to avoid console-encoding errors on log output.
On Linux, UTF-8 is already the default.

## Windows

Mapache also runs on Windows. Use a normal `py -m venv` / `pip install -r
requirements.txt`. Many offensive binaries are unavailable on Windows, so route the
agent's shell through an attacker container (`--exec-backend docker`) or a remote Kali
box (SSH backend) for the real toolchain. See `tests/lab/isolated_lab.sh` for a
contained lab.
