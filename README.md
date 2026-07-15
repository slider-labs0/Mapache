# Mapache

An offensive-security AI agent: a ReAct loop over a local model (via [Ollama](https://ollama.com))
or a frontier cloud model, with phase-aware attack-state tracking, an offensive
toolchain (nmap, Metasploit, searchsploit, hydra, john, …), persistent memory,
rules-of-engagement guardrails, an auditable engagement log, and optional
Telegram/Discord operation.

> `STATUS.md` is the source of truth for architecture and progress.

## Requirements

- **Python 3.10+**
- **[Ollama](https://ollama.com)** for local models (`ollama serve`, then pull a model).
  Cloud providers (Anthropic, OpenAI-compatible, Grok) work instead via `--model … --allow-cloud`.
- The offensive tools shell out to their real binaries (`nmap`, `msfconsole`,
  `searchsploit`, …). These are pre-installed on **Kali/ParrotOS**; on other
  distros install the ones you need. Missing tools degrade gracefully — the tool
  reports it, the agent adapts.

## Linux setup

Mapache runs natively on Linux, and Linux (especially Kali) is the recommended
platform — the whole offensive toolchain is packaged there, and the POSIX shell
avoids the quoting workarounds Windows needs.

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

Everything beyond the core is feature-gated; install per feature (uncomment the
matching line in `requirements.txt`):

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

Config lives at `~/.mapache/config.json` (see `python -m cli config show`). Keys
can be stored there or referenced from the environment.

## Running the tests

```bash
python tests/test_core.py
```

(On Windows, prefix with `PYTHONUTF8=1` to avoid console-encoding errors on log
output. On Linux, UTF-8 is already the default — no prefix needed.)

## Windows

Mapache also runs on Windows. Use a normal `py -m venv` / `pip install -r
requirements.txt`, and note that many offensive binaries aren't available on
Windows — routing the agent's shell through an attacker container
(`--attacker-container`) or a remote Kali box (SSH backend) gives it the real
toolchain. See `tests/lab/isolated_lab.sh` for a contained lab.
