#!/usr/bin/env python3
"""
setup_wizard.py — Mapache interactive setup (feature C1)

`mapache setup` walks an operator through a first-run configuration and writes
the result to the global config file (`~/.mapache/config.json`). It is the
companion to the C0 config loader (`core/config.py`): the loader reads, this
writes.

What it does, in order:
  1. Detect Ollama at the configured URL; list installed models and offer to
     pull the chosen default if it is missing.
  2. Check the optional offensive toolchain on PATH (nmap, msfconsole, …) and
     report what is present vs missing — informational, never fatal.
  3. Prompt for cloud-provider API keys (OpenRouter, Nous) and the model ids to
     expose, plus Telegram/Discord tokens.
  4. Write the config, then smoke-test one turn against the chosen default model.

Design notes:
  - **Idempotent.** Every prompt shows the current effective value as its
    default; pressing Enter keeps it. Re-running reports what is already set.
  - **Secret-preserving.** The wizard edits the *raw* global file
    (`load_global_raw`), so a key kept as a `${ENV_VAR}` placeholder — or one
    supplied only by the environment — is never rewritten as a plaintext
    literal. A secret is only written when the operator types a new value.

`mapache config show` / `config path` (also routed here) print the effective
config (secrets redacted) and the file location.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path
from typing import Any, Optional

from core.config import (
    DEFAULT_NOUS_URL,
    DEFAULT_OPENROUTER_URL,
    KIND_OPENAI,
    load_config,
    load_global_raw,
    global_config_path,
    save_global_config,
)

# Optional offensive bins we like to see on PATH. Missing ones are reported, not
# required — Mapache degrades to whatever is installed (and remote exec, H, will
# eventually cover the gaps).
OPTIONAL_BINS = [
    ("nmap", "port/service scanning"),
    ("msfconsole", "Metasploit exploitation"),
    ("searchsploit", "ExploitDB lookup"),
    ("john", "password cracking"),
    ("hashcat", "GPU password cracking"),
    ("hydra", "network brute force"),
    ("gobuster", "directory brute force"),
    ("nikto", "web vuln scanning"),
    ("tor", "anonymized fetches"),
]

# Cloud providers the wizard can configure: name → (default base_url, env var).
CLOUD_PROVIDERS = [
    ("openrouter", DEFAULT_OPENROUTER_URL, "OPENROUTER_API_KEY"),
    ("nous", DEFAULT_NOUS_URL, "NOUS_API_KEY"),
]


# --------------------------------------------------------------------------- #
# Prompt helpers
# --------------------------------------------------------------------------- #


def _prompt(label: str, default: str = "") -> str:
    """Free-text prompt; empty input keeps `default`."""
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"  {label}{suffix}: ").strip().lstrip("﻿")
    except EOFError:
        return default
    return val or default


def _prompt_secret(label: str, current: str = "") -> tuple[str, bool]:
    """Secret prompt. Returns (value, changed).

    Shows the current value masked; empty input keeps it (changed=False) so the
    caller can leave the raw file untouched and preserve `${ENV}` placeholders.
    """
    shown = ("***" + current[-4:]) if current and len(current) > 4 else ("set" if current else "")
    suffix = f" [{shown}, Enter to keep]" if shown else ""
    try:
        val = input(f"  {label}{suffix}: ").strip().lstrip("﻿")
    except EOFError:
        return current, False
    if not val:
        return current, False
    return val, True


def _prompt_bool(label: str, default: bool) -> bool:
    d = "Y/n" if default else "y/N"
    try:
        val = input(f"  {label} [{d}]: ").strip().lower()
    except EOFError:
        return default
    if not val:
        return default
    return val in ("y", "yes", "on", "true", "1")


def _nested_set(d: dict, path: tuple[str, ...], value: Any) -> None:
    cur = d
    for key in path[:-1]:
        cur = cur.setdefault(key, {})
    cur[path[-1]] = value


def _hr(title: str) -> None:
    print(f"\n── {title} " + "─" * max(0, 56 - len(title)))


# --------------------------------------------------------------------------- #
# Wizard steps
# --------------------------------------------------------------------------- #


async def _step_ollama(cfg, raw: dict, default_model: str) -> None:
    """Detect Ollama, list models, offer to pull the chosen default if absent."""
    from models.providers.ollama_provider import OllamaProvider

    _hr("Local models (Ollama)")
    url = cfg.ollama_url
    print(f"  Endpoint: {url}")
    prov = OllamaProvider(model=default_model, base_url=url)
    try:
        if not await prov.is_available():
            print("  ✗  Ollama is not reachable. Start it with:  ollama serve")
            print("     (Then re-run `mapache setup`, or pull models yourself.)")
            return

        models = await prov.list_models()
        if models:
            print(f"  ✓  Ollama up — {len(models)} model(s) installed:")
            for m in models:
                print(f"       • {m}")
        else:
            print("  ✓  Ollama up — no models installed yet.")

        base = default_model.split(":")[0]
        have = any(base in m for m in models)
        if not have:
            print(f"  ⚠  Default model '{default_model}' is not installed.")
            if _prompt_bool(f"Pull '{default_model}' now? (large download)", default=False):
                await prov.pull_model(default_model)
                print(f"  ✓  Pulled {default_model}.")
            else:
                print("  • Skipped — pull it later with:  ollama pull " + default_model)
    finally:
        await prov.close()


def _step_bins() -> None:
    """Report which optional offensive bins are on PATH."""
    _hr("Offensive toolchain (PATH)")
    present, missing = [], []
    for name, desc in OPTIONAL_BINS:
        (present if shutil.which(name) else missing).append((name, desc))
    for name, _desc in present:
        print(f"  ✓  {name}")
    for name, desc in missing:
        print(f"  –  {name:14s} not found  ({desc})")
    if missing:
        print("  Missing tools just disable their feature; nothing here is required.")


def _step_cloud(cfg, raw: dict) -> None:
    """Prompt for cloud-provider keys + exposed model ids (G's providers)."""
    _hr("Cloud providers (optional — data leaves this machine)")
    print("  Leave a key blank to skip a provider. Keys are stored in the global")
    print("  config file; you can instead set the env var and enter ${ENV_VAR}.")

    any_key = False
    for name, base_url, env_var in CLOUD_PROVIDERS:
        cur = cfg.providers.get(name)
        cur_key = cur.api_key if cur else ""
        key, changed = _prompt_secret(f"{name} API key (env: {env_var})", cur_key)
        if changed:
            _nested_set(raw, ("providers", name, "kind"), KIND_OPENAI)
            _nested_set(raw, ("providers", name, "api_key"), key)
            _nested_set(raw, ("providers", name, "enabled"), True)
        # If this provider has a key now (typed or pre-existing), collect models.
        effective_key = key if changed else cur_key
        if effective_key:
            any_key = True
            cur_models = ", ".join(cur.models) if cur and cur.models else ""
            models = _prompt(f"{name} model ids (comma-separated)", cur_models)
            ids = [m.strip() for m in models.split(",") if m.strip()]
            if ids:
                _nested_set(raw, ("providers", name, "models"), ids)
            elif not (cur and cur.models):
                print(f"  ⚠  No model ids for {name}; it won't be routable until you add some.")

    if any_key:
        cur_allow = bool(raw.get("allow_cloud", cfg.allow_cloud))
        allow = _prompt_bool("Allow cloud routing by default? (--allow-cloud)", cur_allow)
        raw["allow_cloud"] = allow
        if allow:
            print("  ⚠  OPSEC: cloud models may receive target/scan/cred context.")


def _step_messaging(cfg, raw: dict) -> None:
    """Prompt for Telegram/Discord bot tokens (optional)."""
    _hr("Messaging bots (optional)")
    tg, tg_changed = _prompt_secret("Telegram bot token", cfg.messaging.telegram_token)
    if tg_changed:
        _nested_set(raw, ("messaging", "telegram_token"), tg)
    dc, dc_changed = _prompt_secret("Discord bot token", cfg.messaging.discord_token)
    if dc_changed:
        _nested_set(raw, ("messaging", "discord_token"), dc)


def _step_prefs(cfg, raw: dict) -> str:
    """Prompt for the non-secret defaults. Returns the chosen default_model."""
    _hr("Defaults")
    model = _prompt("Default model", cfg.default_model)
    raw["default_model"] = model

    strat = _prompt("Default strategy (single|pipeline|auto|hybrid)", cfg.default_strategy)
    if strat not in ("single", "pipeline", "auto", "hybrid"):
        print(f"  ⚠  Unknown strategy '{strat}', keeping '{cfg.default_strategy}'.")
        strat = cfg.default_strategy
    raw["default_strategy"] = strat

    vram = _prompt("Max VRAM budget (GB, for routing)", str(cfg.max_vram_gb))
    try:
        raw["max_vram_gb"] = float(vram)
    except ValueError:
        print(f"  ⚠  '{vram}' is not a number, keeping {cfg.max_vram_gb}.")
    return model


async def _step_smoke_test(default_model: str, working_dir: Path) -> None:
    """Send one trivial turn to the chosen default model and report the reply."""
    _hr("Smoke test")
    # Reload so the test reflects exactly what we just wrote.
    cfg = load_config(working_dir=working_dir)
    prov_cfg = cfg.provider_for_model(default_model)
    if prov_cfg is None:
        print("  • No provider resolves the default model; skipping smoke test.")
        return

    if prov_cfg.is_cloud:
        if not cfg.allow_cloud:
            print("  • Default is a cloud model and cloud routing is off; skipping.")
            return
        if not prov_cfg.is_usable:
            print(f"  • Cloud provider '{prov_cfg.name}' has no key; skipping.")
            return
        from models.providers.openai_compatible import OpenAICompatibleProvider
        provider = OpenAICompatibleProvider(
            model=default_model, base_url=prov_cfg.base_url, api_key=prov_cfg.api_key
        )
    else:
        from models.providers.ollama_provider import OllamaProvider
        provider = OllamaProvider(model=default_model, base_url=cfg.ollama_url)
        if not await provider.is_available():
            print("  • Ollama not reachable; skipping smoke test.")
            await provider.close()
            return

    print(f"  Asking '{default_model}' to reply with a single word …")
    try:
        resp = await provider.chat(
            messages=[{"role": "user", "content": "Reply with exactly one word: pong"}]
        )
        reply = provider.extract_content(resp).strip()
        if reply:
            print(f"  ✓  Model replied: {reply[:80]!r}")
        else:
            print("  ⚠  Model returned an empty reply (config saved, model may be loading).")
    except Exception as exc:
        print(f"  ✗  Smoke test failed: {exc}")
        print("     Config was still saved; fix the model/endpoint and retry.")
    finally:
        await provider.close()


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #


async def run_setup(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="mapache setup",
                                 description="Interactive Mapache configuration.")
    ap.add_argument("--dir", "-d", default=os.getcwd(),
                    help="Working dir for project-level config detection.")
    ap.add_argument("--no-smoke-test", action="store_true",
                    help="Skip the final model smoke test.")
    args = ap.parse_args(argv or [])
    working_dir = Path(os.path.abspath(args.dir))

    gpath = global_config_path()
    print("╔══════════════════════════════════════╗")
    print("║   Mapache setup                      ║")
    print("╚══════════════════════════════════════╝")
    print(f"  Writing to: {gpath}")
    if gpath.is_file():
        print("  (existing config found — Enter keeps each current value)")

    # Effective view drives the shown defaults; the raw file is what we edit.
    cfg = load_config(working_dir=working_dir)
    raw = load_global_raw()

    default_model = _step_prefs(cfg, raw)
    await _step_ollama(cfg, raw, default_model)
    _step_bins()
    _step_cloud(cfg, raw)
    _step_messaging(cfg, raw)

    saved = save_global_config(raw)
    print(f"\n  ✓  Saved {saved}")

    if not args.no_smoke_test:
        await _step_smoke_test(default_model, working_dir)

    print("\n  Done. Launch with:  python -m cli --model " + default_model)
    print("  Show config with:   python -m cli config show\n")
    return 0


async def run_config_cmd(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="mapache config",
                                 description="Inspect Mapache configuration.")
    ap.add_argument("subcommand", nargs="?", default="show",
                    choices=["show", "path"])
    ap.add_argument("--dir", "-d", default=os.getcwd())
    args = ap.parse_args(argv or [])

    if args.subcommand == "path":
        print(global_config_path())
        return 0

    cfg = load_config(working_dir=Path(os.path.abspath(args.dir)))
    print(json.dumps(cfg.redacted(), indent=2))
    if cfg.sources:
        print("\n# sources (low → high precedence): " + ", ".join(cfg.sources))
    else:
        print("\n# no config files found — built-in defaults in effect")
    print(f"# global config path: {global_config_path()}")
    return 0
