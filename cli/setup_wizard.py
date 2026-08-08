#!/usr/bin/env python3
"""
setup_wizard.py - Mapache interactive setup (feature C1)

`mapache setup` walks an operator through a first-run configuration and writes
the result to the global config file (`~/.mapache/config.json`). It is the
companion to the C0 config loader (`core/config.py`): the loader reads, this
writes.

What it does, in order:
  1. Detect Ollama at the configured URL; list installed models and offer to
     pull the chosen default if it is missing.
  2. Check the optional offensive toolchain on PATH (nmap, msfconsole, …) and
     report what is present vs missing - informational, never fatal.
  3. Prompt for cloud-provider API keys (OpenRouter, Nous) and the model ids to
     expose, plus Telegram/Discord tokens.
  4. Write the config, then smoke-test one turn against the chosen default model.

Design notes:
  - **Idempotent.** Every prompt shows the current effective value as its
    default; pressing Enter keeps it. Re-running reports what is already set.
  - **Secret-preserving.** The wizard edits the *raw* global file
    (`load_global_raw`), so a key kept as a `${ENV_VAR}` placeholder - or one
    supplied only by the environment - is never rewritten as a plaintext
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
    ANTHROPIC_MODELS,
    DEFAULT_ANTHROPIC_URL,
    DEFAULT_NOUS_URL,
    DEFAULT_OPENAI_URL,
    DEFAULT_OPENROUTER_URL,
    DEFAULT_XAI_URL,
    GROK_MODELS,
    KIND_ANTHROPIC,
    KIND_OLLAMA,
    KIND_OPENAI,
    OPENAI_MODELS,
    load_config,
    load_global_raw,
    global_config_path,
    save_global_config,
)

# Optional offensive bins we like to see on PATH. Missing ones are reported, not
# required - Mapache degrades to whatever is installed (and remote exec, H, will
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

# Providers the setup chooser offers, in menu order:
#   (name, kind, default base_url, env var, is_cloud).
PROVIDER_MENU = [
    ("ollama", KIND_OLLAMA, "", "", False),
    ("openrouter", KIND_OPENAI, DEFAULT_OPENROUTER_URL, "OPENROUTER_API_KEY", True),
    ("anthropic", KIND_ANTHROPIC, DEFAULT_ANTHROPIC_URL, "ANTHROPIC_API_KEY", True),
    ("openai", KIND_OPENAI, DEFAULT_OPENAI_URL, "OPENAI_API_KEY", True),
    ("grok", KIND_OPENAI, DEFAULT_XAI_URL, "XAI_API_KEY", True),
    ("nous", KIND_OPENAI, DEFAULT_NOUS_URL, "NOUS_API_KEY", True),
]

# Suggested model ids per cloud provider for the chooser's pick list.
MODEL_SUGGESTIONS: dict[str, list[str]] = {
    "openrouter": ["anthropic/claude-sonnet-4.6", "anthropic/claude-opus-4.8",
                   "openai/gpt-4.1", "x-ai/grok-4"],
    "anthropic": list(ANTHROPIC_MODELS),
    "openai": list(OPENAI_MODELS),
    "grok": list(GROK_MODELS),
    "nous": ["Hermes-4-405B"],
}


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
            print("  x  Ollama is not reachable. Start it with:  ollama serve")
            print("     (Then re-run `mapache setup`, or pull models yourself.)")
            return

        models = await prov.list_models()
        if models:
            print(f"  ok  Ollama up - {len(models)} model(s) installed:")
            for m in models:
                print(f"       - {m}")
        else:
            print("  ok  Ollama up - no models installed yet.")

        base = default_model.split(":")[0]
        have = any(base in m for m in models)
        if not have:
            print(f"  [!]  Default model '{default_model}' is not installed.")
            if _prompt_bool(f"Pull '{default_model}' now? (large download)", default=False):
                await prov.pull_model(default_model)
                print(f"  ok  Pulled {default_model}.")
            else:
                print("  - Skipped - pull it later with:  ollama pull " + default_model)
    finally:
        await prov.close()


def _step_bins() -> None:
    """Report which optional offensive bins are on PATH."""
    _hr("Offensive toolchain (PATH)")
    present, missing = [], []
    for name, desc in OPTIONAL_BINS:
        (present if shutil.which(name) else missing).append((name, desc))
    for name, _desc in present:
        print(f"  ok  {name}")
    for name, desc in missing:
        print(f"  -  {name:14s} not found  ({desc})")
    if missing:
        print("  Missing tools just disable their feature; nothing here is required.")


def _resolve_provider(sel: str):
    """Map a menu selection (1-based number or name) to a PROVIDER_MENU entry."""
    sel = (sel or "").strip().lower()
    if sel.isdigit():
        idx = int(sel) - 1
        return PROVIDER_MENU[idx] if 0 <= idx < len(PROVIDER_MENU) else None
    for entry in PROVIDER_MENU:
        if entry[0] == sel:
            return entry
    return None


def configure_model_choice(
    raw: dict,
    *,
    provider_name: str,
    kind: str,
    base_url: str,
    model_id: str,
    api_key: Optional[str] = None,
    is_cloud: bool = False,
) -> str:
    """Record provider_name/model_id as the default in `raw`. Returns model_id.

    For a cloud provider: enable it, store base_url + (optional) key, ensure
    model_id is in its `models` list so `provider_for_model` routes it, and turn
    on `allow_cloud`. Pure config mutation (no I/O), so it is unit-testable.
    """
    raw["default_model"] = model_id
    if is_cloud:
        prov = raw.setdefault("providers", {}).setdefault(provider_name, {})
        prov["kind"] = kind
        prov["base_url"] = base_url
        prov["enabled"] = True
        if api_key:
            prov["api_key"] = api_key
        models = list(prov.get("models") or [])
        if model_id and model_id not in models:
            models.append(model_id)
        prov["models"] = models
        raw["allow_cloud"] = True
    return model_id


async def _pick_ollama_model(cfg, current: str) -> str:
    """List installed Ollama models and let the operator pick one (or type an id)."""
    from models.providers.ollama_provider import OllamaProvider

    prov = OllamaProvider(model=current or "qwen2.5:32b", base_url=cfg.ollama_url)
    installed: list[str] = []
    try:
        if await prov.is_available():
            installed = await prov.list_models()
    except Exception:
        pass
    finally:
        await prov.close()

    if installed:
        print("  Installed local models:")
        for i, m in enumerate(installed, 1):
            print(f"    {i}) {m}")
        sel = _prompt("Choose a model (number or full name)", current or installed[0])
        if sel.isdigit() and 1 <= int(sel) <= len(installed):
            return installed[int(sel) - 1]
        return sel
    print("  [!]  Ollama has no installed models (or is unreachable at "
          f"{cfg.ollama_url}).")
    return _prompt("Enter a model id to use (you can `ollama pull` it later)",
                   current or "qwen2.5:32b")


def _pick_cloud_model(name: str, cur) -> str:
    """Offer suggested + already-configured model ids for a cloud provider."""
    existing = list(cur.models) if cur and cur.models else []
    options = existing + [s for s in MODEL_SUGGESTIONS.get(name, []) if s not in existing]
    if options:
        print(f"  {name} models:")
        for i, m in enumerate(options, 1):
            print(f"    {i}) {m}")
        sel = _prompt("Choose a model (number or full id)", options[0])
        if sel.isdigit() and 1 <= int(sel) <= len(options):
            return options[int(sel) - 1]
        return sel
    return _prompt(f"{name} model id", "")


async def _step_choose_provider_model(cfg, raw: dict) -> tuple[str, bool]:
    """Ask which provider + model to use by default. Returns (model_id, is_cloud)."""
    _hr("Model / provider")
    print("  Which model should Mapache use by default?")
    for i, (name, _k, _u, _e, is_cloud) in enumerate(PROVIDER_MENU, 1):
        print(f"    {i}) {name}  ({'cloud' if is_cloud else 'local'})")

    cur_prov = cfg.provider_for_model(cfg.default_model)
    default_sel = cur_prov.name if cur_prov else "ollama"
    entry = (_resolve_provider(_prompt("Provider (number or name)", default_sel))
             or _resolve_provider(default_sel) or PROVIDER_MENU[0])
    name, kind, base_url, env_var, is_cloud = entry

    if not is_cloud:
        model_id = await _pick_ollama_model(cfg, cfg.default_model)
        configure_model_choice(raw, provider_name=name, kind=kind,
                               base_url=cfg.ollama_url, model_id=model_id,
                               is_cloud=False)
    else:
        cur = cfg.providers.get(name)
        cur_key = cur.api_key if cur else ""
        key, changed = _prompt_secret(f"{name} API key (env: {env_var})", cur_key)
        api_key = key if changed else cur_key
        model_id = _pick_cloud_model(name, cur)
        configure_model_choice(raw, provider_name=name, kind=kind, base_url=base_url,
                               model_id=model_id, api_key=api_key or None,
                               is_cloud=True)
        if not api_key:
            print(f"  [!]  No API key for {name} yet - add one (or set {env_var}) "
                  "before launching this model.")
        else:
            print("  [!]  OPSEC: cloud models may receive target/scan/cred context.")

    print(f"  ok  Default model: {model_id}  (provider: {name})")
    return model_id, is_cloud


def _step_messaging(cfg, raw: dict) -> None:
    """Prompt for Telegram/Discord bot tokens (optional)."""
    _hr("Messaging bots (optional)")
    tg, tg_changed = _prompt_secret("Telegram bot token", cfg.messaging.telegram_token)
    if tg_changed:
        _nested_set(raw, ("messaging", "telegram_token"), tg)
    dc, dc_changed = _prompt_secret("Discord bot token", cfg.messaging.discord_token)
    if dc_changed:
        _nested_set(raw, ("messaging", "discord_token"), dc)


def _step_prefs(cfg, raw: dict) -> None:
    """Prompt for the non-secret defaults (strategy + VRAM). The default model is
    chosen in the model/provider step, not here."""
    _hr("Defaults")
    strat = _prompt("Default strategy (single|pipeline|auto|hybrid)", cfg.default_strategy)
    if strat not in ("single", "pipeline", "auto", "hybrid"):
        print(f"  [!]  Unknown strategy '{strat}', keeping '{cfg.default_strategy}'.")
        strat = cfg.default_strategy
    raw["default_strategy"] = strat

    vram = _prompt("Max VRAM budget (GB, for routing)", str(cfg.max_vram_gb))
    try:
        raw["max_vram_gb"] = float(vram)
    except ValueError:
        print(f"  [!]  '{vram}' is not a number, keeping {cfg.max_vram_gb}.")


async def _step_smoke_test(default_model: str, working_dir: Path) -> None:
    """Send one trivial turn to the chosen default model and report the reply."""
    _hr("Smoke test")
    # Reload so the test reflects exactly what we just wrote.
    cfg = load_config(working_dir=working_dir)
    prov_cfg = cfg.provider_for_model(default_model)
    if prov_cfg is None:
        print("  - No provider resolves the default model; skipping smoke test.")
        return

    if prov_cfg.is_cloud:
        if not cfg.allow_cloud:
            print("  - Default is a cloud model and cloud routing is off; skipping.")
            return
        if not prov_cfg.is_usable:
            print(f"  - Cloud provider '{prov_cfg.name}' has no key; skipping.")
            return
        from models.providers.openai_compatible import OpenAICompatibleProvider
        provider = OpenAICompatibleProvider(
            model=default_model, base_url=prov_cfg.base_url, api_key=prov_cfg.api_key
        )
    else:
        from models.providers.ollama_provider import OllamaProvider
        provider = OllamaProvider(model=default_model, base_url=cfg.ollama_url)
        if not await provider.is_available():
            print("  - Ollama not reachable; skipping smoke test.")
            await provider.close()
            return

    print(f"  Asking '{default_model}' to reply with a single word …")
    try:
        resp = await provider.chat(
            messages=[{"role": "user", "content": "Reply with exactly one word: pong"}]
        )
        reply = provider.extract_content(resp).strip()
        if reply:
            print(f"  ok  Model replied: {reply[:80]!r}")
        else:
            print("  [!]  Model returned an empty reply (config saved, model may be loading).")
    except Exception as exc:
        print(f"  x  Smoke test failed: {exc}")
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
        print("  (existing config found - Enter keeps each current value)")

    # Effective view drives the shown defaults; the raw file is what we edit.
    cfg = load_config(working_dir=working_dir)
    raw = load_global_raw()

    default_model, is_cloud = await _step_choose_provider_model(cfg, raw)
    if not is_cloud:
        # Offer to pull the chosen local model if it isn't installed yet.
        await _step_ollama(cfg, raw, default_model)
    _step_bins()
    _step_prefs(cfg, raw)
    _step_messaging(cfg, raw)

    saved = save_global_config(raw)
    print(f"\n  ok  Saved {saved}")

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
        print("\n# no config files found - built-in defaults in effect")
    print(f"# global config path: {global_config_path()}")
    return 0
