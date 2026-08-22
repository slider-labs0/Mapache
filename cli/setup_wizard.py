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
    ALIBABA_MODELS,
    ANTHROPIC_MODELS,
    DEEPSEEK_MODELS,
    DEFAULT_ALIBABA_URL,
    DEFAULT_ANTHROPIC_URL,
    DEFAULT_DEEPSEEK_URL,
    DEFAULT_HUGGINGFACE_URL,
    DEFAULT_MOONSHOT_URL,
    DEFAULT_NOUS_URL,
    DEFAULT_NVIDIA_NIM_URL,
    DEFAULT_OPENAI_URL,
    DEFAULT_OPENROUTER_URL,
    DEFAULT_XAI_URL,
    DEFAULT_ZHIPU_URL,
    GROK_MODELS,
    HUGGINGFACE_MODELS,
    KIND_ANTHROPIC,
    KIND_OLLAMA,
    KIND_OPENAI,
    MOONSHOT_MODELS,
    NVIDIA_NIM_MODELS,
    OPENAI_MODELS,
    ZHIPU_MODELS,
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
    ("nvidia_nim", KIND_OPENAI, DEFAULT_NVIDIA_NIM_URL, "NVIDIA_API_KEY", True),
    ("deepseek", KIND_OPENAI, DEFAULT_DEEPSEEK_URL, "DEEPSEEK_API_KEY", True),
    ("moonshot", KIND_OPENAI, DEFAULT_MOONSHOT_URL, "MOONSHOT_API_KEY", True),
    ("zhipu", KIND_OPENAI, DEFAULT_ZHIPU_URL, "ZHIPU_API_KEY", True),
    ("alibaba", KIND_OPENAI, DEFAULT_ALIBABA_URL, "DASHSCOPE_API_KEY", True),
    ("huggingface", KIND_OPENAI, DEFAULT_HUGGINGFACE_URL, "HF_TOKEN", True),
]

# Suggested model ids per cloud provider for the chooser's pick list.
MODEL_SUGGESTIONS: dict[str, list[str]] = {
    "openrouter": ["anthropic/claude-sonnet-4.6", "anthropic/claude-opus-4.8",
                   "openai/gpt-4.1", "x-ai/grok-4"],
    "anthropic": list(ANTHROPIC_MODELS),
    "openai": list(OPENAI_MODELS),
    "grok": list(GROK_MODELS),
    "nous": ["Hermes-4-405B"],
    "nvidia_nim": list(NVIDIA_NIM_MODELS),
    "deepseek": list(DEEPSEEK_MODELS),
    "moonshot": list(MOONSHOT_MODELS),
    "zhipu": list(ZHIPU_MODELS),
    "alibaba": list(ALIBABA_MODELS),
    "huggingface": list(HUGGINGFACE_MODELS),
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
# Boxed UI (hermes-style neat panels, in Mapache's purple/blue palette)
# --------------------------------------------------------------------------- #

from cli import theme

_COLOR = theme.supports_color()


def _paint(text: str, *styles: str) -> str:
    return theme.paint(text, *styles, color=_COLOR)


def _prompt_char() -> str:
    glyph = "❯" if theme._can_encode("❯") else ">"
    return _paint(f"  {glyph} ", "blue")


def _panel(title: str, lines: list[str]) -> None:
    """Print one titled purple panel; every question lives in its own box."""
    print()
    print(theme.panel(title, lines, color=_COLOR, accent="lav"))


def _read(default: str = "") -> str:
    """Read one answer at the blue prompt beneath the panel; Enter keeps default."""
    try:
        val = input(_prompt_char()).strip().lstrip("﻿")
    except EOFError:
        return default
    return val or default


def _read_secret(current: str = "") -> tuple[str, bool]:
    """Secret answer at the blue prompt. Returns (value, changed); Enter keeps."""
    try:
        val = input(_prompt_char()).strip().lstrip("﻿")
    except EOFError:
        return current, False
    return (val, True) if val else (current, False)


def _menu(title: str, question: str, options: list[tuple[str, str]], *,
          default_idx: int = 0, notes: Optional[list[str]] = None) -> int:
    """Render a numbered menu in a panel and return the chosen index. Accepts a
    number, or a case-insensitive label prefix; Enter takes the default (marked ▸)."""
    lines: list[str] = [_paint(question, "white")]
    for n in (notes or []):
        lines.append(_paint(n, "grey"))
    lines.append("")
    for i, (label, hint) in enumerate(options):
        mark = _paint("▸", "blue") if i == default_idx else " "
        num = _paint(f"{i + 1})", "lavdim")
        lbl = _paint(f"{label:<10}", "bold", "lav")
        tail = _paint(hint, "grey") if hint else ""
        lines.append(f"{mark} {num} {lbl} {tail}".rstrip())
    _panel(title, lines)
    raw = _read()
    if not raw:
        return default_idx
    if raw.isdigit() and 1 <= int(raw) <= len(options):
        return int(raw) - 1
    low = raw.lower()
    for i, (label, _h) in enumerate(options):
        if label.lower().startswith(low):
            return i
    return default_idx


# --------------------------------------------------------------------------- #
# Wizard steps
# --------------------------------------------------------------------------- #


async def _step_ollama(cfg, raw: dict, default_model: str) -> None:
    """Detect Ollama, offer to pull the chosen default if absent (boxed)."""
    from models.providers.ollama_provider import OllamaProvider

    prov = OllamaProvider(model=default_model, base_url=cfg.ollama_url)
    try:
        if not await prov.is_available():
            _panel("Ollama", [_paint("not reachable - start it with:  ollama serve", "amber")])
            return
        models = await prov.list_models()
        have = any(default_model.split(":")[0] in m for m in models)
        status = (_paint(f"up · {len(models)} model(s)", "green") if models
                  else _paint("up · no models yet", "amber"))
        lines = [f"{_paint('endpoint', 'grey')}  {cfg.ollama_url}",
                 f"{_paint('status  ', 'grey')}  {status}"]
        if not have:
            lines.append(_paint(f"'{default_model}' not installed", "amber"))
        _panel("Ollama", lines)
        if not have and _prompt_bool(f"Pull '{default_model}' now? (large download)",
                                     default=False):
            await prov.pull_model(default_model)
            print(_paint(f"  ok  pulled {default_model}", "green"))
    finally:
        await prov.close()


def _step_bins() -> None:
    """Compact one-panel view of which optional offensive bins are on PATH."""
    present, missing = [], []
    for name, desc in OPTIONAL_BINS:
        (present if shutil.which(name) else missing).append(name)
    lines = []
    if present:
        lines.append(f"{_paint('found  ', 'green')} {', '.join(present)}")
    if missing:
        lines.append(f"{_paint('missing', 'grey')} {', '.join(missing)}")
        lines.append(_paint("(missing tools just disable their feature - none required)", "grey"))
    _panel("Offensive toolchain", lines or [_paint("nothing detected", "grey")])


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
    """List installed Ollama models and return them (empty if none/unreachable)."""
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
    return installed


def _choose_model(title: str, question: str, options: list[str], default: str) -> str:
    """Panel listing candidate model ids; accept a number, a typed id, or Enter."""
    lines = [_paint(question, "white"), ""]
    if options:
        for i, m in enumerate(options, 1):
            mark = _paint("▸", "blue") if m == default else " "
            lines.append(f"{mark} {_paint(str(i) + ')', 'lavdim')} {_paint(m, 'lav')}")
    else:
        lines.append(_paint("(no models detected - type an id, pull it later)", "grey"))
    _panel(title, lines)
    raw = _read(default)
    if raw.isdigit() and 1 <= int(raw) <= len(options):
        return options[int(raw) - 1]
    return raw or default


def _cloud_model_options(name: str, cur) -> list[str]:
    existing = list(cur.models) if cur and cur.models else []
    return existing + [s for s in MODEL_SUGGESTIONS.get(name, []) if s not in existing]


async def _step_choose_provider_model(cfg, raw: dict) -> "tuple[str, bool, tuple]":
    """Provider + one default model, each in its own panel. Returns
    (model_id, is_cloud, provider_entry)."""
    prov_opts = [(nm, "local" if not cloud else "cloud")
                 for (nm, _k, _u, _e, cloud) in PROVIDER_MENU]
    cur_prov = cfg.provider_for_model(cfg.default_model)
    default_name = cur_prov.name if cur_prov else "ollama"
    default_idx = next((i for i, (nm, *_r) in enumerate(PROVIDER_MENU)
                        if nm == default_name), 0)
    idx = _menu("Model provider", "Which provider should Mapache use?",
                prov_opts, default_idx=default_idx)
    entry = PROVIDER_MENU[idx]
    name, kind, base_url, env_var, is_cloud = entry

    if not is_cloud:
        installed = await _pick_ollama_model(cfg, cfg.default_model)
        model_id = _choose_model("Model", "Pick a local model (Ollama):",
                                 installed, cfg.default_model or "qwen2.5:32b")
        configure_model_choice(raw, provider_name=name, kind=kind,
                               base_url=cfg.ollama_url, model_id=model_id,
                               is_cloud=False)
    else:
        cur = cfg.providers.get(name)
        cur_key = cur.api_key if cur else ""
        _panel(f"API key · {name}", [
            _paint(f"Paste your {name} key, or leave blank to use ${env_var}.", "white"),
            _paint("Enter keeps the current key.", "grey") if cur_key else "",
        ])
        key, changed = _read_secret(cur_key)
        api_key = key if changed else cur_key
        opts = _cloud_model_options(name, cur)
        model_id = _choose_model("Model", f"Pick a {name} model:", opts,
                                 opts[0] if opts else "")
        configure_model_choice(raw, provider_name=name, kind=kind, base_url=base_url,
                               model_id=model_id, api_key=api_key or None,
                               is_cloud=True)

    access = _paint("cloud", "amber") if is_cloud else _paint("local", "green")
    _panel("Selected", [
        f"{_paint('provider', 'grey')}  {_paint(name, 'bold', 'lav')}",
        f"{_paint('model   ', 'grey')}  {_paint(model_id, 'bold', 'lav')}",
        f"{_paint('access  ', 'grey')}  {access}",
    ])
    if is_cloud and not (key if changed else cur_key):
        print(_paint(f"  ! no {name} key yet - set ${env_var} before launch", "amber"))
    return model_id, is_cloud, entry


async def _step_roles(cfg, raw: dict, base_model: str, entry: tuple, is_cloud: bool) -> None:
    """Optional: one model for everything (default), or a model per role."""
    idx = _menu("Roles", "Use one model for every role, or customize per role?", [
        ("one", f"{base_model} drives lead, sub-agents & verifier"),
        ("per-role", "choose a model for lead / executor / verifier"),
    ], default_idx=0)
    if idx == 0:
        raw.pop("model_roles", None)
        return

    name, kind, base_url, env_var, is_cloud = entry
    if is_cloud:
        options = _cloud_model_options(name, cfg.providers.get(name)) or [base_model]
    else:
        options = await _pick_ollama_model(cfg, base_model) or [base_model]
    roles = [("planner", "Lead / planner  (strategy, decides next move)"),
             ("executor", "Executor        (runs the tools each turn)"),
             ("verifier", "Verifier        (checks the final answer)")]
    chosen: dict[str, str] = {}
    for role_key, role_label in roles:
        chosen[role_key] = _choose_model(
            f"Role · {role_key}", role_label + ":", options, base_model)
    raw["model_roles"] = chosen


def _step_messaging(cfg, raw: dict) -> None:
    """Optional Telegram/Discord bot tokens (skipped unless the operator opts in)."""
    if _menu("Messaging", "Wire up Telegram / Discord control? (optional)",
             [("skip", "run from the terminal only"),
              ("set up", "paste bot tokens now")], default_idx=0) == 0:
        return
    _panel("Telegram", [_paint("Bot token (Enter to skip):", "white")])
    tg, tg_changed = _read_secret(cfg.messaging.telegram_token)
    if tg_changed:
        _nested_set(raw, ("messaging", "telegram_token"), tg)
    _panel("Discord", [_paint("Bot token (Enter to skip):", "white")])
    dc, dc_changed = _read_secret(cfg.messaging.discord_token)
    if dc_changed:
        _nested_set(raw, ("messaging", "discord_token"), dc)


# Friendly strategy names → the value written to config. "swarm" activates the
# multi-agent supervisor at launch (mapache_cli maps it to AUTO routing + fan-out).
_STRATEGIES = [
    ("auto", "Auto", "smart routing - best model per role"),
    ("single", "Solo", "one model, no delegation"),
    ("swarm", "Swarm", "multi-agent team, supervisor-driven"),
]


def _step_prefs(cfg, raw: dict) -> None:
    """The routing strategy, in plain-English names."""
    default_idx = next((i for i, (val, *_r) in enumerate(_STRATEGIES)
                        if val == cfg.default_strategy.lower()), 0)
    idx = _menu("Strategy", "How should Mapache route work?",
                [(label, hint) for _v, label, hint in _STRATEGIES],
                default_idx=default_idx)
    raw["default_strategy"] = _STRATEGIES[idx][0]


async def _step_smoke_test(default_model: str, working_dir: Path) -> None:
    """Send one trivial turn to the chosen default model and report the reply."""
    # Reload so the test reflects exactly what we just wrote.
    cfg = load_config(working_dir=working_dir)
    prov_cfg = cfg.provider_for_model(default_model)
    if prov_cfg is None:
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

    try:
        resp = await provider.chat(
            messages=[{"role": "user", "content": "Reply with exactly one word: pong"}]
        )
        reply = provider.extract_content(resp).strip()
        if reply:
            _panel("Smoke test", [f"{_paint('ok', 'green')}  {default_model} replied: "
                                  f"{_paint(reply[:60], 'lav')}"])
        else:
            _panel("Smoke test", [_paint("empty reply (config saved; model may be loading)",
                                         "amber")])
    except Exception as exc:
        _panel("Smoke test", [_paint(f"failed: {exc}", "amber"),
                              _paint("config saved - fix the model/endpoint and retry", "grey")])
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
    print()
    print(theme.render_logo(color=_COLOR, large=True))
    _panel("Setup", [
        f"{_paint('config', 'grey')}  {gpath}",
        _paint("existing config found - Enter keeps each value", "grey")
        if gpath.is_file() else _paint("first run - let's configure Mapache", "grey"),
    ])

    # Effective view drives the shown defaults; the raw file is what we edit.
    cfg = load_config(working_dir=working_dir)
    raw = load_global_raw()

    default_model, is_cloud, entry = await _step_choose_provider_model(cfg, raw)
    await _step_roles(cfg, raw, default_model, entry, is_cloud)
    if not is_cloud:
        await _step_ollama(cfg, raw, default_model)
    _step_bins()
    _step_prefs(cfg, raw)
    _step_messaging(cfg, raw)

    saved = save_global_config(raw)
    _panel("Done", [
        f"{_paint('saved', 'grey')}   {saved}",
        f"{_paint('launch', 'grey')}  mapache serve",
        f"{_paint('config', 'grey')}  mapache config show",
    ])

    if not args.no_smoke_test:
        await _step_smoke_test(default_model, working_dir)
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
