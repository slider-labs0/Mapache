"""
config.py — Mapache configuration layer (feature C0)

The single place settings come from. Before this, configuration was scattered
across argparse flags and a few ad-hoc `os.environ` reads; this consolidates it
into one typed `MapacheConfig` with a clear precedence chain.

Precedence (highest wins):

    CLI flag  >  project file  >  global file  >  environment  >  built-in default

- **global file**  — `~/.mapache/config.json` (override with $MAPACHE_CONFIG).
  Holds secrets + provider entries; lives outside any repo.
- **project file** — `<working_dir>/mapache.json`. Non-secret per-engagement
  overrides (default model, strategy). Mirrors MCP's `mcp.json` precedent.
- **environment**  — well-known vars (OLLAMA_URL, OPENROUTER_API_KEY, …) mapped
  into the config, plus `${VAR}` interpolation anywhere in a value so a config
  can reference a secret kept only in the environment.

Secrets are stored plaintext in the user-dir file (document a 0600 / .gitignore)
*or* referenced as `"${OPENROUTER_API_KEY}"` and resolved from the environment at
load — an unresolved reference becomes empty (never a literal token on the wire).
`MapacheConfig.redacted()` masks secrets for display (`mapache config show`).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# --------------------------------------------------------------------------- #
# Built-in defaults
# --------------------------------------------------------------------------- #

DEFAULT_OLLAMA_URL = "http://localhost:11434"
# Cloud provider base URLs. OpenRouter is stable; the Nous Portal endpoint is a
# documented default the user can override in config (its API is OpenAI-shaped).
DEFAULT_OPENROUTER_URL = "https://openrouter.ai/api/v1"
DEFAULT_NOUS_URL = "https://inference-api.nousresearch.com/v1"
# Frontier providers: Anthropic speaks its own Messages API (KIND_ANTHROPIC);
# OpenAI is OpenAI-shaped (KIND_OPENAI). Both are pre-listed so a key + a
# --model of a listed id + --allow-cloud works with no config editing.
DEFAULT_ANTHROPIC_URL = "https://api.anthropic.com"
DEFAULT_OPENAI_URL = "https://api.openai.com/v1"
# xAI's Grok API is OpenAI-compatible (KIND_OPENAI), served from api.x.ai.
DEFAULT_XAI_URL = "https://api.x.ai/v1"

KIND_OLLAMA = "ollama"
KIND_OPENAI = "openai_compatible"
KIND_ANTHROPIC = "anthropic"

# Frontier model ids pre-listed on their providers so provider_for_model can
# route them out of the box. Kept to the current-generation models.
ANTHROPIC_MODELS = [
    "claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5-20251001",
]
OPENAI_MODELS = ["gpt-4.1", "gpt-4o", "o4-mini"]
GROK_MODELS = ["grok-4", "grok-3", "grok-3-mini"]


def _default_config() -> dict[str, Any]:
    return {
        "default_model": "deepseek-coder:33b",
        "default_strategy": "single",
        "allow_cloud": False,
        "max_vram_gb": 12.0,
        "providers": {
            "ollama": {
                "kind": KIND_OLLAMA, "base_url": DEFAULT_OLLAMA_URL,
                "api_key": "", "models": [], "enabled": True,
            },
            "openrouter": {
                "kind": KIND_OPENAI, "base_url": DEFAULT_OPENROUTER_URL,
                "api_key": "", "models": [], "enabled": False,
            },
            "nous": {
                "kind": KIND_OPENAI, "base_url": DEFAULT_NOUS_URL,
                "api_key": "", "models": [], "enabled": False,
            },
            "anthropic": {
                "kind": KIND_ANTHROPIC, "base_url": DEFAULT_ANTHROPIC_URL,
                "api_key": "", "models": list(ANTHROPIC_MODELS), "enabled": True,
            },
            "openai": {
                "kind": KIND_OPENAI, "base_url": DEFAULT_OPENAI_URL,
                "api_key": "", "models": list(OPENAI_MODELS), "enabled": True,
            },
            "grok": {
                "kind": KIND_OPENAI, "base_url": DEFAULT_XAI_URL,
                "api_key": "", "models": list(GROK_MODELS), "enabled": True,
            },
        },
        "messaging": {"telegram_token": "", "discord_token": ""},
        # Execution backend (feature H): where `shell` commands run.
        # backend: local | ssh | docker. ssh needs host (+user/port/key);
        # docker needs container OR image (+optional workdir).
        "execution": {"backend": "local"},
        # Egress / operator anonymity: how attack traffic exits, to hide the
        # operator's IP. mode: direct | proxy | tor; proxy = socks5://host:port or
        # http://host:port; wrapper = auto|proxychains|torsocks|none (shell tools).
        "egress": {"mode": "direct"},
        # Integrations: bring-your-own tools the agent can call. Each entry is an
        # http spec (wrap an API like Shodan; keys via ${ENV}) or a command spec
        # (wrap a CLI / GitHub repo). See tools/external_tools.py for the shape.
        "integrations": [],
        # Community skill hub (feature I): registry = path to a local index.json
        # dir (empty disables the hub).
        "hub": {"registry": ""},
        # Voice I/O (Phase 9): enabled + tts/stt backend names (null disables).
        "voice": {"enabled": False, "tts": "null", "stt": "null"},
    }


# Well-known environment variables mapped onto config paths (the "environment"
# precedence layer). `${VAR}` interpolation (below) handles arbitrary references;
# this handles the common ones with no config file present at all.
_ENV_MAP: dict[str, tuple[str, ...]] = {
    "MAPACHE_MODEL": ("default_model",),
    "MAPACHE_STRATEGY": ("default_strategy",),
    "OLLAMA_URL": ("providers", "ollama", "base_url"),
    "OPENROUTER_API_KEY": ("providers", "openrouter", "api_key"),
    "NOUS_API_KEY": ("providers", "nous", "api_key"),
    "ANTHROPIC_API_KEY": ("providers", "anthropic", "api_key"),
    "OPENAI_API_KEY": ("providers", "openai", "api_key"),
    "XAI_API_KEY": ("providers", "grok", "api_key"),
    "GROK_API_KEY": ("providers", "grok", "api_key"),
    "TELEGRAM_BOT_TOKEN": ("messaging", "telegram_token"),
    "DISCORD_BOT_TOKEN": ("messaging", "discord_token"),
}

_SECRET_KEYS = {"api_key", "telegram_token", "discord_token"}
_INTERP = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


# --------------------------------------------------------------------------- #
# Helpers: merge, env layer, interpolation
# --------------------------------------------------------------------------- #


def _deep_merge(base: dict, over: dict) -> dict:
    """Recursively merge `over` onto `base` (over wins). Returns a new dict."""
    out = dict(base)
    for key, val in over.items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], val)
        else:
            out[key] = val
    return out


def _set_path(d: dict, path: tuple[str, ...], value: Any) -> None:
    cur = d
    for key in path[:-1]:
        cur = cur.setdefault(key, {})
    cur[path[-1]] = value


def _env_layer(environ: dict[str, str]) -> dict[str, Any]:
    """Build a config-shaped dict from well-known environment variables."""
    layer: dict[str, Any] = {}
    for env_name, path in _ENV_MAP.items():
        if env_name in environ and environ[env_name] != "":
            _set_path(layer, path, environ[env_name])
    if "MAPACHE_ALLOW_CLOUD" in environ:
        _set_path(layer, ("allow_cloud",),
                  environ["MAPACHE_ALLOW_CLOUD"].lower() in ("1", "true", "yes", "on"))
    return layer


def _interpolate(value: Any, environ: dict[str, str]) -> Any:
    """Resolve `${VAR}` references in any string within the structure.

    An unresolved reference becomes "" rather than a literal `${VAR}` — so a
    secret referenced but absent from the environment is simply unset, never
    sent verbatim.
    """
    if isinstance(value, str):
        return _INTERP.sub(lambda m: environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _interpolate(v, environ) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v, environ) for v in value]
    return value


def _load_json_file(path: Optional[Path]) -> dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


# --------------------------------------------------------------------------- #
# Typed view
# --------------------------------------------------------------------------- #


@dataclass
class ProviderConfig:
    name: str
    kind: str = KIND_OLLAMA
    base_url: str = ""
    api_key: str = ""
    models: list[str] = field(default_factory=list)
    enabled: bool = True

    @property
    def is_cloud(self) -> bool:
        return self.kind != KIND_OLLAMA

    @property
    def is_usable(self) -> bool:
        """Enabled, and (for cloud) actually has a key to authenticate with."""
        if not self.enabled:
            return False
        if self.is_cloud:
            return bool(self.api_key)
        return True


@dataclass
class MessagingConfig:
    telegram_token: str = ""
    discord_token: str = ""


@dataclass
class MapacheConfig:
    default_model: str = "deepseek-coder:33b"
    default_strategy: str = "single"
    allow_cloud: bool = False
    max_vram_gb: float = 12.0
    providers: dict[str, ProviderConfig] = field(default_factory=dict)
    messaging: MessagingConfig = field(default_factory=MessagingConfig)
    # Execution backend (feature H): raw dict ({"backend": "local|ssh|docker", …}).
    execution: dict[str, Any] = field(default_factory=lambda: {"backend": "local"})
    # Egress / operator anonymity: raw dict ({"mode": "direct|proxy|tor", …}).
    egress: dict[str, Any] = field(default_factory=lambda: {"mode": "direct"})
    # Bring-your-own tool specs (http/command). See tools/external_tools.py.
    integrations: list[Any] = field(default_factory=list)
    # Community skill hub (feature I): raw dict ({"registry": "<path>"}).
    hub: dict[str, Any] = field(default_factory=dict)
    # Voice I/O (Phase 9): raw dict ({"enabled": bool, "tts": …, "stt": …}).
    voice: dict[str, Any] = field(default_factory=dict)
    # Engagement budget (optional): {"max_tokens": int, "max_seconds": number}.
    # Enforced by BudgetMiddleware — the loop stops gracefully when exceeded.
    budget: dict[str, Any] = field(default_factory=dict)
    # Human-in-the-loop checkpoints (optional): {"enabled": bool, "every": int,
    # "on_phase_change": bool}. Enforced by HITLMiddleware — the loop pauses for
    # operator approve/deny/steer at milestones.
    hitl: dict[str, Any] = field(default_factory=dict)
    # Paths the config was assembled from, for diagnostics.
    sources: list[str] = field(default_factory=list)

    # -- construction --------------------------------------------------- #

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MapacheConfig":
        providers: dict[str, ProviderConfig] = {}
        for name, raw in (data.get("providers") or {}).items():
            raw = raw or {}
            providers[name] = ProviderConfig(
                name=name,
                kind=raw.get("kind", KIND_OLLAMA),
                base_url=raw.get("base_url", ""),
                api_key=raw.get("api_key", ""),
                models=list(raw.get("models") or []),
                enabled=bool(raw.get("enabled", True)),
            )
        msg = data.get("messaging") or {}
        return cls(
            default_model=data.get("default_model", "deepseek-coder:33b"),
            default_strategy=data.get("default_strategy", "single"),
            allow_cloud=bool(data.get("allow_cloud", False)),
            max_vram_gb=float(data.get("max_vram_gb", 12.0)),
            providers=providers,
            messaging=MessagingConfig(
                telegram_token=msg.get("telegram_token", ""),
                discord_token=msg.get("discord_token", ""),
            ),
            execution=dict(data.get("execution") or {"backend": "local"}),
            egress=dict(data.get("egress") or {"mode": "direct"}),
            integrations=list(data.get("integrations") or []),
            hub=dict(data.get("hub") or {}),
            voice=dict(data.get("voice") or {}),
            budget=dict(data.get("budget") or {}),
            hitl=dict(data.get("hitl") or {}),
            sources=list(data.get("_sources") or []),
        )

    # -- queries -------------------------------------------------------- #

    @property
    def ollama_url(self) -> str:
        prov = self.providers.get("ollama")
        return prov.base_url if prov else DEFAULT_OLLAMA_URL

    def provider_for_model(self, model_id: str) -> Optional[ProviderConfig]:
        """
        Which provider serves a model id. A cloud provider that explicitly lists
        the model wins; otherwise it falls back to the local `ollama` provider
        (which serves any locally-installed model without listing it).
        """
        for prov in self.providers.values():
            if prov.is_cloud and model_id in prov.models:
                return prov
        return self.providers.get("ollama")

    def cloud_models(self) -> list[str]:
        out: list[str] = []
        for prov in self.providers.values():
            if prov.is_cloud and prov.is_usable:
                out.extend(prov.models)
        return out

    def usable_providers(self) -> list[ProviderConfig]:
        return [p for p in self.providers.values() if p.is_usable]

    # -- display -------------------------------------------------------- #

    def to_dict(self, redact: bool = False) -> dict[str, Any]:
        def _secret(v: str) -> str:
            if not v:
                return ""
            return "***" + v[-4:] if len(v) > 4 else "***"

        providers = {}
        for name, p in self.providers.items():
            providers[name] = {
                "kind": p.kind, "base_url": p.base_url,
                "api_key": _secret(p.api_key) if redact else p.api_key,
                "models": list(p.models), "enabled": p.enabled,
            }
        return {
            "default_model": self.default_model,
            "default_strategy": self.default_strategy,
            "allow_cloud": self.allow_cloud,
            "max_vram_gb": self.max_vram_gb,
            "providers": providers,
            "messaging": {
                "telegram_token": _secret(self.messaging.telegram_token) if redact
                else self.messaging.telegram_token,
                "discord_token": _secret(self.messaging.discord_token) if redact
                else self.messaging.discord_token,
            },
            "execution": dict(self.execution),
            "egress": dict(self.egress),
            "integrations": list(self.integrations),
            "hub": dict(self.hub),
            "voice": dict(self.voice),
            "budget": dict(self.budget),
            "hitl": dict(self.hitl),
        }

    def redacted(self) -> dict[str, Any]:
        return self.to_dict(redact=True)


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #


def global_config_path(environ: Optional[dict[str, str]] = None) -> Path:
    environ = environ if environ is not None else dict(os.environ)
    override = environ.get("MAPACHE_CONFIG")
    if override:
        return Path(override)
    return Path(environ.get("USERPROFILE") or environ.get("HOME") or Path.home()) \
        / ".mapache" / "config.json"


def load_config(
    overrides: Optional[dict[str, Any]] = None,
    *,
    working_dir: Optional[str | Path] = None,
    environ: Optional[dict[str, str]] = None,
    global_path: Optional[Path] = None,
) -> MapacheConfig:
    """
    Assemble the effective config across the precedence chain.

    Layers, low → high: defaults, environment, global file, project file,
    `overrides` (CLI). `overrides` should contain only keys the user explicitly
    set on the command line (sparse), so unset flags don't clobber file values.
    """
    environ = environ if environ is not None else dict(os.environ)
    working_dir = Path(working_dir) if working_dir else Path.cwd()
    gpath = global_path if global_path is not None else global_config_path(environ)
    ppath = working_dir / "mapache.json"

    sources: list[str] = []
    merged = _default_config()
    merged = _deep_merge(merged, _env_layer(environ))

    global_data = _load_json_file(gpath)
    if global_data:
        merged = _deep_merge(merged, global_data)
        sources.append(str(gpath))

    project_data = _load_json_file(ppath)
    if project_data:
        merged = _deep_merge(merged, project_data)
        sources.append(str(ppath))

    if overrides:
        merged = _deep_merge(merged, overrides)
        sources.append("cli")

    # Resolve ${VAR} references last, so a value pulled from any layer can point
    # at an environment secret.
    merged = _interpolate(merged, environ)
    merged["_sources"] = sources

    return MapacheConfig.from_dict(merged)


# --------------------------------------------------------------------------- #
# Writing (the setup wizard, C1)
# --------------------------------------------------------------------------- #


def load_global_raw(
    path: Optional[Path] = None, *, environ: Optional[dict[str, str]] = None
) -> dict[str, Any]:
    """Read the global config file verbatim — no merge, no `${VAR}` resolution.

    The wizard edits this raw dict so that secrets kept as `${ENV}` placeholders
    (or values supplied only by the environment) are preserved on save rather
    than baked into the file as literals.
    """
    gpath = path if path is not None else global_config_path(environ)
    return _load_json_file(Path(gpath))


def save_global_config(
    data: dict[str, Any],
    path: Optional[Path] = None,
    *,
    environ: Optional[dict[str, str]] = None,
) -> Path:
    """Write the global config JSON, creating `~/.mapache/` if needed.

    Best-effort tightens permissions to 0600 (a no-op on Windows) since this
    file may hold plaintext secrets.
    """
    gpath = Path(path if path is not None else global_config_path(environ))
    gpath.parent.mkdir(parents=True, exist_ok=True)
    gpath.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(gpath, 0o600)
    except OSError:
        pass
    return gpath
