"""
model_registry.py — Mapache model registry

Central registry of all available models and their capabilities.
The routing engine queries this to decide which model handles which task.

Each model is registered with:
    - Provider (ollama, openai, openrouter, huggingface)
    - Role suitability scores (planner, executor, verifier, embedder)
    - Context window size
    - Tool calling support
    - Speed/quality tradeoff
    - Hardware requirements

This is what makes the multi-model pipeline intelligent —
the right model gets assigned to the right job automatically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ModelRole(str, Enum):
    PLANNER   = "planner"    # strategic reasoning, goal decomposition
    EXECUTOR  = "executor"   # tool calling, action execution
    VERIFIER  = "verifier"   # output validation, quality checking
    EMBEDDER  = "embedder"   # text embeddings for vector search
    GENERAL   = "general"    # all-purpose fallback


class Provider(str, Enum):
    OLLAMA      = "ollama"
    OPENAI      = "openai"
    OPENROUTER  = "openrouter"
    HUGGINGFACE = "huggingface"
    ANTHROPIC   = "anthropic"
    NOUS        = "nous"
    GROK        = "grok"


@dataclass
class ModelCapabilities:
    """What a model can and can't do."""
    supports_tools: bool = False
    supports_json_mode: bool = True
    supports_streaming: bool = True
    supports_vision: bool = False
    context_window: int = 4096
    max_output_tokens: int = 2048


@dataclass
class ModelProfile:
    """Full profile of a registered model."""

    id: str                          # unique identifier e.g. "qwen2.5:14b"
    provider: Provider
    display_name: str = ""

    # Role suitability (0.0 to 1.0)
    planner_score: float = 0.5
    executor_score: float = 0.5
    verifier_score: float = 0.5
    embedder_score: float = 0.0

    # Characteristics
    capabilities: ModelCapabilities = field(default_factory=ModelCapabilities)
    speed_score: float = 0.5         # 0=slow, 1=very fast
    quality_score: float = 0.5       # 0=weak, 1=excellent
    vram_gb: float = 0.0             # 0 = cloud/CPU
    cost_per_1k_tokens: float = 0.0  # 0 = free/local

    # Metadata
    tags: list[str] = field(default_factory=list)
    notes: str = ""

    @property
    def is_local(self) -> bool:
        # Local == runs on the local Ollama server. A *free* cloud model
        # (cost==0) is still cloud, so it must NOT count as local — otherwise it
        # would slip past the `--allow-cloud` / local_only OPSEC gate.
        return self.provider == Provider.OLLAMA

    @property
    def best_role(self) -> ModelRole:
        scores = {
            ModelRole.PLANNER:  self.planner_score,
            ModelRole.EXECUTOR: self.executor_score,
            ModelRole.VERIFIER: self.verifier_score,
            ModelRole.EMBEDDER: self.embedder_score,
        }
        return max(scores, key=lambda r: scores[r])

    def score_for_role(self, role: ModelRole) -> float:
        mapping = {
            ModelRole.PLANNER:  self.planner_score,
            ModelRole.EXECUTOR: self.executor_score,
            ModelRole.VERIFIER: self.verifier_score,
            ModelRole.EMBEDDER: self.embedder_score,
            ModelRole.GENERAL:  (self.planner_score + self.executor_score) / 2,
        }
        return mapping.get(role, 0.5)


class ModelRegistry:
    """
    Central store of all known models.

    Pre-populated with common models and their characteristics.
    Users can register custom models or override profiles.
    """

    # Pre-built profiles for common models
    DEFAULTS: list[dict] = [
        # ── Local Ollama models ──────────────────────────────────────
        {
            "id": "qwen2.5:14b",
            "provider": Provider.OLLAMA,
            "display_name": "Qwen 2.5 14B",
            "planner_score": 0.80,
            "executor_score": 0.85,
            "verifier_score": 0.75,
            "capabilities": ModelCapabilities(
                supports_tools=True, supports_json_mode=True,
                context_window=32768, max_output_tokens=4096,
            ),
            "speed_score": 0.70,
            "quality_score": 0.80,
            "vram_gb": 10.0,
            "tags": ["local", "tool-use", "recommended"],
            "notes": "Best balance of quality/speed for 12GB VRAM",
        },
        {
            "id": "qwen2.5:7b",
            "provider": Provider.OLLAMA,
            "display_name": "Qwen 2.5 7B",
            "planner_score": 0.65,
            "executor_score": 0.80,
            "verifier_score": 0.60,
            "capabilities": ModelCapabilities(
                supports_tools=True, supports_json_mode=True,
                context_window=32768, max_output_tokens=2048,
            ),
            "speed_score": 0.90,
            "quality_score": 0.65,
            "vram_gb": 5.0,
            "tags": ["local", "fast", "executor"],
            "notes": "Ideal executor — fast tool calling, low VRAM",
        },
        {
            "id": "qwen3:8b",
            "provider": Provider.OLLAMA,
            "display_name": "Qwen 3 8B",
            "planner_score": 0.75,
            "executor_score": 0.80,
            "verifier_score": 0.70,
            "capabilities": ModelCapabilities(
                supports_tools=True, supports_json_mode=True,
                context_window=32768, max_output_tokens=4096,
            ),
            "speed_score": 0.85,
            "quality_score": 0.78,
            "vram_gb": 6.0,
            "tags": ["local", "tool-use"],
        },
        {
            "id": "mistral-nemo",
            "provider": Provider.OLLAMA,
            "display_name": "Mistral Nemo 12B",
            "planner_score": 0.72,
            "executor_score": 0.78,
            "verifier_score": 0.72,
            "capabilities": ModelCapabilities(
                supports_tools=True, supports_json_mode=True,
                context_window=128000, max_output_tokens=4096,
            ),
            "speed_score": 0.75,
            "quality_score": 0.75,
            "vram_gb": 8.0,
            "tags": ["local", "large-context"],
        },
        {
            "id": "llama3.1:8b",
            "provider": Provider.OLLAMA,
            "display_name": "Llama 3.1 8B",
            "planner_score": 0.60,
            "executor_score": 0.65,
            "verifier_score": 0.60,
            "capabilities": ModelCapabilities(
                supports_tools=True, supports_json_mode=True,
                context_window=131072, max_output_tokens=4096,
            ),
            "speed_score": 0.88,
            "quality_score": 0.60,
            "vram_gb": 6.0,
            "tags": ["local", "fast"],
        },
        {
            "id": "nomic-embed-text",
            "provider": Provider.OLLAMA,
            "display_name": "Nomic Embed Text",
            "planner_score": 0.0,
            "executor_score": 0.0,
            "verifier_score": 0.0,
            "embedder_score": 0.90,
            "capabilities": ModelCapabilities(
                supports_tools=False, context_window=8192,
            ),
            "speed_score": 0.95,
            "quality_score": 0.85,
            "vram_gb": 0.5,
            "tags": ["local", "embeddings"],
        },
        # ── OpenAI ────────────────────────────────────────────────────
        {
            "id": "gpt-4o",
            "provider": Provider.OPENAI,
            "display_name": "GPT-4o",
            "planner_score": 0.95,
            "executor_score": 0.90,
            "verifier_score": 0.95,
            "capabilities": ModelCapabilities(
                supports_tools=True, supports_json_mode=True,
                supports_vision=True, context_window=128000,
            ),
            "speed_score": 0.80,
            "quality_score": 0.95,
            "vram_gb": 0.0,
            "cost_per_1k_tokens": 0.005,
            "tags": ["cloud", "high-quality", "planner"],
        },
        {
            "id": "gpt-4o-mini",
            "provider": Provider.OPENAI,
            "display_name": "GPT-4o Mini",
            "planner_score": 0.75,
            "executor_score": 0.80,
            "verifier_score": 0.75,
            "capabilities": ModelCapabilities(
                supports_tools=True, supports_json_mode=True,
                context_window=128000,
            ),
            "speed_score": 0.92,
            "quality_score": 0.75,
            "vram_gb": 0.0,
            "cost_per_1k_tokens": 0.00015,
            "tags": ["cloud", "fast", "cheap", "executor"],
        },
        # ── Anthropic ─────────────────────────────────────────────────
        {
            "id": "claude-opus-4-5",
            "provider": Provider.ANTHROPIC,
            "display_name": "Claude Opus 4.5",
            "planner_score": 0.98,
            "executor_score": 0.88,
            "verifier_score": 0.98,
            "capabilities": ModelCapabilities(
                supports_tools=True, supports_json_mode=True,
                supports_vision=True, context_window=200000,
            ),
            "speed_score": 0.60,
            "quality_score": 0.98,
            "vram_gb": 0.0,
            "cost_per_1k_tokens": 0.015,
            "tags": ["cloud", "planner", "verifier", "best-quality"],
        },
        {
            "id": "claude-sonnet-4-5",
            "provider": Provider.ANTHROPIC,
            "display_name": "Claude Sonnet 4.5",
            "planner_score": 0.90,
            "executor_score": 0.88,
            "verifier_score": 0.90,
            "capabilities": ModelCapabilities(
                supports_tools=True, supports_json_mode=True,
                supports_vision=True, context_window=200000,
            ),
            "speed_score": 0.80,
            "quality_score": 0.92,
            "vram_gb": 0.0,
            "cost_per_1k_tokens": 0.003,
            "tags": ["cloud", "balanced", "recommended-cloud"],
        },
    ]

    def __init__(self) -> None:
        self._models: dict[str, ModelProfile] = {}
        self._load_defaults()

    def _load_defaults(self) -> None:
        for d in self.DEFAULTS:
            profile = ModelProfile(
                id=d["id"],
                provider=d["provider"],
                display_name=d.get("display_name", d["id"]),
                planner_score=d.get("planner_score", 0.5),
                executor_score=d.get("executor_score", 0.5),
                verifier_score=d.get("verifier_score", 0.5),
                embedder_score=d.get("embedder_score", 0.0),
                capabilities=d.get("capabilities", ModelCapabilities()),
                speed_score=d.get("speed_score", 0.5),
                quality_score=d.get("quality_score", 0.5),
                vram_gb=d.get("vram_gb", 0.0),
                cost_per_1k_tokens=d.get("cost_per_1k_tokens", 0.0),
                tags=d.get("tags", []),
                notes=d.get("notes", ""),
            )
            self._models[profile.id] = profile

    def register(self, profile: ModelProfile) -> None:
        self._models[profile.id] = profile

    def get(self, model_id: str) -> Optional[ModelProfile]:
        return self._models.get(model_id)

    def best_for_role(
        self,
        role: ModelRole,
        local_only: bool = False,
        max_vram_gb: float = 0.0,
        available_ids: Optional[list[str]] = None,
    ) -> Optional[ModelProfile]:
        """
        Find the best registered model for a given role.
        Respects hardware constraints.
        """
        candidates = list(self._models.values())

        if local_only:
            candidates = [m for m in candidates if m.is_local]

        if max_vram_gb > 0:
            candidates = [m for m in candidates if m.vram_gb <= max_vram_gb]

        if available_ids:
            candidates = [m for m in candidates if m.id in available_ids]

        if not candidates:
            return None

        return max(candidates, key=lambda m: m.score_for_role(role))

    def list_by_role(self, role: ModelRole) -> list[ModelProfile]:
        return sorted(
            self._models.values(),
            key=lambda m: m.score_for_role(role),
            reverse=True,
        )

    def list_local(self) -> list[ModelProfile]:
        return [m for m in self._models.values() if m.is_local]

    def summary(self) -> str:
        lines = [f"Model Registry ({len(self._models)} models)\n"]
        lines.append(f"{'ID':30s} {'PROVIDER':12s} {'PLAN':6s} {'EXEC':6s} {'VERIF':6s} {'SPEED':6s}")
        lines.append("─" * 70)
        for m in sorted(self._models.values(), key=lambda x: x.quality_score, reverse=True):
            local = "⚡" if m.is_local else "☁"
            lines.append(
                f"{local} {m.id:28s} {m.provider.value:12s} "
                f"{m.planner_score:.2f}  {m.executor_score:.2f}  "
                f"{m.verifier_score:.2f}  {m.speed_score:.2f}"
            )
        return "\n".join(lines)

    def __len__(self) -> int:
        return len(self._models)
