"""
routing_engine.py — Mapache model routing engine

Decides which model handles which task in the pipeline.

Routing strategies:
    AUTO      — best model per role from registry
    SINGLE    — one model does everything
    PIPELINE  — dedicated planner + executor + verifier
    HYBRID    — cloud planner + local executor
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from models.model_registry import ModelProfile, ModelRegistry, ModelRole, Provider
from core.logger import get_logger

logger = get_logger(__name__)


class RoutingStrategy(str, Enum):
    SINGLE   = "single"
    PIPELINE = "pipeline"
    AUTO     = "auto"
    HYBRID   = "hybrid"


@dataclass
class RoutingDecision:
    role: ModelRole
    model_id: str
    provider: str
    reason: str
    fallback_id: Optional[str] = None


# Models that are embedding-only and cannot do chat
EMBEDDING_ONLY_MODELS = {
    "nomic-embed-text",
    "mxbai-embed-large",
    "all-minilm",
    "snowflake-arctic-embed",
    "bge-large",
    "bge-m3",
}


def _is_embedding_only(model_id: str, profile: Optional[ModelProfile]) -> bool:
    """Check if a model is embedding-only and cannot be used for chat."""
    base = model_id.split(":")[0].lower()
    if base in EMBEDDING_ONLY_MODELS:
        return True
    if profile and profile.embedder_score >= 0.8 and profile.executor_score == 0.0:
        return True
    return False


class RoutingEngine:
    """
    Selects the right model for each role in the pipeline.

    Usage:
        engine = RoutingEngine(registry, strategy=RoutingStrategy.PIPELINE)
        engine.set_available_models(["qwen3.5:35b", "qwen2.5:7b"])

        planner_decision  = engine.route(ModelRole.PLANNER)
        executor_decision = engine.route(ModelRole.EXECUTOR)
        verifier_decision = engine.route(ModelRole.VERIFIER)
    """

    def __init__(
        self,
        registry: ModelRegistry,
        strategy: RoutingStrategy = RoutingStrategy.AUTO,
        primary_model_id: Optional[str] = None,
        local_only: bool = True,
        max_vram_gb: float = 12.0,
    ) -> None:
        self.registry = registry
        self.strategy = strategy
        self.primary_model_id = primary_model_id
        self.local_only = local_only
        self.max_vram_gb = max_vram_gb
        self._available: list[str] = []
        self._chat_capable: list[str] = []  # filtered list — no embedding models
        self._overrides: dict[ModelRole, str] = {}

        logger.info(
            "RoutingEngine initialized: strategy=%s local_only=%s",
            strategy.value, local_only,
        )

    def set_available_models(self, model_ids: list[str]) -> None:
        """Tell the engine which models are installed. Filters out embedding-only models."""
        self._available = model_ids

        # Build chat-capable list — exclude embedding-only models
        self._chat_capable = []
        for model_id in model_ids:
            profile = self.registry.get(model_id)
            if _is_embedding_only(model_id, profile):
                logger.debug("Skipping embedding-only model for chat roles: %s", model_id)
                continue
            self._chat_capable.append(model_id)

        if not self._chat_capable and self.primary_model_id:
            self._chat_capable = [self.primary_model_id]

        logger.info(
            "Available models: %d total, %d chat-capable: %s",
            len(model_ids), len(self._chat_capable), self._chat_capable,
        )

    def local_clone(self) -> "RoutingEngine":
        """A local-only sibling of this engine (feature O — OPSEC pinning).

        Shares the registry but forces `local_only=True` AND prunes the candidate
        lists down to local models, so even strategies that don't honor
        `local_only` (SINGLE returns the primary; `_best_chat_model` scans the
        chat list) still resolve to an on-box model. A cloud primary or a cloud
        role-override is dropped in favor of a local one.
        """
        def _is_local(model_id: str) -> bool:
            profile = self.registry.get(model_id)
            # Unknown ids are locally-installed Ollama models not in the registry.
            return profile is None or profile.is_local

        local_chat = [m for m in self._chat_capable if _is_local(m)]
        primary = self.primary_model_id
        if primary and not _is_local(primary):
            primary = local_chat[0] if local_chat else None

        clone = RoutingEngine(
            self.registry,
            strategy=self.strategy,
            primary_model_id=primary,
            local_only=True,
            max_vram_gb=self.max_vram_gb,
        )
        clone._available = list(self._available)
        clone._chat_capable = local_chat
        clone._overrides = {r: m for r, m in self._overrides.items() if _is_local(m)}
        return clone

    def override_role(self, role: ModelRole, model_id: str) -> None:
        self._overrides[role] = model_id
        logger.info("Role override: %s → %s", role.value, model_id)

    def clear_override(self, role: ModelRole) -> None:
        self._overrides.pop(role, None)

    def route(self, role: ModelRole) -> RoutingDecision:
        """Get the model to use for a given role."""

        # Manual override always wins
        if role in self._overrides:
            model_id = self._overrides[role]
            return RoutingDecision(
                role=role,
                model_id=model_id,
                provider=self._get_provider(model_id),
                reason="manual override",
            )

        if self.strategy == RoutingStrategy.SINGLE:
            return self._route_single(role)
        elif self.strategy == RoutingStrategy.PIPELINE:
            return self._route_pipeline(role)
        elif self.strategy == RoutingStrategy.HYBRID:
            return self._route_hybrid(role)
        else:  # AUTO
            return self._route_auto(role)

    # ------------------------------------------------------------------ #
    # Routing strategies
    # ------------------------------------------------------------------ #

    def _route_single(self, role: ModelRole) -> RoutingDecision:
        """One model handles everything."""
        model_id = self.primary_model_id or self._best_chat_model()
        return RoutingDecision(
            role=role,
            model_id=model_id,
            provider=self._get_provider(model_id),
            reason="single model strategy",
        )

    def _route_pipeline(self, role: ModelRole) -> RoutingDecision:
        """Dedicated model per role."""
        if role == ModelRole.PLANNER:
            candidate = self._best_for_role(role, prefer_quality=True)
            return RoutingDecision(
                role=role,
                model_id=candidate,
                provider=self._get_provider(candidate),
                reason="pipeline: highest quality planner",
            )
        elif role == ModelRole.EXECUTOR:
            candidate = self._best_for_role(role, prefer_speed=True, require_tools=True)
            return RoutingDecision(
                role=role,
                model_id=candidate,
                provider=self._get_provider(candidate),
                reason="pipeline: fastest tool-capable executor",
            )
        elif role == ModelRole.VERIFIER:
            candidate = self._best_for_role(role, prefer_quality=True)
            return RoutingDecision(
                role=role,
                model_id=candidate,
                provider=self._get_provider(candidate),
                reason="pipeline: quality verifier",
            )
        else:
            return self._route_auto(role)

    def _route_hybrid(self, role: ModelRole) -> RoutingDecision:
        """Cloud for planning/verification, local for execution."""
        if role in (ModelRole.PLANNER, ModelRole.VERIFIER):
            cloud = self._best_cloud_for_role(role)
            if cloud:
                return RoutingDecision(
                    role=role,
                    model_id=cloud,
                    provider=self._get_provider(cloud),
                    reason="hybrid: cloud model for reasoning role",
                )
        return self._route_auto(role)

    def _route_auto(self, role: ModelRole) -> RoutingDecision:
        """Auto-select best model for role."""
        candidate = self._best_for_role(role)
        return RoutingDecision(
            role=role,
            model_id=candidate,
            provider=self._get_provider(candidate),
            reason=f"auto: best score for {role.value}",
        )

    # ------------------------------------------------------------------ #
    # Selection helpers
    # ------------------------------------------------------------------ #

    def _best_for_role(
        self,
        role: ModelRole,
        prefer_quality: bool = False,
        prefer_speed: bool = False,
        require_tools: bool = False,
    ) -> str:
        """Find the best chat-capable model for a role."""
        candidates = []
        models_to_check = self._chat_capable or [self.primary_model_id]

        for model_id in models_to_check:
            if not model_id:
                continue

            profile = self.registry.get(model_id)

            # Skip embedding-only models
            if _is_embedding_only(model_id, profile):
                continue

            if self.local_only and profile and not profile.is_local:
                continue

            if require_tools and profile and not profile.capabilities.supports_tools:
                continue

            if profile:
                role_score = profile.score_for_role(role)
                if prefer_quality:
                    final_score = role_score * 0.7 + profile.quality_score * 0.3
                elif prefer_speed:
                    final_score = role_score * 0.5 + profile.speed_score * 0.5
                else:
                    final_score = role_score
                speed = profile.speed_score
            else:
                # Unknown model — give it a default score
                final_score = 0.5
                speed = 0.5

            candidates.append((model_id, final_score, speed))

        if not candidates:
            fallback = self.primary_model_id or (self._chat_capable[0] if self._chat_capable else "qwen2.5:14b")
            return fallback

        candidates.sort(key=lambda x: (x[1], x[2]), reverse=True)
        return candidates[0][0]

    def _best_chat_model(self) -> str:
        """Pick single best all-around chat model."""
        if not self._chat_capable:
            return self.primary_model_id or "qwen2.5:14b"

        best = None
        best_score = 0.0
        for model_id in self._chat_capable:
            profile = self.registry.get(model_id)
            if profile:
                score = (profile.quality_score + profile.executor_score) / 2
            else:
                score = 0.5
            if score > best_score:
                best_score = score
                best = model_id

        return best or self._chat_capable[0]

    def _best_cloud_for_role(self, role: ModelRole) -> Optional[str]:
        best = None
        best_score = 0.0
        for model_id in (self._chat_capable or []):
            profile = self.registry.get(model_id)
            if not profile or profile.is_local:
                continue
            score = profile.score_for_role(role)
            if score > best_score:
                best_score = score
                best = model_id
        return best

    def _get_provider(self, model_id: str) -> str:
        if not model_id:
            return Provider.OLLAMA.value
        profile = self.registry.get(model_id)
        if profile:
            return profile.provider.value
        if "/" in model_id:
            return Provider.HUGGINGFACE.value
        return Provider.OLLAMA.value

    def explain(self) -> str:
        """Show routing decisions for all roles."""
        lines = [f"Routing Engine — strategy={self.strategy.value}\n"]
        for role in [ModelRole.PLANNER, ModelRole.EXECUTOR, ModelRole.VERIFIER]:
            decision = self.route(role)
            lines.append(
                f"  {role.value:10s} → {decision.model_id:35s} ({decision.reason})"
            )
        return "\n".join(lines)
