"""
model_pool.py - Mapache lazy provider pool

Caches one provider per model id. With a MapacheConfig, it builds the *right*
provider per model - Ollama for local models, OpenAICompatibleProvider for models
a cloud provider entry (openrouter / nous / …) claims - so per-role routing can
address local and cloud models interchangeably. Without a config it stays
Ollama-only (backwards-compatible).
"""

from __future__ import annotations

from typing import Any, Optional

from models.providers.ollama_provider import OllamaProvider
from models.providers.openai_compatible import OpenAICompatibleProvider
from models.providers.anthropic_provider import AnthropicProvider
from core.config import KIND_ANTHROPIC
from core.logger import get_logger

logger = get_logger(__name__)


class ModelPool:
    """Lazily builds and reuses providers keyed by model id."""

    def __init__(
        self,
        base_url: str,
        timeout: float = 600.0,
        config: Any = None,
    ) -> None:
        self.base_url = base_url
        self.timeout = timeout
        # Optional MapacheConfig: drives which provider serves which model id.
        self.config = config
        self._providers: dict[str, Any] = {}

    def register(self, model_id: str, provider: Any) -> None:
        """Seed the pool with an already-built provider (e.g. the primary)."""
        self._providers[model_id] = provider

    def get(self, model_id: str) -> Any:
        provider = self._providers.get(model_id)
        if provider is None:
            provider = self._build(model_id)
            self._providers[model_id] = provider
            logger.debug("ModelPool: created provider for %s", model_id)
        return provider

    def _build(self, model_id: str) -> Any:
        """Construct the provider for a model id from the config (or Ollama)."""
        if self.config is not None:
            prov = self.config.provider_for_model(model_id)
            if prov is not None and prov.is_cloud:
                if prov.kind == KIND_ANTHROPIC:
                    return AnthropicProvider(
                        model=model_id,
                        base_url=prov.base_url,
                        api_key=prov.api_key,
                        timeout=self.timeout,
                    )
                return OpenAICompatibleProvider(
                    model=model_id,
                    base_url=prov.base_url,
                    api_key=prov.api_key,
                    timeout=self.timeout,
                )
            base = prov.base_url if prov is not None else self.base_url
            return OllamaProvider(model=model_id, base_url=base, timeout=self.timeout)

        return OllamaProvider(
            model=model_id, base_url=self.base_url, timeout=self.timeout,
        )

    async def close(self) -> None:
        for provider in self._providers.values():
            try:
                await provider.close()
            except Exception:
                pass
        self._providers.clear()
