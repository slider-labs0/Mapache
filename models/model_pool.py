"""
model_pool.py — Mapache lazy provider pool

Caches one OllamaProvider per model id, all pointed at the same Ollama
server. RoutedModel uses this so per-role routing can address several
installed models without re-creating an HTTP client on every call.
"""

from __future__ import annotations

from typing import Optional

from models.providers.ollama_provider import OllamaProvider
from core.logger import get_logger

logger = get_logger(__name__)


class ModelPool:
    """Lazily builds and reuses OllamaProvider instances keyed by model id."""

    def __init__(self, base_url: str, timeout: float = 600.0) -> None:
        self.base_url = base_url
        self.timeout = timeout
        self._providers: dict[str, OllamaProvider] = {}

    def register(self, model_id: str, provider: OllamaProvider) -> None:
        """Seed the pool with an already-built provider (e.g. the primary)."""
        self._providers[model_id] = provider

    def get(self, model_id: str) -> OllamaProvider:
        provider = self._providers.get(model_id)
        if provider is None:
            provider = OllamaProvider(
                model=model_id,
                base_url=self.base_url,
                timeout=self.timeout,
            )
            self._providers[model_id] = provider
            logger.debug("ModelPool: created provider for %s", model_id)
        return provider

    async def close(self) -> None:
        for provider in self._providers.values():
            try:
                await provider.close()
            except Exception:
                pass
        self._providers.clear()
