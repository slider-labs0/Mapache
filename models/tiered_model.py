"""
tiered_model.py - explicit cost/quality tiering across sub-agents (Decepticon-style).

The RoutedModel (models/routed_model.py) tiers by SCORED role and needs a populated
registry. This is the simpler, deterministic sibling: an explicit {tier: model_id} map,
so a swarm runs high-volume, low-stakes discovery (recon/OSINT/scanning) on a cheaper
model and keeps the strong model for the hacking-critical operators - the exact lever
that would have stretched the budget the XBOW run exhausted.

Drop-in for the controller's model_provider: same chat/chat_stream/supports_tools
surface. The controller applies per-operator tiering by calling `for_tier(operator.tier)`
when spawning a sub-agent; `for_role` is a passthrough so it also satisfies the
per-role hook harmlessly.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Optional


class TieredModel:
    """Routes each (sub-)agent's calls to a model chosen by its cost/quality tier."""

    def __init__(self, pool: Any, tier_models: dict[str, str], default_model: str,
                 tier: str = "high", on_cloud_call: Optional[Any] = None) -> None:
        self.pool = pool
        self.tier_models = dict(tier_models or {})   # "high"/"low" -> model_id
        self.default_model = default_model
        self.tier = tier if tier in self.tier_models else "high"
        self.on_cloud_call = on_cloud_call
        self._calls: dict[str, int] = {}

    def _model_id(self) -> str:
        return self.tier_models.get(self.tier, self.default_model)

    def _provider(self) -> Any:
        return self.pool.get(self._model_id())

    @property
    def supports_tools(self) -> bool:
        return self._provider().supports_tools

    async def chat(self, messages: list[dict[str, Any]], tools: Optional[list[dict]] = None,
                   json_mode: bool = False, stream: bool = False,
                   role: Optional[Any] = None) -> Any:
        mid = self._model_id()
        self._calls[mid] = self._calls.get(mid, 0) + 1
        return await self.pool.get(mid).chat(messages=messages, tools=tools,
                                             json_mode=json_mode, stream=stream)

    async def chat_stream(self, messages: list[dict[str, Any]],
                          tools: Optional[list[dict]] = None,
                          role: Optional[Any] = None) -> AsyncIterator[Any]:
        mid = self._model_id()
        self._calls[mid] = self._calls.get(mid, 0) + 1
        async for token in self.pool.get(mid).chat_stream(messages=messages, tools=tools):
            yield token

    # -- controller hooks ------------------------------------------------ #

    def for_tier(self, tier: str) -> "TieredModel":
        """A sibling bound to `tier` (the sub-agent's operator.tier)."""
        sib = TieredModel(self.pool, self.tier_models, self.default_model,
                          tier=(tier or "high"), on_cloud_call=self.on_cloud_call)
        sib._calls = self._calls  # share the call tally
        return sib

    def for_role(self, role: Any) -> "TieredModel":
        return self  # tiering is by operator.tier, not model role

    def can_pin_local(self) -> bool:
        return False  # cloud tiering; no local pin

    def stats(self) -> dict[str, int]:
        return dict(self._calls)

    async def list_models(self) -> list[str]:
        return await self._provider().list_models()

    async def is_available(self) -> bool:
        return await self._provider().is_available()

    async def close(self) -> None:
        try:
            await self.pool.close()
        except Exception:
            pass
