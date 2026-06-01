"""
routed_model.py — Mapache routed model provider

A model-provider facade that routes each call to the best installed model
for the role, via RoutingEngine + ModelRegistry + ModelPool. It is a drop-in
replacement for a single OllamaProvider as AgentController's model_provider:
it exposes the same chat() / chat_stream() / supports_tools surface the
controller and CLI rely on.

The ReAct loop in AgentController._agent_loop drives tool-calling, so calls
default to the EXECUTOR role. Callers that want a different role (e.g. a
verifier reflection step) can pass role=ModelRole.VERIFIER.

This is what makes Phase 7 routing actually take effect: previously the
RoutingEngine and ModelRegistry existed but nothing in the live turn path
consulted them.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Optional

from models.model_registry import ModelRole
from models.routing_engine import RoutingEngine, RoutingStrategy
from models.model_pool import ModelPool
from core.logger import get_logger

logger = get_logger(__name__)


class RoutedModel:
    """Routes model calls to the best installed model per role."""

    def __init__(
        self,
        routing_engine: RoutingEngine,
        pool: ModelPool,
        primary_model_id: str,
        default_role: ModelRole = ModelRole.EXECUTOR,
    ) -> None:
        self.routing = routing_engine
        self.pool = pool
        self.primary_model_id = primary_model_id
        self.default_role = default_role
        self._calls: dict[str, int] = {}  # model_id -> call count

    # ------------------------------------------------------------------ #
    # Routing
    # ------------------------------------------------------------------ #

    def model_for(self, role: ModelRole) -> str:
        """Resolve the model id the engine would use for a role."""
        decision = self.routing.route(role)
        return decision.model_id or self.primary_model_id

    def _provider_for(self, role: ModelRole):
        return self.pool.get(self.model_for(role))

    # ------------------------------------------------------------------ #
    # Provider interface (matches OllamaProvider)
    # ------------------------------------------------------------------ #

    @property
    def supports_tools(self) -> bool:
        # Tool-calling capability is decided by whichever model runs the loop.
        return self._provider_for(self.default_role).supports_tools

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict]] = None,
        json_mode: bool = False,
        stream: bool = False,
        role: Optional[ModelRole] = None,
    ) -> Any:
        role = role or self.default_role
        model_id = self.model_for(role)
        self._calls[model_id] = self._calls.get(model_id, 0) + 1
        provider = self.pool.get(model_id)
        return await provider.chat(
            messages=messages,
            tools=tools,
            json_mode=json_mode,
            stream=stream,
        )

    async def chat_stream(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict]] = None,
        role: Optional[ModelRole] = None,
    ) -> AsyncIterator[str | dict]:
        role = role or self.default_role
        model_id = self.model_for(role)
        self._calls[model_id] = self._calls.get(model_id, 0) + 1
        provider = self.pool.get(model_id)
        async for token in provider.chat_stream(messages=messages, tools=tools):
            yield token

    # ------------------------------------------------------------------ #
    # Control / introspection
    # ------------------------------------------------------------------ #

    def set_strategy(self, strategy: RoutingStrategy) -> None:
        self.routing.strategy = strategy

    def explain(self) -> str:
        return self.routing.explain()

    def stats(self) -> dict[str, int]:
        return dict(self._calls)

    async def list_models(self) -> list[str]:
        return await self.pool.get(self.primary_model_id).list_models()

    async def is_available(self) -> bool:
        return await self.pool.get(self.primary_model_id).is_available()

    async def close(self) -> None:
        await self.pool.close()
