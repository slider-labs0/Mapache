"""
anthropic_provider.py - native Anthropic (Claude) provider.

Speaks the Claude Messages API (POST /v1/messages), which is NOT OpenAI-shaped:
the system prompt is a top-level field, tools use `input_schema`, and tool calls
come back as `tool_use` content blocks. This provider translates Mapache's
message/tool shapes into that API and normalizes the response back into the same
``{"message": {"content": ..., "tool_calls": [...]}}`` envelope the controller
already understands (so `_parse_model_response` / `_normalize_call` need no
changes).

Tool results in Mapache's history are `tool`-role messages (the assistant's
originating `tool_use` block is not stored). Rather than reconstruct the strict
tool_use/tool_result pairing the Messages API requires, tool outputs are
flattened into user text - valid, model-agnostic, and what JSON-mode already
does. The model still receives the tool schemas and can emit fresh tool_use.
"""

from __future__ import annotations

import logging
from typing import Any, AsyncIterator, Optional

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

from core.logger import get_logger

logger = get_logger(__name__)

DEFAULT_BASE_URL = "https://api.anthropic.com"
DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_TIMEOUT = 600.0
DEFAULT_MAX_TOKENS = 4096
ANTHROPIC_VERSION = "2023-06-01"


class AnthropicProvider:
    """Model provider for the Anthropic Claude Messages API."""

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        api_key: str = "",
        timeout: float = DEFAULT_TIMEOUT,
        supports_tools: Optional[bool] = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        if not HAS_HTTPX:
            raise ImportError("httpx is required: pip install httpx")

        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.supports_tools = True if supports_tools is None else supports_tools

        headers = {
            "content-type": "application/json",
            "anthropic-version": ANTHROPIC_VERSION,
        }
        if api_key:
            headers["x-api-key"] = api_key
        self._client = httpx.AsyncClient(timeout=self.timeout, headers=headers)
        logger.info("AnthropicProvider: model=%s url=%s tools=%s",
                    self.model, self.base_url, self.supports_tools)

    # ------------------------------------------------------------------ #
    # Message / tool translation (OpenAI-ish → Anthropic)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _split_messages(
        messages: list[dict[str, Any]],
    ) -> tuple[str, list[dict[str, Any]]]:
        """Return (system_prompt, anthropic_messages).

        System messages are pulled into the top-level `system` field. `tool`
        messages become user text. Consecutive same-role turns are coalesced,
        since the Messages API requires strictly alternating user/assistant.
        """
        system_parts: list[str] = []
        turns: list[tuple[str, str]] = []  # (role, text)
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content") or ""
            if role == "system":
                if content:
                    system_parts.append(content)
                continue
            if role == "tool":
                name = msg.get("tool_name") or msg.get("name") or "tool"
                content = f"[tool:{name}] returned:\n{content}"
                role = "user"
            elif role not in ("user", "assistant"):
                role = "user"
            turns.append((role, content))

        # Coalesce consecutive same-role turns.
        merged: list[dict[str, Any]] = []
        for role, text in turns:
            if merged and merged[-1]["role"] == role:
                merged[-1]["content"] += "\n\n" + text
            else:
                merged.append({"role": role, "content": text})

        # The Messages API requires the first turn to be from the user.
        while merged and merged[0]["role"] != "user":
            merged.pop(0)

        return "\n\n".join(system_parts), merged

    @staticmethod
    def _convert_tool(tool: dict[str, Any]) -> dict[str, Any]:
        """OpenAI function schema → Anthropic tool (`input_schema`)."""
        fn = tool.get("function", tool)
        return {
            "name": fn.get("name", ""),
            "description": fn.get("description", ""),
            "input_schema": fn.get("parameters") or fn.get("input_schema")
            or {"type": "object", "properties": {}},
        }

    def _build_payload(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict]],
    ) -> dict[str, Any]:
        system, conv = self._split_messages(messages)
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": conv,
        }
        if system:
            payload["system"] = system
        if tools and self.supports_tools:
            payload["tools"] = [self._convert_tool(t) for t in tools]
        return payload

    @staticmethod
    def _normalize(data: dict[str, Any]) -> dict[str, Any]:
        """Anthropic response → the {"message": {...}} envelope the loop expects."""
        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        for block in data.get("content") or []:
            btype = block.get("type")
            if btype == "text":
                text_parts.append(block.get("text", ""))
            elif btype == "tool_use":
                tool_calls.append({"function": {
                    "name": block.get("name", ""),
                    "arguments": block.get("input") or {},
                }})
        u = data.get("usage") or {}
        p = int(u.get("input_tokens") or 0)
        c = int(u.get("output_tokens") or 0)
        return {"message": {
            "content": "".join(text_parts),
            "tool_calls": tool_calls or None,
        }, "usage": {"prompt_tokens": p, "completion_tokens": c,
                     "total_tokens": p + c}}

    # ------------------------------------------------------------------ #
    # Chat
    # ------------------------------------------------------------------ #

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict]] = None,
        json_mode: bool = False,
        stream: bool = False,
    ) -> Any:
        data = await self._post("/v1/messages", self._build_payload(messages, tools))
        return self._normalize(data)

    async def chat_stream(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict]] = None,
    ) -> AsyncIterator[str | dict]:
        """Non-incremental stream: emit the tool call, or the text in one chunk.

        A full SSE parser is deferred; this keeps the streaming interface the
        controller expects without depending on incremental deltas.
        """
        result = await self.chat(messages, tools=tools)
        message = result["message"]
        if message.get("tool_calls"):
            fn = message["tool_calls"][0]["function"]
            yield {"type": "tool_call", "tool": fn["name"], "args": fn["arguments"]}
            return
        text = message.get("content") or ""
        if text:
            yield text

    # ------------------------------------------------------------------ #
    # Utilities
    # ------------------------------------------------------------------ #

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = await self._client.post(f"{self.base_url}{path}", json=payload)
            response.raise_for_status()
            return response.json()
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to {self.base_url}.")
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(
                f"{self.base_url} API error {exc.response.status_code}: "
                f"{exc.response.text[:300]}"
            )
        except Exception as exc:
            raise RuntimeError(f"{self.base_url} request failed: {exc}")

    async def is_available(self) -> bool:
        # A configured provider with a key is "available"; the first real call
        # surfaces auth/network errors rather than blocking startup.
        if not self.api_key:
            return False
        try:
            response = await self._client.get(f"{self.base_url}/v1/models", timeout=8.0)
            return response.status_code == 200
        except Exception:
            return True

    def extract_content(self, response: Any) -> str:
        if isinstance(response, dict):
            return (
                response.get("message", {}).get("content", "")
                or response.get("content", "")
            )
        return str(response)

    async def close(self) -> None:
        await self._client.aclose()

    def __repr__(self) -> str:
        return f"AnthropicProvider(model={self.model!r}, url={self.base_url!r})"
