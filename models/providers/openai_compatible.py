"""
openai_compatible.py - Mapache OpenAI-compatible cloud provider (feature G)

One provider class for any OpenAI `/chat/completions`-shaped API. OpenRouter and
Nous Portal are just two configured instances of this (different base_url + key),
which is why feature G needs only one provider, not two.

It is a drop-in for OllamaProvider as far as the controller is concerned: it
returns the same `{"message": {...}}` shape `OllamaProvider.chat()` does, so
`AgentController._parse_model_response` (which reads `raw["message"]["tool_calls"]`
/ `["content"]` and `json.loads`-es string tool arguments) needs zero changes.
Streaming yields the same str-token / `{"type": "tool_call", ...}` pieces the
controller's `_chat` reassembler expects.

OPSEC: this sends prompts (and therefore any target/scan/cred context in them) to
a third party. The router gates whether a cloud provider is used at all
(`--allow-cloud` / config), and the CLI warns when a cloud model is active - see
feature G's routing + warning wiring.
"""

from __future__ import annotations

import asyncio
import json
import random
from typing import Any, AsyncIterator, Optional

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

from core.logger import get_logger

logger = get_logger(__name__)

DEFAULT_TIMEOUT = 300.0
# Retry transient failures (rate limits, 5xx) with backoff so a throttled call
# waits instead of failing the whole engagement. Rate-limited tiers (e.g. NVIDIA
# NIM's free catalog) 429 readily under a benchmark's call rate.
DEFAULT_MAX_RETRIES = 5
_RETRY_STATUSES = {429, 500, 502, 503, 504}


def _retry_after_seconds(headers: Any, attempt: int) -> float:
    """Honor a Retry-After header if present; else exponential backoff with jitter."""
    try:
        ra = headers.get("Retry-After") if headers is not None else None
        if ra is not None:
            return min(float(ra), 60.0)
    except (TypeError, ValueError):
        pass
    return min(2.0 ** attempt, 30.0) + random.uniform(0, 0.5)


def _norm_usage(usage: Any) -> dict[str, int]:
    """Normalize an OpenAI-style usage block to {prompt,completion,total}_tokens."""
    u = usage or {}
    return {
        "prompt_tokens": int(u.get("prompt_tokens") or 0),
        "completion_tokens": int(u.get("completion_tokens") or 0),
        "total_tokens": int(u.get("total_tokens") or 0),
    }


class OpenAICompatibleProvider:
    """A model provider speaking the OpenAI /chat/completions protocol."""

    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str = "",
        timeout: float = DEFAULT_TIMEOUT,
        supports_tools: Optional[bool] = None,
        extra_headers: Optional[dict[str, str]] = None,
    ) -> None:
        if not HAS_HTTPX:
            raise ImportError("httpx is required: pip install httpx")

        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        # Cloud chat models are tool-capable by default; config/profile may override.
        self.supports_tools = True if supports_tools is None else supports_tools

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        if extra_headers:
            headers.update(extra_headers)
        self._client = httpx.AsyncClient(timeout=self.timeout, headers=headers)
        logger.info("OpenAICompatibleProvider: model=%s url=%s tools=%s",
                    self.model, self.base_url, self.supports_tools)

    # ------------------------------------------------------------------ #
    # Chat (non-streaming)
    # ------------------------------------------------------------------ #

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict]] = None,
        json_mode: bool = False,
        stream: bool = False,
    ) -> Any:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }
        if tools and self.supports_tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        elif json_mode:
            payload["response_format"] = {"type": "json_object"}

        data = await self._post("/chat/completions", payload)
        # Normalize choices[0].message → the {"message": {...}} shape the
        # controller already understands (tool_calls in OpenAI form, arguments
        # as a JSON string, are handled by _normalize_call downstream).
        choices = data.get("choices") or [{}]
        message = choices[0].get("message", {}) or {}
        result: dict[str, Any] = {"message": {
            "content": message.get("content") or "",
            "tool_calls": message.get("tool_calls"),
        }}
        result["usage"] = _norm_usage(data.get("usage"))
        return result

    # ------------------------------------------------------------------ #
    # Streaming chat
    # ------------------------------------------------------------------ #

    async def chat_stream(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict]] = None,
    ) -> AsyncIterator[str | dict]:
        """Yield str tokens, or a {"type": "tool_call", ...} dict on a tool call."""
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            # Ask for a final usage chunk so token accounting works while streaming.
            "stream_options": {"include_usage": True},
        }
        if tools and self.supports_tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        url = f"{self.base_url}/chat/completions"
        # Retry the stream-open on transient failures (rate limits / 5xx) with
        # backoff, so a throttled call waits instead of aborting the engagement.
        for attempt in range(DEFAULT_MAX_RETRIES + 1):
            # Tool calls stream as fragments (name in the first delta, arguments
            # across several) - accumulate, then emit once at the end.
            tc_name = ""
            tc_args = ""
            try:
                async with self._client.stream("POST", url, json=payload) as response:
                    # Read the error body while the stream is still OPEN - a streamed
                    # response's .text isn't available until aread(), and touching it
                    # after the context closes raises a confusing error that MASKS the
                    # real API failure (rate limit, bad key, …).
                    if response.status_code in _RETRY_STATUSES and attempt < DEFAULT_MAX_RETRIES:
                        await response.aread()
                        delay = _retry_after_seconds(getattr(response, "headers", None), attempt)
                        logger.warning(
                            "%s stream %s - retrying in %.1fs (attempt %d/%d)",
                            self.base_url, response.status_code, delay,
                            attempt + 1, DEFAULT_MAX_RETRIES)
                    else:
                        if response.status_code >= 400:
                            await response.aread()
                            raise RuntimeError(
                                f"{self.base_url} API error {response.status_code}: "
                                f"{response.text[:300]}")
                        async for line in response.aiter_lines():
                            line = line.strip()
                            if not line or not line.startswith("data:"):
                                continue
                            body = line[len("data:"):].strip()
                            if body == "[DONE]":
                                break
                            try:
                                chunk = json.loads(body)
                            except json.JSONDecodeError:
                                continue
                            # The usage chunk (from stream_options) has empty choices
                            # and arrives just before [DONE] - surface it to the caller.
                            if chunk.get("usage"):
                                yield {"type": "usage", **_norm_usage(chunk["usage"])}
                                continue
                            delta = (chunk.get("choices") or [{}])[0].get("delta", {})
                            for tc in delta.get("tool_calls") or []:
                                fn = tc.get("function", {})
                                if fn.get("name"):
                                    tc_name = fn["name"]
                                if fn.get("arguments"):
                                    tc_args += fn["arguments"]
                            content = delta.get("content")
                            if content:
                                yield content
                        if tc_name:
                            try:
                                args = json.loads(tc_args) if tc_args else {}
                            except json.JSONDecodeError:
                                args = {}
                            yield {"type": "tool_call", "tool": tc_name, "args": args}
                        return  # streamed a good response - done
            except httpx.HTTPStatusError as exc:
                # Fallback if a non-2xx slips through as an exception elsewhere.
                try:
                    await exc.response.aread()
                    detail = exc.response.text[:300]
                except Exception:
                    detail = "(unreadable error body)"
                raise RuntimeError(
                    f"{self.base_url} API error {exc.response.status_code}: {detail}")
            except httpx.ConnectError:
                raise ConnectionError(f"Cannot connect to {self.base_url}.")
            await asyncio.sleep(delay)  # only reached on a retryable status

    # ------------------------------------------------------------------ #
    # Utilities
    # ------------------------------------------------------------------ #

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = None
        for attempt in range(DEFAULT_MAX_RETRIES + 1):
            try:
                response = await self._client.post(f"{self.base_url}{path}", json=payload)
            except httpx.ConnectError:
                raise ConnectionError(f"Cannot connect to {self.base_url}.")
            except Exception as exc:
                raise RuntimeError(f"{self.base_url} request failed: {exc}")
            # Retry transient failures (rate limits / 5xx) with backoff.
            if response.status_code in _RETRY_STATUSES and attempt < DEFAULT_MAX_RETRIES:
                delay = _retry_after_seconds(getattr(response, "headers", None), attempt)
                logger.warning("%s %s - retrying in %.1fs (attempt %d/%d)",
                               self.base_url, response.status_code, delay,
                               attempt + 1, DEFAULT_MAX_RETRIES)
                await asyncio.sleep(delay)
                continue
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise RuntimeError(
                    f"{self.base_url} API error {exc.response.status_code}: "
                    f"{exc.response.text[:300]}"
                )
            return response.json()
        raise RuntimeError(
            f"{self.base_url} API error {response.status_code} after "
            f"{DEFAULT_MAX_RETRIES} retries: {response.text[:300]}")

    async def list_models(self) -> list[str]:
        try:
            response = await self._client.get(f"{self.base_url}/models", timeout=8.0)
            response.raise_for_status()
            return [m.get("id", "") for m in response.json().get("data", [])]
        except Exception:
            return []

    async def is_available(self) -> bool:
        # A configured cloud provider with a key is "available"; avoid a hard
        # network dependency at startup (the first real call surfaces errors).
        if not self.api_key:
            return False
        try:
            response = await self._client.get(f"{self.base_url}/models", timeout=8.0)
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
        return f"OpenAICompatibleProvider(model={self.model!r}, url={self.base_url!r})"
