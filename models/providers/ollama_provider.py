"""
ollama_provider.py - Mapache Ollama model provider (v2)

Adds:
- chat_stream() for token-by-token streaming
- Better tool support detection including qwen3
- Increased default timeout
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, AsyncIterator, Optional

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

from core.logger import get_logger

logger = get_logger(__name__)

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL    = "qwen2.5:14b"
DEFAULT_TIMEOUT  = 600.0  # 10 minutes - long scans need this
# Ollama defaults a model's context window to a small value (often 4096), so a
# full Mapache prompt (system prompt + tools + state, ~12-16k tokens) overflows it
# and Ollama returns HTTP 400 "exceeds the available context size". We request a
# larger window via options.num_ctx so any model can hold a real engagement prompt.
# It must exceed the controller's prompt budget (max_context_tokens, 16384) with room
# left for the model's OUTPUT - otherwise a big prompt (e.g. with MCP browser tools)
# fills the whole window and the model's tool call is truncated mid-JSON. So this is
# the prompt budget plus output headroom. Override with OLLAMA_NUM_CTX (raise it for
# heavy tool sets, lower it if a big model runs short on memory).
DEFAULT_NUM_CTX  = 25000
# Transient transport failures worth retrying: Ollama reloading a model, a momentary
# connection reset, or a slow first token on a heavy local model. A 4xx / bad request
# is NOT retried. httpx.TransportError covers connect/read/write/pool timeouts + resets.
_RETRIES = 2
_RETRY_BACKOFF = 1.5  # seconds, multiplied by the attempt number


class OllamaProvider:
    """
    Ollama local model provider with streaming support.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        supports_tools: Optional[bool] = None,
        num_ctx: int = 0,
    ) -> None:
        if not HAS_HTTPX:
            raise ImportError("httpx is required: pip install httpx")

        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        # Context window to request from Ollama (see DEFAULT_NUM_CTX). Explicit arg
        # wins, then the OLLAMA_NUM_CTX env var, then the default.
        try:
            self.num_ctx = num_ctx or int(os.environ.get("OLLAMA_NUM_CTX") or DEFAULT_NUM_CTX)
        except (TypeError, ValueError):
            self.num_ctx = DEFAULT_NUM_CTX
        self.supports_tools = (
            supports_tools
            if supports_tools is not None
            else self._detect_tool_support(model)
        )
        self._client = httpx.AsyncClient(timeout=self.timeout)
        logger.info(
            "OllamaProvider: model=%s supports_tools=%s",
            self.model, self.supports_tools,
        )

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
            "options": {"num_ctx": self.num_ctx},
        }

        if tools and self.supports_tools:
            payload["tools"] = tools
        elif json_mode or (tools and not self.supports_tools):
            payload["format"] = "json"

        last_exc: Optional[Exception] = None
        for attempt in range(_RETRIES + 1):
            try:
                response = await self._client.post(
                    f"{self.base_url}/api/chat",
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
                # Normalize Ollama's eval counts to an OpenAI-style usage block so the
                # controller accounts tokens the same way across providers.
                p = int(data.get("prompt_eval_count") or 0)
                c = int(data.get("eval_count") or 0)
                data["usage"] = {"prompt_tokens": p, "completion_tokens": c,
                                 "total_tokens": p + c}
                return data
            except httpx.HTTPStatusError as exc:
                # 5xx (model loading / transient server error) is worth a retry; a 4xx
                # (e.g. a bad prompt) is not - surface it immediately.
                if exc.response.status_code >= 500 and attempt < _RETRIES:
                    last_exc = exc
                    await asyncio.sleep(_RETRY_BACKOFF * (attempt + 1))
                    continue
                raise RuntimeError(
                    f"Ollama API error {exc.response.status_code}: {exc.response.text}")
            except httpx.TransportError as exc:
                last_exc = exc
                if attempt < _RETRIES:
                    await asyncio.sleep(_RETRY_BACKOFF * (attempt + 1))
                    continue
                break
            except Exception as exc:
                # Non-transport failure (e.g. malformed JSON) - do not retry.
                raise RuntimeError(
                    f"Ollama request failed: {type(exc).__name__}: {exc}")

        # Retries exhausted on a transport error - surface the real cause + type.
        if isinstance(last_exc, httpx.ConnectError):
            raise ConnectionError(
                f"Cannot connect to Ollama at {self.base_url} after {_RETRIES + 1} "
                "attempts. Is Ollama running (ollama serve), or did it run out of memory? "
                f"({type(last_exc).__name__}: {last_exc})")
        raise RuntimeError(
            f"Ollama request failed after {_RETRIES + 1} attempts: "
            f"{type(last_exc).__name__}: {last_exc}")

    # ------------------------------------------------------------------ #
    # Streaming chat
    # ------------------------------------------------------------------ #

    async def chat_stream(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict]] = None,
    ) -> AsyncIterator[str | dict]:
        """
        Stream tokens from Ollama.
        Yields str tokens for text, or dict {"type": "tool_call", ...} for tool calls.
        """
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "options": {"num_ctx": self.num_ctx},
        }

        if tools and self.supports_tools:
            payload["tools"] = tools

        try:
            async with self._client.stream(
                "POST",
                f"{self.base_url}/api/chat",
                json=payload,
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    message = chunk.get("message", {})

                    # Check for tool call in stream
                    tool_calls = message.get("tool_calls")
                    if tool_calls:
                        first = tool_calls[0]
                        fn = first.get("function", first)
                        args = fn.get("arguments", {})
                        if isinstance(args, str):
                            try:
                                args = json.loads(args)
                            except Exception:
                                args = {}
                        yield {"type": "tool_call", "tool": fn.get("name", ""), "args": args}
                        return

                    # Text token
                    content = message.get("content", "")
                    if content:
                        yield content

                    if chunk.get("done"):
                        p = int(chunk.get("prompt_eval_count") or 0)
                        c = int(chunk.get("eval_count") or 0)
                        if p or c:
                            yield {"type": "usage", "prompt_tokens": p,
                                   "completion_tokens": c, "total_tokens": p + c}
                        return

        except httpx.ConnectError as exc:
            raise ConnectionError(
                f"Cannot connect to Ollama at {self.base_url}. Is it running, or did it "
                f"run out of memory? ({type(exc).__name__}: {exc})"
            )
        except Exception as exc:
            raise RuntimeError(f"Ollama stream failed: {type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------ #
    # Utilities
    # ------------------------------------------------------------------ #

    async def list_models(self) -> list[str]:
        try:
            response = await self._client.get(
                f"{self.base_url}/api/tags", timeout=5.0
            )
            response.raise_for_status()
            return [m["name"] for m in response.json().get("models", [])]
        except Exception:
            return []

    async def is_available(self) -> bool:
        try:
            response = await self._client.get(
                f"{self.base_url}/api/tags", timeout=5.0
            )
            return response.status_code == 200
        except Exception:
            return False

    async def pull_model(self, model_name: str) -> None:
        logger.info("Pulling model: %s", model_name)
        async with self._client.stream(
            "POST",
            f"{self.base_url}/api/pull",
            json={"name": model_name},
        ) as response:
            async for line in response.aiter_lines():
                if line:
                    try:
                        data = json.loads(line)
                        status = data.get("status", "")
                        if "total" in data and data["total"]:
                            pct = int(data.get("completed", 0) / data["total"] * 100)
                            print(f"\r  Pulling {model_name}: {status} {pct}%", end="", flush=True)
                        else:
                            print(f"\r  {status}                    ", end="", flush=True)
                    except Exception:
                        pass
        print()

    def extract_content(self, response: Any) -> str:
        if isinstance(response, dict):
            return (
                response.get("message", {}).get("content", "")
                or response.get("content", "")
            )
        return str(response)

    async def close(self) -> None:
        await self._client.aclose()

    def _detect_tool_support(self, model: str) -> bool:
        tool_capable = {
            "llama3.1", "llama3.2", "llama3.3",
            "mistral-nemo", "mistral-small",
            "qwen2.5", "qwen2.5-coder",
            "qwen3",
            "command-r", "command-r-plus",
            "firefunction-v2",
            "hermes3",
            "ornith",  # agentic-coding family, native tool calling
        }
        base = model.split(":")[0].lower()
        return any(base.startswith(t) for t in tool_capable)

    def __repr__(self) -> str:
        return f"OllamaProvider(model={self.model!r}, url={self.base_url!r})"
