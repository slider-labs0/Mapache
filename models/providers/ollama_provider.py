"""
ollama_provider.py — Mapache Ollama model provider (v2)

Adds:
- chat_stream() for token-by-token streaming
- Better tool support detection including qwen3
- Increased default timeout
"""

from __future__ import annotations

import json
import logging
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
DEFAULT_TIMEOUT  = 600.0  # 10 minutes — long scans need this


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
    ) -> None:
        if not HAS_HTTPX:
            raise ImportError("httpx is required: pip install httpx")

        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
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
        }

        if tools and self.supports_tools:
            payload["tools"] = tools
        elif json_mode or (tools and not self.supports_tools):
            payload["format"] = "json"

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
        except httpx.ConnectError:
            raise ConnectionError(
                f"Cannot connect to Ollama at {self.base_url}. "
                "Is Ollama running? Try: ollama serve"
            )
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(
                f"Ollama API error {exc.response.status_code}: {exc.response.text}"
            )
        except Exception as exc:
            raise RuntimeError(f"Ollama request failed: {exc}")

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

        except httpx.ConnectError:
            raise ConnectionError(
                f"Cannot connect to Ollama at {self.base_url}."
            )
        except Exception as exc:
            raise RuntimeError(f"Ollama stream failed: {exc}")

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
        }
        base = model.split(":")[0].lower()
        return any(base.startswith(t) for t in tool_capable)

    def __repr__(self) -> str:
        return f"OllamaProvider(model={self.model!r}, url={self.base_url!r})"
