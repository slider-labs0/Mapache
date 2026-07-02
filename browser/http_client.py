"""
http_client.py — Mapache HTTP client

Base HTTP client used by both surface web and Tor browsing.
Supports proxy routing (SOCKS5 for Tor), custom headers,
TLS configuration, and response parsing.

Used by:
    - scraping_tools.py  (direct requests, no browser)
    - tor_controller.py  (routes through Tor SOCKS5 proxy)
    - chromium_controller.py (for non-browser requests)
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


# ------------------------------------------------------------------ #
# Response wrapper
# ------------------------------------------------------------------ #

@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    text: str
    elapsed_ms: float
    via_tor: bool = False
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None and 200 <= self.status_code < 400

    @property
    def is_html(self) -> bool:
        ct = self.headers.get("content-type", "")
        return "text/html" in ct

    def extract_title(self) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", self.text, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""

    def extract_text(self) -> str:
        """Strip HTML tags and return plain text."""
        text = re.sub(r"<script[^>]*>.*?</script>", "", self.text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    def extract_links(self, base_url: str = "") -> list[str]:
        """Extract all href links from HTML."""
        links = re.findall(r'href=["\']([^"\']+)["\']', self.text, re.IGNORECASE)
        result = []
        for link in links:
            if link.startswith("http"):
                result.append(link)
            elif link.startswith("/") and base_url:
                parsed = urlparse(base_url)
                result.append(f"{parsed.scheme}://{parsed.netloc}{link}")
        return list(set(result))


# ------------------------------------------------------------------ #
# HTTP Client
# ------------------------------------------------------------------ #

class HttpClient:
    """
    Async HTTP client with proxy support.

    Surface web:
        client = HttpClient()
        response = await client.get("https://example.com")

    Through Tor:
        client = HttpClient(proxy="socks5://127.0.0.1:9050")
        response = await client.get("http://example.onion")
    """

    DEFAULT_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    def __init__(
        self,
        proxy: Optional[str] = None,
        timeout: float = 30.0,
        headers: Optional[dict[str, str]] = None,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
    ) -> None:
        if not HAS_HTTPX:
            raise ImportError("httpx is required: pip install httpx[socks]")

        self.proxy = proxy
        self.timeout = timeout
        self.via_tor = proxy is not None and "9050" in proxy
        self.verify_ssl = verify_ssl

        merged_headers = {**self.DEFAULT_HEADERS, **(headers or {})}

        client_kwargs: dict[str, Any] = {
            "headers": merged_headers,
            "timeout": timeout,
            "follow_redirects": follow_redirects,
            "verify": verify_ssl,
        }

        if proxy:
            client_kwargs["proxy"] = proxy

        self._client = httpx.AsyncClient(**client_kwargs)

    async def get(
        self,
        url: str,
        params: Optional[dict] = None,
        extra_headers: Optional[dict] = None,
    ) -> HttpResponse:
        start = time.monotonic()
        try:
            response = await self._client.get(
                url,
                params=params,
                headers=extra_headers or {},
            )
            elapsed = (time.monotonic() - start) * 1000
            return HttpResponse(
                url=str(response.url),
                status_code=response.status_code,
                headers=dict(response.headers),
                text=response.text,
                elapsed_ms=elapsed,
                via_tor=self.via_tor,
            )
        except httpx.ConnectError as exc:
            return HttpResponse(
                url=url, status_code=0, headers={}, text="",
                elapsed_ms=(time.monotonic() - start) * 1000,
                via_tor=self.via_tor,
                error=f"Connection failed: {exc}",
            )
        except httpx.TimeoutException:
            return HttpResponse(
                url=url, status_code=0, headers={}, text="",
                elapsed_ms=self.timeout * 1000,
                via_tor=self.via_tor,
                error=f"Request timed out after {self.timeout}s",
            )
        except Exception as exc:
            return HttpResponse(
                url=url, status_code=0, headers={}, text="",
                elapsed_ms=(time.monotonic() - start) * 1000,
                via_tor=self.via_tor,
                error=str(exc),
            )

    async def post(
        self,
        url: str,
        data: Optional[dict] = None,
        json: Optional[dict] = None,
        extra_headers: Optional[dict] = None,
    ) -> HttpResponse:
        start = time.monotonic()
        try:
            response = await self._client.post(
                url,
                data=data,
                json=json,
                headers=extra_headers or {},
            )
            elapsed = (time.monotonic() - start) * 1000
            return HttpResponse(
                url=str(response.url),
                status_code=response.status_code,
                headers=dict(response.headers),
                text=response.text,
                elapsed_ms=elapsed,
                via_tor=self.via_tor,
            )
        except Exception as exc:
            return HttpResponse(
                url=url, status_code=0, headers={}, text="",
                elapsed_ms=(time.monotonic() - start) * 1000,
                via_tor=self.via_tor,
                error=str(exc),
            )

    async def request(
        self,
        method: str,
        url: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        json: Optional[dict] = None,
        content: Optional[str] = None,
        extra_headers: Optional[dict] = None,
    ) -> HttpResponse:
        """Generic request for any HTTP method (GET/POST/PUT/DELETE/PATCH/...).

        Bodies are passed as structured values (``json``/``data``) or a raw
        ``content`` string, so payloads containing quotes are transported as
        data and never have to survive shell quoting."""
        start = time.monotonic()
        try:
            response = await self._client.request(
                method.upper(),
                url,
                params=params,
                data=data,
                json=json,
                content=content,
                headers=extra_headers or {},
            )
            elapsed = (time.monotonic() - start) * 1000
            return HttpResponse(
                url=str(response.url),
                status_code=response.status_code,
                headers=dict(response.headers),
                text=response.text,
                elapsed_ms=elapsed,
                via_tor=self.via_tor,
            )
        except Exception as exc:
            return HttpResponse(
                url=url, status_code=0, headers={}, text="",
                elapsed_ms=(time.monotonic() - start) * 1000,
                via_tor=self.via_tor,
                error=str(exc),
            )

    async def check_tor(self) -> tuple[bool, str]:
        """
        Verify Tor connectivity by checking the Tor Project's check page.
        Returns (is_tor, ip_address).
        """
        response = await self.get("https://check.torproject.org/api/ip")
        if response.success:
            import json
            try:
                data = json.loads(response.text)
                return data.get("IsTor", False), data.get("IP", "unknown")
            except Exception:
                pass
        return False, "unknown"

    async def get_ip(self) -> str:
        """Return the current external IP address."""
        for url in ["https://api.ipify.org", "https://icanhazip.com"]:
            resp = await self.get(url)
            if resp.success:
                return resp.text.strip()
        return "unknown"

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
