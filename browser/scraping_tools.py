"""
scraping_tools.py — Mapache web scraping utilities

Structured content extraction from web pages.
Works with both surface web and .onion pages via HttpClient.

Tools exposed to the agent:
    web_fetch      — fetch a URL and return readable content
    web_search     — search the web (DuckDuckGo, no API key needed)
    extract_links  — extract all links from a page
"""

from __future__ import annotations

import asyncio
import re
import urllib.parse
from typing import Any, Optional

from browser.http_client import HttpClient, HttpResponse
from plugins.sdk.base_tool import BaseTool, Permission, ToolResult


# ------------------------------------------------------------------ #
# Content extraction helpers
# ------------------------------------------------------------------ #

def html_to_text(html: str, max_length: int = 8000) -> str:
    """
    Convert HTML to clean readable text.
    Removes scripts, styles, navigation noise.
    """
    # Remove script and style blocks
    html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<nav[^>]*>.*?</nav>", "", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<footer[^>]*>.*?</footer>", "", html, flags=re.DOTALL | re.IGNORECASE)

    # Replace block elements with newlines
    html = re.sub(r"<(?:br|p|div|h[1-6]|li|tr)[^>]*>", "\n", html, flags=re.IGNORECASE)

    # Remove remaining tags
    html = re.sub(r"<[^>]+>", "", html)

    # Decode common HTML entities
    html = html.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    html = html.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")

    # Normalize whitespace
    html = re.sub(r"\n{3,}", "\n\n", html)
    html = re.sub(r"[ \t]+", " ", html)
    html = "\n".join(line.strip() for line in html.splitlines())

    return html.strip()[:max_length]


def format_response(response: HttpResponse, max_content: int = 6000) -> str:
    """Format an HttpResponse into model-friendly text."""
    lines = []
    route = "via Tor" if response.via_tor else "direct"
    lines.append(f"URL: {response.url}")
    lines.append(f"Status: {response.status_code} ({route}, {response.elapsed_ms:.0f}ms)")

    title = response.extract_title()
    if title:
        lines.append(f"Title: {title}")

    if response.error:
        lines.append(f"Error: {response.error}")
        return "\n".join(lines)

    if response.is_html:
        content = html_to_text(response.text, max_length=max_content)
    else:
        content = response.text[:max_content]

    if content:
        lines.append(f"\n--- Content ---\n{content}")

    return "\n".join(lines)


# ------------------------------------------------------------------ #
# Tools
# ------------------------------------------------------------------ #

class WebFetchTool(BaseTool):
    name = "web_fetch"
    description = (
        "Fetch the content of a URL and return readable text. "
        "Works for surface web (http/https) pages. "
        "Use for reading web pages, documentation, news articles, or any URL. "
        "Returns the page title and main text content."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "The URL to fetch (must start with http:// or https://)",
            },
            "extract_links": {
                "type": "boolean",
                "description": "Also return all links found on the page",
                "default": False,
            },
            "max_length": {
                "type": "integer",
                "description": "Maximum characters of content to return (default: 4000)",
                "default": 4000,
            },
        },
        "required": ["url"],
    }
    permissions = {Permission.NETWORK}
    timeout = 30
    tags = ["browser", "web", "fetch"]

    async def execute(
        self,
        url: str,
        extract_links: bool = False,
        max_length: int = 4000,
        **kwargs: Any,
    ) -> ToolResult:
        if not url.startswith(("http://", "https://")):
            return ToolResult.fail(f"Invalid URL: must start with http:// or https://")

        async with HttpClient(timeout=25.0) as client:
            response = await client.get(url)

        if not response.success and response.error:
            return ToolResult.fail(response.error)

        output = format_response(response, max_content=max_length)

        if extract_links:
            links = response.extract_links(url)[:20]
            if links:
                output += f"\n\n--- Links ({len(links)}) ---\n" + "\n".join(links)

        return ToolResult.ok(
            output,
            metadata={"url": url, "status": response.status_code, "via_tor": False},
        )


class WebSearchTool(BaseTool):
    name = "web_search"
    description = (
        "Search the web using DuckDuckGo and return results. "
        "No API key required. Returns titles, URLs, and snippets. "
        "Use for finding information, news, documentation, or researching topics."
    )
    parameters = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "The search query",
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of results to return (default: 5, max: 10)",
                "default": 5,
            },
        },
        "required": ["query"],
    }
    permissions = {Permission.NETWORK}
    timeout = 20
    tags = ["browser", "web", "search"]

    DDG_URL = "https://html.duckduckgo.com/html/"

    async def execute(
        self,
        query: str,
        max_results: int = 5,
        **kwargs: Any,
    ) -> ToolResult:
        max_results = min(max(1, max_results), 10)

        async with HttpClient(timeout=15.0) as client:
            response = await client.post(
                self.DDG_URL,
                data={"q": query, "b": "", "kl": ""},
                extra_headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

        if not response.success:
            return ToolResult.fail(
                response.error or f"Search failed with status {response.status_code}"
            )

        results = self._parse_ddg(response.text, max_results)

        if not results:
            return ToolResult.ok(f"No results found for: {query}")

        lines = [f"Search results for: {query}\n"]
        for i, r in enumerate(results, 1):
            lines.append(f"{i}. {r['title']}")
            lines.append(f"   {r['url']}")
            if r.get("snippet"):
                lines.append(f"   {r['snippet']}")
            lines.append("")

        return ToolResult.ok(
            "\n".join(lines),
            metadata={"query": query, "result_count": len(results)},
        )

    def _parse_ddg(self, html: str, max_results: int) -> list[dict]:
        results = []

        # DuckDuckGo HTML result pattern
        result_blocks = re.findall(
            r'<a[^>]+class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>.*?'
            r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>',
            html,
            re.DOTALL | re.IGNORECASE,
        )

        for url, title, snippet in result_blocks[:max_results]:
            # Clean up
            title = re.sub(r"<[^>]+>", "", title).strip()
            snippet = re.sub(r"<[^>]+>", "", snippet).strip()
            url = url.replace("//duckduckgo.com/l/?uddg=", "")
            url = urllib.parse.unquote(url.split("&")[0])

            if url and title:
                results.append({"url": url, "title": title, "snippet": snippet})

        return results


class TorFetchTool(BaseTool):
    name = "tor_fetch"
    description = (
        "Fetch a URL through the Tor network for anonymous browsing. "
        "Supports both regular URLs (https://) and .onion hidden services. "
        "Requires Tor to be running (tor service or Tor Browser). "
        "Use for accessing dark web pages or browsing anonymously."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "URL to fetch (http://, https://, or .onion address)",
            },
            "tor_port": {
                "type": "integer",
                "description": "Tor SOCKS5 proxy port (default: 9050, Tor Browser uses 9150)",
                "default": 9050,
            },
            "max_length": {
                "type": "integer",
                "description": "Maximum characters of content to return (default: 4000)",
                "default": 4000,
            },
        },
        "required": ["url"],
    }
    permissions = {Permission.NETWORK, Permission.TOR}
    timeout = 60
    tags = ["browser", "tor", "onion", "dark-web"]

    async def execute(
        self,
        url: str,
        tor_port: int = 9050,
        max_length: int = 4000,
        **kwargs: Any,
    ) -> ToolResult:
        proxy = f"socks5://127.0.0.1:{tor_port}"

        try:
            async with HttpClient(
                proxy=proxy,
                timeout=45.0,
                verify_ssl=False,  # Many .onion sites have self-signed certs
            ) as client:
                # First verify Tor is working
                is_tor, ip = await client.check_tor()
                if not is_tor:
                    return ToolResult.fail(
                        f"Tor does not appear to be running on port {tor_port}.\n"
                        f"Start Tor: 'tor' (Linux) or open Tor Browser (Windows/Mac).\n"
                        f"If using Tor Browser, try tor_port=9150 instead."
                    )

                response = await client.get(url)

        except Exception as exc:
            if "SOCKS" in str(exc) or "Connection" in str(exc):
                return ToolResult.fail(
                    f"Cannot connect to Tor on port {tor_port}. "
                    f"Is Tor running? Try: tor_port=9150 for Tor Browser."
                )
            return ToolResult.fail(str(exc))

        if not response.success and response.error:
            return ToolResult.fail(f"Fetch failed: {response.error}")

        output = format_response(response, max_content=max_length)
        output = f"[Routed via Tor — External IP: {ip}]\n\n" + output

        return ToolResult.ok(
            output,
            metadata={"url": url, "via_tor": True, "exit_ip": ip},
        )
