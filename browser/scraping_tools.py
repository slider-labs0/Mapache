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
# Attack-surface recon (grounding: read the real app before acting)
# ------------------------------------------------------------------ #

def _extract_forms(html: str) -> list[dict]:
    """Forms with their REAL action/method and input field names — so the agent
    submits the actual field names (not a guessed 'username'/'password') and posts
    to the real endpoint instead of an invented one."""
    forms = []
    for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, re.IGNORECASE | re.DOTALL):
        attrs, body = m.group(1), m.group(2)
        action = re.search(r'action\s*=\s*["\']([^"\']*)["\']', attrs, re.IGNORECASE)
        method = re.search(r'method\s*=\s*["\']([^"\']*)["\']', attrs, re.IGNORECASE)
        fields = re.findall(
            r'<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["\']([^"\']+)["\']',
            body, re.IGNORECASE)
        forms.append({
            "action": action.group(1) if action else "",
            "method": (method.group(1) if method else "GET").upper(),
            "fields": list(dict.fromkeys(fields)),  # de-dup, keep order
        })
    return forms


def _extract_comments(html: str) -> list[str]:
    """HTML comments — CTF apps routinely leak hints, paths, or creds in them."""
    out = []
    for c in re.findall(r"<!--(.*?)-->", html, re.DOTALL):
        c = " ".join(c.split())
        if c:
            out.append(c)
    return out


_ENDPOINT_HINTS = ("/api", "/rest", "/graphql", "/admin", "/user", "/account",
                   "/login", "/logout", "/profile", "/upload", "/v1", "/v2", "/debug")


def _extract_endpoints(html: str) -> list[str]:
    """Path-like strings the page references (in scripts, links, actions) that look
    like real endpoints — the true routes, instead of ones the model invents."""
    eps: set[str] = set()
    for m in re.finditer(r'["\'](/[A-Za-z0-9_\-./?=&]{2,})["\']', html):
        p = m.group(1)
        if any(h in p.lower() for h in _ENDPOINT_HINTS) or p.endswith(
                (".php", ".json", ".do", ".jsp", ".aspx")):
            eps.add(p.split("?")[0] if len(p) > 60 else p)
    return sorted(eps)[:25]


def format_attack_surface(html: str, base_url: str = "") -> str:
    """A compact recon block: forms (with real field names), referenced endpoints,
    and HTML comments — so the agent grounds its actions in the actual app instead
    of blind-guessing routes and parameters (the observed failure mode)."""
    forms = _extract_forms(html)
    endpoints = _extract_endpoints(html)
    comments = _extract_comments(html)
    lines: list[str] = []
    if forms:
        lines.append("Forms:")
        for f in forms[:6]:
            lines.append(f"  {f['method']} {f['action'] or '(self)'} — fields: "
                         f"{', '.join(f['fields']) or '(none)'}")
    if endpoints:
        lines.append("Referenced endpoints: " + ", ".join(endpoints))
    if comments:
        lines.append("HTML comments: " + " | ".join(c[:140] for c in comments[:5]))
    return "\n".join(lines)


# ------------------------------------------------------------------ #
# Persistent session
# ------------------------------------------------------------------ #

class WebSession:
    """A web session shared across web-tool calls: one persistent cookie jar so a
    login on one request authenticates the next.

    The web tools build a fresh HttpClient per call, so without this a Set-Cookie
    from a login was thrown away and the very next request was unauthenticated —
    the root cause of the auth / IDOR / privilege-escalation failures. Share one
    WebSession between the web tools (e.g. web_fetch + http_request) and the login
    state carries across every call. httpx scopes cookies by domain, so a single
    session is safe even when the agent touches several hosts."""

    def __init__(self) -> None:
        try:
            import httpx
            self.cookies: Any = httpx.Cookies()
        except Exception:
            self.cookies = None
        # Optional sticky headers (e.g. a bearer token the agent chooses to pin).
        self.headers: dict[str, str] = {}

    def cookie_names(self) -> list[str]:
        if not self.cookies:
            return []
        return sorted({c.name for c in self.cookies.jar})

    def absorb(self, client_cookies: Any) -> None:
        """Merge a client's post-response cookies back into the persistent jar.

        httpx (0.28) COPIES a passed jar into the client rather than sharing it, so
        a response's Set-Cookie lands in the client's throwaway jar, not ours. We
        therefore round-trip: seed each HttpClient from this jar, then absorb the
        client's jar back here after the request — so login state survives across
        the fresh client built for every tool call."""
        if self.cookies is None or client_cookies is None:
            return
        try:
            for cookie in client_cookies.jar:
                self.cookies.jar.set_cookie(cookie)
        except Exception:
            pass


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

    def __init__(self, egress: Any = None, session: "Optional[WebSession]" = None,
                 **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # Egress/OPSEC (EgressProfile): when active, HTTP requests exit through the
        # configured proxy/Tor so the target sees that IP, not the operator's.
        self.egress = egress
        # Persistent cookie jar shared with the other web tools (see WebSession).
        self.session = session or WebSession()

    def _proxy(self) -> Any:
        return self.egress.httpx_proxy() if self.egress is not None else None

    async def execute(
        self,
        url: str,
        extract_links: bool = False,
        max_length: int = 4000,
        **kwargs: Any,
    ) -> ToolResult:
        if not url.startswith(("http://", "https://")):
            return ToolResult.fail(f"Invalid URL: must start with http:// or https://")

        async with HttpClient(timeout=25.0, proxy=self._proxy(),
                              cookies=self.session.cookies) as client:
            response = await client.get(url, extra_headers=self.session.headers or None)
            self.session.absorb(client.cookies)  # persist any Set-Cookie

        if not response.success and response.error:
            return ToolResult.fail(response.error)

        output = format_response(response, max_content=max_length)

        # Recon grounding: surface the real attack surface (forms + field names,
        # referenced endpoints, comments) so the agent acts on what's actually there.
        if response.is_html:
            surface = format_attack_surface(response.text, url)
            if surface:
                output += f"\n\n--- Attack surface (recon) ---\n{surface}"

        if extract_links:
            links = response.extract_links(url)[:20]
            if links:
                output += f"\n\n--- Links ({len(links)}) ---\n" + "\n".join(links)

        return ToolResult.ok(
            output,
            metadata={"url": url, "status": response.status_code, "via_tor": False},
        )


class HttpRequestTool(BaseTool):
    name = "http_request"
    description = (
        "Send an arbitrary HTTP request (GET/POST/PUT/DELETE/PATCH) to a URL and "
        "return the status, response headers, and raw body. Use this — NOT shell "
        "curl — for web-API testing: authentication, injection, and access-control "
        "attacks. The body and headers are sent as structured data, so payloads "
        "that contain quotes (e.g. a SQL injection like ' OR 1=1--) are transported "
        "verbatim with no shell-escaping problems. Provide a JSON body via "
        "json_body (sent as application/json), form fields via data, or a raw "
        "string via body."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string",
                     "description": "Target URL (must start with http:// or https://)"},
            "method": {"type": "string",
                       "description": "HTTP method (GET, POST, PUT, DELETE, PATCH)",
                       "default": "GET"},
            "json_body": {"type": "object",
                          "description": "Request body sent as JSON. Put injection "
                          "payloads in here as plain string values."},
            "data": {"type": "object",
                     "description": "Form-encoded body (application/x-www-form-urlencoded)"},
            "body": {"type": "string", "description": "Raw request body string"},
            "params": {"type": "object", "description": "URL query parameters"},
            "headers": {"type": "object",
                        "description": "Extra request headers, e.g. an Authorization "
                        "bearer token captured from a previous response"},
            "max_length": {"type": "integer",
                           "description": "Max characters of body to return (default 4000)",
                           "default": 4000},
        },
        "required": ["url"],
    }
    permissions = {Permission.NETWORK}
    timeout = 30
    tags = ["browser", "web", "http", "api"]

    # Response headers worth surfacing to the model for web attacks.
    _KEY_HEADERS = ("content-type", "set-cookie", "location", "www-authenticate",
                    "server", "x-powered-by")

    def __init__(self, egress: Any = None, session: "Optional[WebSession]" = None,
                 **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # Egress/OPSEC: route the request through the configured proxy/Tor so the
        # target's web logs show that IP, not the operator's.
        self.egress = egress
        # Persistent cookie jar shared with the other web tools (see WebSession) —
        # a login here authenticates every later http_request/web_fetch call.
        self.session = session or WebSession()

    def _proxy(self) -> Any:
        return self.egress.httpx_proxy() if self.egress is not None else None

    async def execute(
        self,
        url: str,
        method: str = "GET",
        json_body: Optional[dict] = None,
        data: Optional[dict] = None,
        body: Optional[str] = None,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        max_length: int = 4000,
        **kwargs: Any,
    ) -> ToolResult:
        if not url.startswith(("http://", "https://")):
            return ToolResult.fail("Invalid URL: must start with http:// or https://")

        # Merge any sticky session headers under the caller's explicit ones.
        req_headers = {**self.session.headers, **(headers or {})} or None

        async with HttpClient(timeout=25.0, proxy=self._proxy(),
                              cookies=self.session.cookies) as client:
            response = await client.request(
                method, url, params=params, data=data, json=json_body,
                content=body, extra_headers=req_headers,
            )
            self.session.absorb(client.cookies)  # persist any Set-Cookie

        if response.error and response.status_code == 0:
            return ToolResult.fail(response.error)

        lines = [f"{method.upper()} {response.url}",
                 f"Status: {response.status_code} ({response.elapsed_ms:.0f}ms)"]
        for h in self._KEY_HEADERS:
            if h in {k.lower() for k in response.headers}:
                val = next(v for k, v in response.headers.items() if k.lower() == h)
                lines.append(f"{h}: {val}")
        # Surface the live session so the model knows its login persists and it does
        # NOT need to re-authenticate or manually replay cookies on the next call.
        held = self.session.cookie_names()
        if held:
            lines.append(f"Session cookies (auto-sent on your next request): {', '.join(held)}")
        text = response.text or ""
        truncated = text[:max_length]
        lines.append(f"\n--- Body ({len(text)} bytes) ---\n{truncated}")
        if len(text) > max_length:
            lines.append("[... body truncated]")

        # Recon grounding: if the response is HTML, add the parsed attack surface.
        ctype = next((v for k, v in response.headers.items()
                      if k.lower() == "content-type"), "")
        low = text.lower()
        if "html" in ctype.lower() or "<form" in low or "<html" in low:
            surface = format_attack_surface(text, url)
            if surface:
                lines.append(f"\n--- Attack surface (recon) ---\n{surface}")

        return ToolResult.ok(
            "\n".join(lines),
            metadata={"url": str(response.url), "status": response.status_code,
                      "method": method.upper()},
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


class EgressCheckTool(BaseTool):
    name = "egress_check"
    description = (
        "OPSEC leak test: report the PUBLIC IP a target would see for your traffic, "
        "by fetching an IP-echo service through the configured egress (proxy/Tor). "
        "Run this before attacking to confirm your real IP is hidden. If egress is "
        "'direct', the target sees your REAL IP — this warns you of that."
    )
    parameters = {"type": "object", "properties": {}}
    permissions = {Permission.NETWORK}
    tags = ["opsec", "egress", "recon"]

    def __init__(self, egress: Any = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.egress = egress

    async def execute(self, **kwargs: Any) -> ToolResult:
        proxy = self.egress.httpx_proxy() if self.egress is not None else None
        desc = self.egress.describe() if self.egress is not None else \
            "direct — no egress configured"
        active = bool(self.egress and self.egress.active)
        try:
            async with HttpClient(timeout=15.0, proxy=proxy) as client:
                ip = await client.get_ip()
        except Exception as exc:
            return ToolResult.fail(
                f"Egress check failed ({exc}). Egress: {desc}. If a proxy/Tor is "
                f"set, make sure it is running and reachable.")
        if ip == "unknown":
            return ToolResult.fail(
                f"Could not determine the apparent IP through the egress ({desc}). "
                f"The proxy may be down or blocking the IP-echo services.")
        lines = [f"Egress        : {desc}",
                 f"Apparent IP   : {ip}  (this is what a target sees)"]
        if not active:
            lines.append("⚠ WARNING: egress is DIRECT — this is your REAL IP. Set an "
                         "egress proxy/Tor or attack from a pivot to hide it.")
        return ToolResult.ok("\n".join(lines),
                             metadata={"apparent_ip": ip, "active": active})
