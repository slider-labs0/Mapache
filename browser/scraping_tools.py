"""
scraping_tools.py - Mapache web scraping utilities

Structured content extraction from web pages.
Works with both surface web and .onion pages via HttpClient.

Tools exposed to the agent:
    web_fetch      - fetch a URL and return readable content
    web_search     - search the web (DuckDuckGo, no API key needed)
    extract_links  - extract all links from a page
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
    """Forms with their REAL action/method and input field names - so the agent
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
    """HTML comments - CTF apps routinely leak hints, paths, or creds in them."""
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
    like real endpoints - the true routes, instead of ones the model invents."""
    eps: set[str] = set()
    for m in re.finditer(r'["\'](/[A-Za-z0-9_\-./?=&]{2,})["\']', html):
        p = m.group(1)
        if any(h in p.lower() for h in _ENDPOINT_HINTS) or p.endswith(
                (".php", ".json", ".do", ".jsp", ".aspx")):
            eps.add(p.split("?")[0] if len(p) > 60 else p)
    return sorted(eps)[:25]


def format_attack_surface(html: str, base_url: str = "") -> str:
    """A compact recon block: forms (with real field names), referenced endpoints,
    and HTML comments - so the agent grounds its actions in the actual app instead
    of blind-guessing routes and parameters (the observed failure mode)."""
    forms = _extract_forms(html)
    endpoints = _extract_endpoints(html)
    comments = _extract_comments(html)
    lines: list[str] = []
    if forms:
        lines.append("Forms:")
        for f in forms[:6]:
            lines.append(f"  {f['method']} {f['action'] or '(self)'} - fields: "
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
    from a login was thrown away and the very next request was unauthenticated -
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
        client's jar back here after the request - so login state survives across
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
        "return the status, response headers, and raw body. Use this - NOT shell "
        "curl - for web-API testing: authentication, injection, and access-control "
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
                 history: Any = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # Egress/OPSEC: route the request through the configured proxy/Tor so the
        # target's web logs show that IP, not the operator's.
        self.egress = egress
        # Persistent cookie jar shared with the other web tools (see WebSession) -
        # a login here authenticates every later http_request/web_fetch call.
        self.session = session or WebSession()
        # Shared Burp-lite history: every request is recorded so http_repeater can
        # replay/tamper/diff it later (id `rN`). Shared with http_repeater + across
        # sub-agents via the shared tool instance.
        self.history = history

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

        ex_id = ""
        if self.history is not None:
            ex = self.history.record(
                method=method, url=str(response.url), status=response.status_code,
                req_headers=req_headers or {}, req_params=params, req_json=json_body,
                req_data=data, req_body=body, resp_headers=dict(response.headers),
                resp_body=response.text or "", elapsed_ms=response.elapsed_ms)
            ex_id = ex.id

        lines = [f"{method.upper()} {response.url}",
                 f"Status: {response.status_code} ({response.elapsed_ms:.0f}ms)"]
        if ex_id:
            lines.append(f"[recorded as {ex_id} - replay/tamper/diff it with http_repeater]")
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


class HttpRepeaterTool(BaseTool):
    name = "http_repeater"
    description = (
        "Burp Repeater for the agent: replay, tamper, and diff HTTP requests you "
        "already sent (each http_request is recorded with an id like r3).\n"
        "USE THIS FOR IDOR / BROKEN ACCESS CONTROL: replay an authenticated request "
        "changing ONE id/param (e.g. account?id=123 -> 124) and it auto-DIFFS the two "
        "responses. A DIFFERENT body = you read another user's object (a CONFIRMED "
        "IDOR - the flag is often there). An IDENTICAL body = the param is ignored "
        "(dead vector; change approach). Session cookies are reused automatically.\n"
        "actions: 'history' (list recorded requests), 'show' (full request+response "
        "of one id), 'replay' (re-send id N with optional tamper overrides + auto-diff "
        "vs the original), 'diff' (compare two ids)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "action": {"type": "string",
                       "description": "history | show | replay | diff",
                       "default": "history"},
            "id": {"type": "string",
                   "description": "Exchange id to show/replay (e.g. 'r3')"},
            "id_b": {"type": "string",
                     "description": "Second exchange id for action='diff'"},
            # Tamper overrides for action='replay' - any omitted field reuses the
            # original request's value. This is how you flip the IDOR id.
            "url": {"type": "string", "description": "replay: override the URL"},
            "method": {"type": "string", "description": "replay: override the method"},
            "params": {"type": "object", "description": "replay: override query params (the usual IDOR knob)"},
            "json_body": {"type": "object", "description": "replay: override the JSON body"},
            "data": {"type": "object", "description": "replay: override the form body"},
            "headers": {"type": "object", "description": "replay: merge/override headers"},
            "search": {"type": "string",
                       "description": "history: only list exchanges matching this substring"},
            "max_length": {"type": "integer", "default": 4000},
        },
        "required": ["action"],
    }
    permissions = {Permission.NETWORK}
    timeout = 30
    tags = ["browser", "web", "http", "repeater", "idor"]

    def __init__(self, egress: Any = None, session: "Optional[WebSession]" = None,
                 history: Any = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.egress = egress
        self.session = session or WebSession()
        if history is None:
            from browser.http_history import HTTPHistory
            history = HTTPHistory()
        self.history = history

    def _proxy(self) -> Any:
        return self.egress.httpx_proxy() if self.egress is not None else None

    async def execute(self, action: str = "history", id: Optional[str] = None,
                      id_b: Optional[str] = None, url: Optional[str] = None,
                      method: Optional[str] = None, params: Optional[dict] = None,
                      json_body: Optional[dict] = None, data: Optional[dict] = None,
                      headers: Optional[dict] = None, search: Optional[str] = None,
                      max_length: int = 4000, **kwargs: Any) -> ToolResult:
        action = (action or "history").lower().strip()

        if action == "history":
            items = self.history.search(search) if search else self.history.recent(25)
            if not items:
                return ToolResult.ok("(no requests recorded yet - send some with http_request)")
            return ToolResult.ok("Recorded HTTP exchanges:\n"
                                 + "\n".join("  " + e.summary() for e in items))

        if action == "show":
            ex = self.history.get(id or "")
            if ex is None:
                return ToolResult.fail(f"No exchange with id {id!r}. Use action='history'.")
            body = (ex.resp_body or "")[:max_length]
            req = []
            if ex.req_params:
                req.append(f"  params: {ex.req_params}")
            if ex.req_json is not None:
                req.append(f"  json: {ex.req_json}")
            if ex.req_data:
                req.append(f"  data: {ex.req_data}")
            if ex.req_body:
                req.append(f"  body: {ex.req_body[:500]}")
            return ToolResult.ok(
                f"{ex.id}: {ex.method} {ex.url}\n" + ("\n".join(req) + "\n" if req else "")
                + f"-> {ex.status} ({ex.elapsed_ms:.0f}ms)\n--- Body ({len(ex.resp_body)}B) ---\n{body}")

        if action == "diff":
            a = self.history.get(id or "")
            b = self.history.get(id_b or "")
            if a is None or b is None:
                return ToolResult.fail("diff needs two valid ids: id and id_b.")
            return ToolResult.ok(self._render_diff(a, b))

        if action == "replay":
            base = self.history.get(id or "")
            if base is None:
                return ToolResult.fail(f"No exchange with id {id!r} to replay. Use action='history'.")
            r_method = (method or base.method).upper()
            r_url = url or base.url
            r_params = params if params is not None else base.req_params
            r_json = json_body if json_body is not None else base.req_json
            r_data = data if data is not None else base.req_data
            r_headers = {**(base.req_headers or {}), **(self.session.headers or {}),
                         **(headers or {})} or None
            async with HttpClient(timeout=25.0, proxy=self._proxy(),
                                  cookies=self.session.cookies) as client:
                response = await client.request(
                    r_method, r_url, params=r_params, data=r_data, json=r_json,
                    content=base.req_body, extra_headers=r_headers)
                self.session.absorb(client.cookies)
            if response.error and response.status_code == 0:
                return ToolResult.fail(response.error)
            new = self.history.record(
                method=r_method, url=str(response.url), status=response.status_code,
                req_headers=r_headers or {}, req_params=r_params, req_json=r_json,
                req_data=r_data, req_body=base.req_body,
                resp_headers=dict(response.headers), resp_body=response.text or "",
                elapsed_ms=response.elapsed_ms, tag=f"replay of {base.id}")
            return ToolResult.ok(
                f"Replayed {base.id} -> {new.id}: {r_method} {response.url} "
                f"-> {response.status_code}\n\n" + self._render_diff(base, new),
                metadata={"replay_of": base.id, "new_id": new.id,
                          "status": response.status_code})

        return ToolResult.fail(f"Unknown action {action!r}. Use history|show|replay|diff.")

    def _render_diff(self, a: Any, b: Any) -> str:
        from browser.http_history import diff_bodies
        changed, rendered = diff_bodies(a.resp_body, b.resp_body)
        head = (f"diff {a.id} (status {a.status}, {len(a.resp_body)}B) "
                f"vs {b.id} (status {b.status}, {len(b.resp_body)}B)")
        if not changed and a.status == b.status:
            return (head + "\nIDENTICAL response - the changed input had NO effect "
                    "(dead vector). Try a different parameter/technique.")
        verdict = ("DIFFERENT response - the change altered the output. If you swapped "
                   "an id/owner, you likely accessed another principal's data (possible "
                   "IDOR / broken access control) - inspect it for the flag.")
        return f"{head}\n{verdict}\n--- body diff ---\n{rendered}"


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


_TRANSIENT_TOR_ERRORS = (
    "ttl exp", "ttl expired", "could not connect", "general socks", "socks server failure",
    "host unreachable", "network unreachable", "connection refused", "timed out",
    "timeout", "temporarily", "no route",
)


def _is_transient_tor_error(err: str) -> bool:
    """A Tor SOCKS/circuit error that typically clears on retry (fresh circuit or once
    bootstrap completes) - as opposed to a permanent failure. TTL-expired and general
    SOCKS failures are the classic transient ones right after Tor starts."""
    e = (err or "").lower()
    return any(m in e for m in _TRANSIENT_TOR_ERRORS)


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
        # Ensure Tor is up - start it ourselves if needed instead of deferring to the
        # user. TorController locates a system tor or a Tor Browser bundle and launches it.
        from browser.tor_controller import TorController
        controller = TorController(socks_port=tor_port, control_port=tor_port + 1)
        if not await controller.is_running():
            ok, msg = await controller.start()
            if not ok:
                return ToolResult.fail(
                    f"Tor is not running and could not be auto-started on port {tor_port}: "
                    f"{msg}")

        # socks5h (not socks5): let the Tor proxy resolve the hostname remotely.
        # .onion addresses have no DNS and cannot be resolved client-side, so plain
        # socks5:// fails on hidden services ("illegal request line" / lookup errors).
        proxy = f"socks5h://127.0.0.1:{tor_port}"
        is_onion = ".onion" in url
        last_err = ""
        ip: Optional[str] = None

        try:
            async with HttpClient(
                proxy=proxy,
                timeout=45.0,
                verify_ssl=False,  # Many .onion sites have self-signed certs
            ) as client:
                # Tor circuits can be transiently unready (right after start) or fail with
                # "TTL expired" / "general SOCKS failure". Retry with a fresh circuit before
                # giving up, so one blip is not reported as an unreachable target.
                for attempt in range(3):
                    if ip is None:
                        try:
                            is_tor, ip_probe = await client.check_tor()
                            if is_tor:
                                ip = ip_probe
                        except Exception:
                            pass
                    response = await client.get(url)
                    if response.success:
                        output = format_response(response, max_content=max_length)
                        output = (f"[Routed via Tor - External IP: {ip or 'unknown'}]\n\n"
                                  + output)
                        return ToolResult.ok(output, metadata={
                            "url": url, "via_tor": True, "exit_ip": ip,
                            "attempts": attempt + 1})
                    last_err = response.error or "unknown error"
                    if attempt == 2 or not _is_transient_tor_error(last_err):
                        break
                    await asyncio.sleep(2.5)
                    try:
                        await controller.new_circuit()  # fresh exit before retrying
                    except Exception:
                        pass
        except Exception as exc:
            if "SOCKS" in str(exc) or "Connection" in str(exc):
                return ToolResult.fail(
                    f"Cannot connect to Tor on port {tor_port}. Is Tor running? "
                    f"Try tor_port=9150 (Tor Browser).")
            return ToolResult.fail(str(exc))

        hint = ("" if not is_onion else
                " - for a .onion this usually means the hidden service is offline/"
                "unreachable, not a Tor problem")
        return ToolResult.fail(f"Fetch failed after 3 attempts: {last_err}{hint}")


class TorControlTool(BaseTool):
    name = "tor_control"
    description = (
        "Manage the local Tor process yourself. action='start' launches Tor if it is "
        "not already running - it auto-locates a system `tor` OR a Tor Browser bundle "
        "(Windows/macOS/Linux), so you do NOT need to ask the operator to start it. "
        "action='status' reports whether Tor is up and the current exit IP; "
        "action='new_circuit' requests a fresh exit IP. Call start before tor_fetch or "
        "the Tor-routed browser when Tor is not yet running."
    )
    parameters = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["start", "status", "new_circuit"],
                "description": "start (launch Tor) | status | new_circuit",
                "default": "start",
            },
            "tor_port": {
                "type": "integer",
                "description": "SOCKS port to use/start (default 9050; Tor Browser uses 9150)",
                "default": 9050,
            },
        },
        "required": [],
    }
    permissions = {Permission.NETWORK, Permission.TOR, Permission.SHELL}
    timeout = 90
    tags = ["tor", "onion", "dark-web", "opsec"]

    async def execute(self, action: str = "start", tor_port: int = 9050,
                      **kwargs: Any) -> ToolResult:
        from browser.tor_controller import TorController
        controller = TorController(socks_port=tor_port, control_port=tor_port + 1)

        if action == "status":
            status = await controller.get_status()
            return ToolResult.ok(status.to_string())

        if action == "new_circuit":
            ok, msg = await controller.new_circuit()
            return ToolResult.ok(msg) if ok else ToolResult.fail(msg)

        # default: start
        ok, msg = await controller.start()
        if not ok:
            return ToolResult.fail(msg)
        status = await controller.get_status()
        return ToolResult.ok(msg + "\n" + status.to_string(),
                             metadata={"socks_port": tor_port})


# dark.fail is the canonical VERIFIED-links directory for major dark-web services
# (markets, forums like Dread, etc.). Unlike Ahmia's keyword search - which is anti-bot
# gated and serves an empty shell to non-Tor-Browser clients - dark.fail is plain
# server-rendered HTML that lists each service's official onion(s) + online/offline
# status, so it can be read reliably over Tor or clearnet.
DARKFAIL_CLEARNET = "https://dark.fail/"
DARKFAIL_ONION = ("http://darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id"
                  ".onion/")
_ONION_RE = re.compile(r"\b[a-z2-7]{56}\.onion\b|\b[a-z2-7]{16}\.onion\b")


def _parse_darkfail(html: str) -> list[tuple[str, str, bool]]:
    """Parse dark.fail into (service_name, onion, online) rows. Each service is an
    <h4><a ...>Name</a></h4> followed by <li class="... online|offline ...">
    <code>http://<onion></code> mirror entries."""
    rows: list[tuple[str, str, bool]] = []
    for block in re.split(r"<h4>", html)[1:]:
        nm = re.search(r"<a [^>]*>([^<]+)</a>", block)
        name = (nm.group(1).strip() if nm else "?")
        for li in re.finditer(
                r'<li class="([^"]*)"[^>]*>\s*<code>\s*https?://([a-z2-7]{56}\.onion)',
                block):
            rows.append((name, li.group(2), "offline" not in li.group(1).lower()))
    return rows


class OnionSearchTool(BaseTool):
    name = "onion_search"
    description = (
        "Look up the VERIFIED .onion address of a known dark-web service (a market, or a "
        "forum like Dread, etc.) from the dark.fail directory - the canonical verified-"
        "links site. Give a service name/keyword (e.g. 'dread') and this returns the "
        "official onion(s) for matching services WITH their online/offline status, so you "
        "don't guess addresses or scrape anti-bot search engines. With no query it lists "
        "every service dark.fail tracks. Then use tor_fetch/browser to open a live one. "
        "NOTE: many services (Dread included) are frequently offline/DDoSed - if the "
        "status says offline, the address is correct but the site is down; do not loop."
    )
    parameters = {
        "type": "object",
        "properties": {
            "query": {"type": "string",
                      "description": "Service name/keyword, e.g. 'dread'. Omit to list all.",
                      "default": ""},
            "tor_port": {"type": "integer",
                         "description": "Tor SOCKS port (default 9050; Tor Browser uses 9150)",
                         "default": 9050},
        },
        "required": [],
    }
    permissions = {Permission.NETWORK, Permission.TOR}
    timeout = 90
    tags = ["tor", "onion", "dark-web", "osint", "search"]

    async def execute(self, query: str = "", tor_port: int = 9050,
                      **kwargs: Any) -> ToolResult:
        # Try clearnet dark.fail first (fast), then its onion over Tor as a fallback.
        html, err = await self._fetch_with_retry(DARKFAIL_CLEARNET, proxy=None)
        source = DARKFAIL_CLEARNET
        if html is None:
            from browser.tor_controller import TorController
            controller = TorController(socks_port=tor_port, control_port=tor_port + 1)
            if not await controller.is_running():
                await controller.start()
            html, err = await self._fetch_with_retry(
                DARKFAIL_ONION, proxy=f"socks5h://127.0.0.1:{tor_port}")
            source = DARKFAIL_ONION
        if html is None:
            return ToolResult.fail(f"Could not reach dark.fail (clearnet or onion): {err}")

        rows = _parse_darkfail(html)
        if not rows:
            return ToolResult.fail(
                "Reached dark.fail but parsed no services (layout may have changed).")

        q = query.strip().lower()
        if q:
            matched = [r for r in rows if q in r[0].lower()]
            if not matched:
                names = sorted({name for name, _, _ in rows})
                return ToolResult.ok(
                    f"No service matching '{query}' on dark.fail. Tracked services: "
                    + ", ".join(names))
            rows = matched

        # Dedup (name, onion), keep online first for readability.
        seen: set = set()
        online, offline = [], []
        for name, onion, is_on in rows:
            key = (name, onion)
            if key in seen:
                continue
            seen.add(key)
            (online if is_on else offline).append(f"  [{name}] http://{onion}")
        lines = [f"onion_search('{query}') via dark.fail (verified links):" if q
                 else "dark.fail verified links:", ""]
        if online:
            lines += ["ONLINE:"] + online
        if offline:
            lines += ["", "OFFLINE (address is correct but the site is down right now):"] + offline
        lines.append("\nVerify over Tor before trusting; addresses can still be cloned.")
        return ToolResult.ok("\n".join(lines),
                             metadata={"query": query, "source": source,
                                       "online": len(online), "offline": len(offline)})

    async def _fetch_with_retry(self, url: str,
                                proxy: Optional[str]) -> tuple[Optional[str], str]:
        try:
            async with HttpClient(proxy=proxy, timeout=45.0, verify_ssl=False) as client:
                for attempt in range(3):
                    resp = await client.get(url)
                    if resp.success:
                        return resp.text, ""
                    err = resp.error or "unknown error"
                    if attempt == 2 or not _is_transient_tor_error(err):
                        return None, err
                    await asyncio.sleep(2.5)
        except Exception as exc:
            return None, str(exc)
        return None, "exhausted retries"


class EgressCheckTool(BaseTool):
    name = "egress_check"
    description = (
        "OPSEC leak test: report the PUBLIC IP a target would see for your traffic, "
        "by fetching an IP-echo service through the configured egress (proxy/Tor). "
        "Run this before attacking to confirm your real IP is hidden. If egress is "
        "'direct', the target sees your REAL IP - this warns you of that."
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
            "direct - no egress configured"
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
            lines.append("[!] WARNING: egress is DIRECT - this is your REAL IP. Set an "
                         "egress proxy/Tor or attack from a pivot to hide it.")
        return ToolResult.ok("\n".join(lines),
                             metadata={"apparent_ip": ip, "active": active})
