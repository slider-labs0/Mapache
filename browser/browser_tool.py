"""
browser_tool.py - a real headless-browser tool for the agent (capability #1)

Mapache's web tools (`web_fetch` / `http_request`) speak raw HTTP: fast, but they
can't run JavaScript, so a single-page app (React/Vue/Angular), a client-side route,
or DOM-based XSS is invisible to them - a hard ceiling on the modern-web-app class.
`browser/chromium_controller.py` already drives a real headless Chromium via
Playwright; this exposes it to the agent as the `browser` tool.

The controller is kept ALIVE across calls (one persistent context), so a login in
one call carries its cookies into the next - the auth/IDOR continuity a fresh page
per call would lose. Playwright is an optional dependency: absent, the tool returns
install instructions instead of crashing, so it is always safe to register.
"""

from __future__ import annotations

from typing import Any, Optional

from plugins.sdk.base_tool import BaseTool, Permission, ToolResult
from browser.chromium_controller import ChromiumController
from browser.scraping_tools import format_attack_surface


def _annotate_browser_error(msg: str, url: str) -> str:
    """Translate opaque Chromium proxy error codes into an actionable diagnosis so a
    Tor/.onion failure is not misread as a browser misconfiguration (the agent burned a
    whole turn chasing a phantom config bug on a .onion that was simply offline)."""
    m = msg or ""
    is_onion = ".onion" in (url or "")
    if "ERR_SOCKS_CONNECTION_FAILED" in m:
        if is_onion:
            return (m + "\nDiagnosis: the SOCKS proxy is reachable but Tor could NOT "
                    "connect to this hidden service - the .onion is most likely OFFLINE "
                    "or unreachable right now (common for sites under DDoS), NOT a proxy "
                    "misconfiguration. Confirm Tor works by loading a known-good onion; "
                    "if that succeeds, this address is down - try a different mirror.")
        return (m + "\nDiagnosis: the SOCKS proxy is reachable but could not connect to "
                "the target host through it (the host is down/unreachable via the proxy).")
    if "ERR_PROXY_CONNECTION_FAILED" in m:
        return (m + "\nDiagnosis: could not reach the proxy itself - check Tor is running "
                "and the port matches (Tor daemon: 9050, Tor Browser bundle: 9150).")
    if is_onion and "ERR_NAME_NOT_RESOLVED" in m:
        return (m + "\nDiagnosis: the .onion was resolved locally instead of via Tor - "
                "the browser must route DNS through the SOCKS proxy (socks5://).")
    return m


class BrowserTool(BaseTool):
    name = "browser"
    description = (
        "Render a URL in a REAL headless Chromium browser - JavaScript executes, the "
        "DOM builds, and client-side routes work. Use this when `web_fetch` returns an "
        "empty page or a JS shell, for single-page apps (React/Vue/Angular), DOM-based "
        "XSS, or any flow that needs scripts to run. The browser SESSION PERSISTS across "
        "calls, so a login carries over (cookies are kept). "
        "action='fetch' loads a page (optionally wait_for a CSS selector, or click one "
        "after load); action='fill_form' fills fields {css_selector: value} and submits."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string",
                    "description": "URL to open (http:// or https://)."},
            "action": {"type": "string", "enum": ["fetch", "fill_form"],
                       "description": "fetch a page (default) or fill_form and submit.",
                       "default": "fetch"},
            "wait_for": {"type": "string",
                         "description": "fetch: CSS selector to wait for before reading."},
            "click": {"type": "string",
                      "description": "fetch: CSS selector to click after the page loads."},
            "fields": {"type": "object",
                       "description": "fill_form: {css_selector: value} pairs to fill."},
            "submit_selector": {"type": "string",
                                "description": "fill_form: submit button selector "
                                               "(default button[type=submit])."},
            "screenshot": {"type": "boolean",
                           "description": "fetch: also note that a screenshot was taken.",
                           "default": False},
        },
        "required": ["url"],
    }
    permissions = {Permission.NETWORK}
    timeout = 200  # generous: a DDoS access queue (Dread/EndGame) can take a while
    tags = ["browser", "web", "headless", "js", "spa"]

    def __init__(self, egress: Any = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # Egress/OPSEC: when active, the browser exits through the configured proxy/Tor.
        self.egress = egress
        self._controller: Optional[ChromiumController] = None

    def _proxy(self) -> Optional[str]:
        # httpx_proxy() returns a "socks5://…" / "http://…" string Playwright accepts.
        return self.egress.httpx_proxy() if self.egress is not None else None

    async def _get_controller(self) -> ChromiumController:
        if self._controller is None:
            self._controller = ChromiumController(proxy=self._proxy(), headless=True)
            await self._controller.start()
        return self._controller

    async def aclose(self) -> None:
        """Tear down the persistent browser (call at engagement end)."""
        if self._controller is not None:
            try:
                await self._controller.stop()
            finally:
                self._controller = None

    async def execute(
        self,
        url: str,
        action: str = "fetch",
        wait_for: Optional[str] = None,
        click: Optional[str] = None,
        fields: Optional[dict] = None,
        submit_selector: str = 'button[type="submit"]',
        screenshot: bool = False,
        **kwargs: Any,
    ) -> ToolResult:
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            return ToolResult.fail("Invalid URL: must start with http:// or https://")
        if not ChromiumController.is_available():
            return ToolResult.fail(
                "The headless browser needs Playwright, which isn't installed. "
                "Install it, then retry:\n"
                "  pip install playwright\n"
                "  playwright install chromium\n"
                "Until then, use web_fetch / http_request (no JavaScript rendering).")

        try:
            controller = await self._get_controller()
        except Exception as exc:
            return ToolResult.fail(f"Could not start the browser: {exc}")

        try:
            if action == "fill_form":
                if not isinstance(fields, dict) or not fields:
                    return ToolResult.fail(
                        "action='fill_form' needs a `fields` object of "
                        "{css_selector: value} pairs.")
                result = await controller.fill_form(
                    url, {str(k): str(v) for k, v in fields.items()},
                    submit_selector=submit_selector or 'button[type="submit"]')
            else:
                result = await controller.fetch(
                    url, screenshot=bool(screenshot),
                    wait_for=wait_for or None, click_selector=click or None)
        except Exception as exc:
            return ToolResult.fail(_annotate_browser_error(f"Browser error: {exc}", url))

        if not result.success:
            return ToolResult.fail(
                _annotate_browser_error(result.error or "Unknown browser error", url))

        lines = [f"[{result.url}] {result.title}".strip(), "", result.text or "(no text)"]
        # Recon grounding on the RENDERED DOM - after JS has built the page, so forms /
        # endpoints that only exist client-side are surfaced too.
        if result.html:
            surface = format_attack_surface(result.html, result.url)
            if surface:
                lines.append(f"\n--- Attack surface (rendered DOM) ---\n{surface}")
        if result.links:
            lines.append("\n--- Links ---\n" + "\n".join(result.links[:20]))
        if result.screenshot_b64:
            lines.append(f"\n[screenshot captured - {len(result.screenshot_b64)} b64 chars]")

        return ToolResult.ok("\n".join(lines),
                             metadata={"url": result.url, "rendered": True})
