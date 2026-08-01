"""
chromium_controller.py — Mapache browser automation

Headless Chromium control via Playwright.
Used for JavaScript-heavy pages that httpx can't handle,
form submission, screenshots, and interactive browsing.

Install:
    pip install playwright
    playwright install chromium

For Tor routing:
    Pass proxy="socks5://127.0.0.1:9050" to use Tor
"""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from typing import Any, Optional

from core.logger import get_logger

logger = get_logger(__name__)

try:
    from playwright.async_api import async_playwright, Browser, Page, Playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


@dataclass
class BrowserResult:
    url: str
    title: str
    text: str
    html: str
    screenshot_b64: Optional[str] = None
    links: list[str] = None
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None

    def __post_init__(self):
        if self.links is None:
            self.links = []


class ChromiumController:
    """
    Headless Chromium browser controller.

    Handles JavaScript-rendered pages, form submissions,
    screenshots, and complex navigation.

    Usage:
        async with ChromiumController() as browser:
            result = await browser.fetch("https://example.com")
            print(result.title)
            print(result.text[:500])
    """

    DEFAULT_TIMEOUT = 30000  # ms
    MAX_TEXT_LENGTH = 8000

    def __init__(
        self,
        proxy: Optional[str] = None,
        headless: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
        user_agent: Optional[str] = None,
    ) -> None:
        self.proxy = proxy
        self.headless = headless
        self.timeout = timeout
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        self._playwright: Optional[Any] = None
        self._browser: Optional[Any] = None
        # One persistent context for the controller's lifetime, so cookies (a login,
        # a session token) carry across pages/calls — the auth/IDOR continuity that a
        # fresh page-per-call would lose.
        self._context: Optional[Any] = None

    async def start(self) -> None:
        if not HAS_PLAYWRIGHT:
            raise ImportError(
                "Playwright not installed.\n"
                "Install: pip install playwright && playwright install chromium"
            )
        self._playwright = await async_playwright().start()

        launch_kwargs: dict[str, Any] = {
            "headless": self.headless,
            "args": [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        }

        if self.proxy:
            launch_kwargs["proxy"] = {"server": self.proxy}

        self._browser = await self._playwright.chromium.launch(**launch_kwargs)
        # ignore_https_errors: lab targets often serve self-signed certs.
        self._context = await self._browser.new_context(
            user_agent=self.user_agent, ignore_https_errors=True)
        self._context.set_default_timeout(self.timeout)
        logger.info("Chromium started (headless=%s proxy=%s)", self.headless, self.proxy)

    async def _new_page(self) -> Any:
        """A page in the shared context (cookies persist), starting the browser lazily."""
        if self._context is None:
            await self.start()
        return await self._context.new_page()

    async def stop(self) -> None:
        if self._context:
            await self._context.close()
            self._context = None
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None
        logger.info("Chromium stopped")

    async def cookies(self) -> list:
        """The context's current cookies (for inspection / cross-tool sharing)."""
        return await self._context.cookies() if self._context else []

    async def __aenter__(self) -> "ChromiumController":
        await self.start()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.stop()

    # ------------------------------------------------------------------ #
    # Page operations
    # ------------------------------------------------------------------ #

    async def fetch(
        self,
        url: str,
        screenshot: bool = False,
        wait_for: Optional[str] = None,
        click_selector: Optional[str] = None,
    ) -> BrowserResult:
        """
        Navigate to a URL and extract content.

        Args:
            url:             Target URL
            screenshot:      Capture a screenshot (returned as base64)
            wait_for:        CSS selector to wait for before extracting content
            click_selector:  CSS selector to click after page load
        """
        page = await self._new_page()

        try:
            await page.set_extra_http_headers({
                "Accept-Language": "en-US,en;q=0.9",
            })

            response = await page.goto(url, timeout=self.timeout, wait_until="domcontentloaded")

            if wait_for:
                try:
                    await page.wait_for_selector(wait_for, timeout=5000)
                except Exception:
                    pass  # Don't fail if selector not found

            if click_selector:
                try:
                    await page.click(click_selector, timeout=3000)
                    await page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass

            title = await page.title()
            html = await page.content()
            text = await page.evaluate("""
                () => {
                    const scripts = document.querySelectorAll('script, style, nav, footer');
                    scripts.forEach(el => el.remove());
                    return document.body ? document.body.innerText : '';
                }
            """)

            # Truncate
            text = text[:self.MAX_TEXT_LENGTH] if text else ""

            # Extract links
            links = await page.evaluate("""
                () => Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter(h => h.startsWith('http'))
                    .slice(0, 30)
            """)

            screenshot_b64 = None
            if screenshot:
                screenshot_bytes = await page.screenshot(type="png", full_page=False)
                screenshot_b64 = base64.b64encode(screenshot_bytes).decode()

            status = response.status if response else 0
            logger.info("Browser fetched %s (status=%s)", url, status)

            return BrowserResult(
                url=page.url,
                title=title,
                text=text,
                html=html[:20000],
                screenshot_b64=screenshot_b64,
                links=links,
            )

        except Exception as exc:
            logger.error("Browser fetch error (%s): %s", url, exc)
            return BrowserResult(
                url=url, title="", text="", html="",
                error=str(exc),
            )
        finally:
            await page.close()

    async def fill_form(
        self,
        url: str,
        fields: dict[str, str],
        submit_selector: str = 'button[type="submit"]',
    ) -> BrowserResult:
        """
        Navigate to a URL, fill in form fields, and submit.

        Args:
            url:              Page with the form
            fields:           dict of {css_selector: value}
            submit_selector:  CSS selector of the submit button
        """
        page = await self._new_page()
        try:
            await page.goto(url, timeout=self.timeout, wait_until="domcontentloaded")

            for selector, value in fields.items():
                try:
                    await page.fill(selector, value)
                except Exception as exc:
                    logger.warning("Could not fill field %s: %s", selector, exc)

            try:
                await page.click(submit_selector, timeout=3000)
                await page.wait_for_load_state("networkidle", timeout=10000)
            except Exception as exc:
                logger.warning("Submit failed: %s", exc)

            title = await page.title()
            text = await page.evaluate("() => document.body ? document.body.innerText : ''")

            return BrowserResult(
                url=page.url,
                title=title,
                text=text[:self.MAX_TEXT_LENGTH],
                html="",
            )
        except Exception as exc:
            return BrowserResult(
                url=url, title="", text="", html="",
                error=str(exc),
            )
        finally:
            await page.close()

    @staticmethod
    def is_available() -> bool:
        return HAS_PLAYWRIGHT

    @staticmethod
    def install_instructions() -> str:
        return (
            "Playwright not installed.\n"
            "Install with:\n"
            "  pip install playwright\n"
            "  playwright install chromium"
        )
