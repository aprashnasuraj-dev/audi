from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from ..models import Identity
from ..scope import ScopeGuard


@dataclass
class DiscoveryResult:
    identity: str
    pages: list[str] = field(default_factory=list)
    network_urls: list[str] = field(default_factory=list)
    requests: list[dict[str, str]] = field(default_factory=list)

    @property
    def urls(self) -> list[str]:
        return sorted(set(self.pages + self.network_urls))


class BrowserCrawler:
    """JavaScript-aware crawler that records XHR/fetch traffic under one identity."""

    def __init__(self, scope: ScopeGuard, *, max_pages: int = 25, settle_ms: int = 750):
        self.scope = scope
        self.max_pages = max_pages
        self.settle_ms = settle_ms

    async def crawl(self, seed_url: str, identity: Identity) -> DiscoveryResult:
        seed = self.scope.assert_url(seed_url)
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright is required for browser discovery; install halo-audit[browser]") from exc

        result = DiscoveryResult(identity=identity.name)
        queue: list[str] = [seed]
        seen: set[str] = set()

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(extra_http_headers=identity.headers)
            if identity.cookies:
                host = urlsplit(seed).hostname or ""
                await context.add_cookies([
                    {"name": k, "value": v, "domain": host, "path": "/"}
                    for k, v in identity.cookies.items()
                ])
            page = await context.new_page()

            def on_request(request) -> None:
                try:
                    url = self.scope.assert_url(request.url)
                except Exception:
                    return
                resource_type = str(request.resource_type)
                result.requests.append({
                    "method": str(request.method).upper(),
                    "url": url,
                    "resource_type": resource_type,
                })
                if resource_type in {"xhr", "fetch"}:
                    result.network_urls.append(url)

            page.on("request", on_request)

            while queue and len(seen) < self.max_pages:
                current = queue.pop(0)
                if current in seen:
                    continue
                seen.add(current)
                try:
                    await page.goto(current, wait_until="domcontentloaded", timeout=20_000)
                    await page.wait_for_timeout(self.settle_ms)
                except Exception:
                    continue
                result.pages.append(current)
                hrefs = await page.locator("a[href]").evaluate_all(
                    "els => els.map(e => e.getAttribute('href')).filter(Boolean)"
                )
                for href in hrefs:
                    candidate = urljoin(current, str(href))
                    try:
                        candidate = self.scope.assert_url(candidate)
                    except Exception:
                        continue
                    if candidate not in seen and candidate not in queue:
                        queue.append(candidate)

            await context.close()
            await browser.close()

        return result
