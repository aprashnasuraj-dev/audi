from __future__ import annotations

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
    total_requests: int = 0
    budget_exhausted: bool = False

    @property
    def urls(self) -> list[str]:
        return sorted(set(self.pages + self.network_urls))


class BrowserCrawler:
    """JavaScript-aware crawler that records XHR/fetch traffic under one identity.

    Every HTTP(S) browser request is intercepted before transmission. Requests
    outside ScopeGuard are aborted; in-scope requests consume the bounded budget.
    Non-network schemes such as data:/blob: may continue without consuming it.
    """

    def __init__(
        self,
        scope: ScopeGuard,
        *,
        max_pages: int = 25,
        settle_ms: int = 750,
        request_budget: int = 250,
    ):
        if request_budget < 1:
            raise ValueError("request_budget must be at least 1")
        self.scope = scope
        self.max_pages = max_pages
        self.settle_ms = settle_ms
        self.request_budget = request_budget

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

            async def route_request(route, request) -> None:
                scheme = (urlsplit(request.url).scheme or "").lower()
                if scheme not in {"http", "https"}:
                    await route.continue_()
                    return
                try:
                    url = self.scope.assert_url(request.url)
                except Exception:
                    await route.abort("blockedbyclient")
                    return
                if result.total_requests >= self.request_budget:
                    result.budget_exhausted = True
                    await route.abort("blockedbyclient")
                    return
                result.total_requests += 1
                resource_type = str(request.resource_type)
                result.requests.append({
                    "method": str(request.method).upper(),
                    "url": url,
                    "resource_type": resource_type,
                })
                if resource_type in {"xhr", "fetch"}:
                    result.network_urls.append(url)
                await route.continue_()

            await context.route("**/*", route_request)
            page = await context.new_page()

            while queue and len(seen) < self.max_pages and not result.budget_exhausted:
                current = queue.pop(0)
                if current in seen:
                    continue
                seen.add(current)
                try:
                    await page.goto(current, wait_until="domcontentloaded", timeout=20_000)
                    await page.wait_for_timeout(self.settle_ms)
                except Exception:
                    if result.budget_exhausted:
                        break
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
