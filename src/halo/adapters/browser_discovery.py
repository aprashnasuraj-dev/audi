from __future__ import annotations

from typing import Any

from .base import AdapterRun, IdentityAwareAdapter
from ..discovery.browser import BrowserCrawler
from ..models import Identity
from ..scope import ScopeGuard


class BrowserDiscoveryAdapter(IdentityAwareAdapter):
    name = "playwright-discovery"
    family = "browser-discovery"

    async def run_one(self, target: dict[str, Any], identity: Identity, context: dict[str, Any]) -> AdapterRun:
        guard = ScopeGuard(tuple(target["allow_hosts"]))
        crawler = BrowserCrawler(
            guard,
            max_pages=int(target.get("limits", {}).get("max_pages", 25)),
            settle_ms=int(target.get("browser", {}).get("settle_ms", 750)),
        )
        result = await crawler.crawl(str(target["url"]), identity)
        discovered = context.setdefault("discovered", {})
        discovered[identity.name] = {
            "urls": result.urls,
            "requests": result.requests,
        }
        return AdapterRun(metadata={"url_count": len(result.urls), "request_count": len(result.requests)})
