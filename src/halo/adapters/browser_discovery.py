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
        limits = target.get("limits", {})
        configured_budget = int(limits.get("request_budget", 250))
        remaining = int(context.setdefault("request_budget_remaining", configured_budget))
        if remaining < 1:
            raise RuntimeError("request budget exhausted before browser discovery completed")

        guard = ScopeGuard(tuple(target["allow_hosts"]))
        crawler = BrowserCrawler(
            guard,
            max_pages=int(limits.get("max_pages", 25)),
            settle_ms=int(target.get("browser", {}).get("settle_ms", 750)),
            request_budget=remaining,
        )
        result = await crawler.crawl(str(target["url"]), identity)
        context["request_budget_remaining"] = max(0, remaining - result.total_requests)
        discovered = context.setdefault("discovered", {})
        discovered[identity.name] = {
            "urls": result.urls,
            "requests": result.requests,
        }
        metadata = {
            "url_count": len(result.urls),
            "request_count": result.total_requests,
            "request_budget_remaining": context["request_budget_remaining"],
            "budget_exhausted": result.budget_exhausted,
        }
        if result.budget_exhausted:
            raise RuntimeError(
                f"request budget exhausted during browser discovery for identity {identity.name!r}"
            )
        return AdapterRun(metadata=metadata)
