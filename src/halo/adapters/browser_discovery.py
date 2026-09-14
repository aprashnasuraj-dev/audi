from __future__ import annotations

from typing import Any

from .base import AdapterRun, IdentityAwareAdapter
from ..discovery.browser import BrowserCrawler
from ..live_safety import live_safety
from ..models import Identity
from ..scope import ScopePolicy


class BrowserDiscoveryAdapter(IdentityAwareAdapter):
    name = "playwright-discovery"
    family = "browser-discovery"

    async def run_one(self, target: dict[str, Any], identity: Identity, context: dict[str, Any]) -> AdapterRun:
        limits = target.get("limits", {})
        configured_budget = int(limits.get("request_budget", 250))
        remaining = int(context.setdefault("request_budget_remaining", configured_budget))
        if remaining < 1:
            raise RuntimeError("request budget exhausted before browser discovery completed")

        policy = context.get("_scope_policy")
        if policy is None:
            policy = ScopePolicy.from_target(target)
            context["_scope_policy"] = policy
        if not isinstance(policy, ScopePolicy):
            raise TypeError("context contains invalid scope policy")

        crawler = BrowserCrawler(
            policy,
            live_safety(context, target),
            max_pages=int(limits.get("max_pages", 25)),
            settle_ms=int(target.get("browser", {}).get("settle_ms", 750)),
            request_budget=remaining,
            allow_third_party_resources=bool(
                target.get("browser", {}).get("allow_third_party_resources", False)
            ),
        )
        result = await crawler.crawl(str(target["url"]), identity)
        context["request_budget_remaining"] = max(0, remaining - result.total_requests)
        discovered = context.setdefault("discovered", {})
        discovered[identity.name] = {
            "urls": result.urls,
            "requests": result.requests,
            "responses": result.responses,
            "authentication_verified": result.authentication_verified,
            "authentication_reason": result.authentication_reason,
        }
        context["scope_transitions"] = policy.provenance()
        metadata = {
            "url_count": len(result.urls),
            "request_count": result.total_requests,
            "request_budget_remaining": context["request_budget_remaining"],
            "budget_exhausted": result.budget_exhausted,
            "authentication_verified": result.authentication_verified,
            "authentication_reason": result.authentication_reason,
            "scope_transitions": policy.provenance(),
            "blocked_request_count": len(result.blocked_requests),
            "blocked_requests": result.blocked_requests[:50],
            "passive_third_party_request_count": len(result.passive_third_party_requests),
            "passive_third_party_requests": result.passive_third_party_requests[:50],
        }
        if identity.role != "anonymous" and target.get("require_authenticated_identity"):
            if not result.authentication_verified:
                raise RuntimeError(
                    f"authentication was not verified for identity {identity.name!r}: "
                    f"{result.authentication_reason}"
                )
        if result.budget_exhausted:
            raise RuntimeError(
                f"request budget exhausted during browser discovery for identity {identity.name!r}"
            )
        if result.rate_limit_stop:
            raise RuntimeError(result.rate_limit_stop)
        return AdapterRun(metadata=metadata)
