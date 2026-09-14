from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from .base import AdapterRun, IdentityAwareAdapter
from ..discovery.browser import BrowserCrawler
from ..identity import authentication_mode
from ..live_safety import live_safety
from ..models import Identity
from ..scope import ScopePolicy


def _edge_profile(responses: list[dict[str, object]]) -> dict[str, object]:
    technologies: set[str] = set()
    challenge_statuses: list[int] = []
    servers: set[str] = set()
    for item in responses:
        headers = {str(k).lower(): str(v) for k, v in dict(item.get("headers") or {}).items()}
        status = int(item.get("status") or 0)
        server = headers.get("server", "").strip()
        if server:
            servers.add(server)
        if "cf-ray" in headers or "cloudflare" in server.lower():
            technologies.add("cloudflare")
        if "x-akamai-transformed" in headers or "akamai" in server.lower():
            technologies.add("akamai")
        if "x-sucuri-id" in headers or "sucuri" in server.lower():
            technologies.add("sucuri")
        if status in {403, 429, 503}:
            challenge_statuses.append(status)
    return {
        "technologies": sorted(technologies),
        "servers": sorted(servers),
        "challenge_statuses": challenge_statuses,
    }


def _auth_flow_hints(items: list[dict[str, str]]) -> list[dict[str, str]]:
    hints: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in items:
        url = str(item.get("url") or "")
        if not url or url in seen:
            continue
        split = urlsplit(url)
        haystack = f"{split.hostname or ''}{split.path or ''}{split.query or ''}".lower()
        if not any(token in haystack for token in ("oauth", "authorize", "oidc", "saml", "sso", "login")):
            continue
        seen.add(url)
        hints.append({
            "url": url,
            "host": split.hostname or "",
            "reason": str(item.get("reason") or "passive-auth-flow-observation"),
        })
    return hints[:25]


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
        edge = _edge_profile(result.responses)
        auth_hints = _auth_flow_hints(result.blocked_requests + result.passive_third_party_requests)
        discovered = context.setdefault("discovered", {})
        discovered[identity.name] = {
            "role": identity.role,
            "urls": result.urls,
            "requests": result.requests,
            "responses": result.responses,
            "websockets": result.websockets,
            "page_evidence": result.page_evidence,
            "edge_profile": edge,
            "auth_flow_hints": auth_hints,
            "authentication_initial_verified": result.authentication_initial_verified,
            "authentication_final_verified": result.authentication_final_verified,
            "authentication_verified": result.authentication_verified,
            "authentication_reason": result.authentication_reason,
        }
        context["scope_transitions"] = policy.provenance()
        metadata = {
            "identity_role": identity.role,
            "url_count": len(result.urls),
            "request_count": result.total_requests,
            "websocket_count": len(result.websockets),
            "request_budget_remaining": context["request_budget_remaining"],
            "budget_exhausted": result.budget_exhausted,
            "authentication_initial_verified": result.authentication_initial_verified,
            "authentication_final_verified": result.authentication_final_verified,
            "authentication_verified": result.authentication_verified,
            "authentication_reason": result.authentication_reason,
            "scope_transitions": policy.provenance(),
            "page_evidence": result.page_evidence[:50],
            "edge_profile": edge,
            "auth_flow_hints": auth_hints,
            "blocked_request_count": len(result.blocked_requests),
            "blocked_requests": result.blocked_requests[:50],
            "passive_third_party_request_count": len(result.passive_third_party_requests),
            "passive_third_party_requests": result.passive_third_party_requests[:50],
        }
        if identity.role != "anonymous" and authentication_mode(target) == "required":
            if not result.authentication_verified:
                raise RuntimeError(
                    f"authentication was not verified at both ends for identity {identity.name!r}: "
                    f"{result.authentication_reason}"
                )
        if result.budget_exhausted:
            raise RuntimeError(
                f"request budget exhausted during browser discovery for identity {identity.name!r}"
            )
        if result.rate_limit_stop:
            raise RuntimeError(result.rate_limit_stop)
        return AdapterRun(metadata=metadata)
