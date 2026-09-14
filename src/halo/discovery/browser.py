from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from ..live_safety import LiveSafetyController, LiveSafetyStop
from ..models import Identity
from ..scope import ScopePolicy, ScopeState

_GRAPHQL_OPERATION = re.compile(r"\b(?:query|mutation|subscription)\s+([_A-Za-z][_0-9A-Za-z]*)")
_GRAPHQL_ROOT = re.compile(r"\{\s*([_A-Za-z][_0-9A-Za-z]*)")
_SAFE_RESPONSE_HEADERS = frozenset({
    "server",
    "via",
    "cf-ray",
    "cf-cache-status",
    "x-sucuri-id",
    "x-akamai-transformed",
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
})


def _graphql_operation_from_post_data(post_data: str | None) -> str | None:
    if not post_data:
        return None
    try:
        payload = json.loads(post_data)
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    operation_name = payload.get("operationName")
    if isinstance(operation_name, str) and operation_name.strip():
        return operation_name.strip()
    query = payload.get("query")
    if not isinstance(query, str):
        return None
    match = _GRAPHQL_OPERATION.search(query)
    if match:
        return match.group(1)
    match = _GRAPHQL_ROOT.search(query)
    return match.group(1) if match else None


@dataclass
class DiscoveryResult:
    identity: str
    pages: list[str] = field(default_factory=list)
    page_evidence: list[dict[str, str]] = field(default_factory=list)
    network_urls: list[str] = field(default_factory=list)
    requests: list[dict[str, str]] = field(default_factory=list)
    responses: list[dict[str, object]] = field(default_factory=list)
    websockets: list[str] = field(default_factory=list)
    blocked_requests: list[dict[str, str]] = field(default_factory=list)
    passive_third_party_requests: list[dict[str, str]] = field(default_factory=list)
    total_requests: int = 0
    budget_exhausted: bool = False
    authentication_initial_verified: bool = False
    authentication_final_verified: bool = False
    authentication_verified: bool = False
    authentication_reason: str = ""
    rate_limit_stop: str | None = None

    @property
    def urls(self) -> list[str]:
        return sorted(set(self.pages + self.network_urls))


class BrowserCrawler:
    """JavaScript-aware, scope-provenance-aware browser crawler.

    Only seed or navigation-derived FLOW_ALLOWED hosts are audited. Third-party
    static resources may optionally load so SPAs remain functional, but they are
    never added to audit inventory and authentication headers are stripped.
    Request bodies are never retained; GraphQL POSTs expose only an operation
    name derived in-memory. Rendered DOM content is not stored; only a SHA-256
    fingerprint and page title are retained for navigation-flow evidence.
    """

    PASSIVE_RESOURCE_TYPES = frozenset({"stylesheet", "script", "image", "font", "media"})

    def __init__(
        self,
        scope: ScopePolicy,
        safety: LiveSafetyController,
        *,
        max_pages: int = 25,
        settle_ms: int = 750,
        request_budget: int = 250,
        allow_third_party_resources: bool = False,
    ):
        if request_budget < 1:
            raise ValueError("request_budget must be at least 1")
        self.scope = scope
        self.safety = safety
        self.max_pages = max_pages
        self.settle_ms = settle_ms
        self.request_budget = request_budget
        self.allow_third_party_resources = allow_third_party_resources

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
            context_kwargs = {}
            if identity.storage_state_path:
                context_kwargs["storage_state"] = identity.storage_state_path
            context = await browser.new_context(**context_kwargs)
            if identity.cookies:
                host = urlsplit(seed).hostname or ""
                await context.add_cookies([
                    {"name": k, "value": v, "domain": host, "path": "/"}
                    for k, v in identity.cookies.items()
                ])

            auth_verified = identity.role == "anonymous"
            result.authentication_initial_verified = auth_verified
            result.authentication_final_verified = auth_verified
            result.authentication_verified = auth_verified
            result.authentication_reason = "anonymous identity" if auth_verified else "authentication not yet verified"

            async def route_request(route, request) -> None:
                nonlocal auth_verified
                scheme = (urlsplit(request.url).scheme or "").lower()
                if scheme not in {"http", "https"}:
                    await route.continue_()
                    return

                resource_type = str(request.resource_type)
                host = urlsplit(request.url).hostname or ""
                state = self.scope.state_for_host(host)
                top_level = bool(request.is_navigation_request() and request.frame.parent_frame is None)
                allowed_url: str | None = None

                if state in {ScopeState.SEED_ALLOWED, ScopeState.FLOW_ALLOWED}:
                    allowed_url = self.scope.assert_url(request.url)
                elif top_level:
                    redirected = request.redirected_from
                    source_url = redirected.url if redirected is not None else request.frame.url
                    try:
                        allowed_url, _ = self.scope.try_navigation_transition(
                            request.url,
                            source_url=source_url,
                            identity=identity,
                            top_level_navigation=True,
                            authentication_verified=auth_verified,
                            event="redirect" if redirected is not None else "top-level-navigation",
                        )
                    except Exception as exc:
                        result.blocked_requests.append({
                            "method": str(request.method).upper(),
                            "url": request.url,
                            "resource_type": resource_type,
                            "reason": str(exc),
                        })
                        await route.abort("blockedbyclient")
                        return
                elif (
                    self.allow_third_party_resources
                    and state is ScopeState.THIRD_PARTY
                    and resource_type in self.PASSIVE_RESOURCE_TYPES
                ):
                    headers = {
                        key: value for key, value in request.headers.items()
                        if key.lower() not in {"authorization", "cookie", "proxy-authorization"}
                    }
                    result.passive_third_party_requests.append({
                        "method": str(request.method).upper(),
                        "url": request.url,
                        "resource_type": resource_type,
                    })
                    await route.continue_(headers=headers)
                    return
                else:
                    result.blocked_requests.append({
                        "method": str(request.method).upper(),
                        "url": request.url,
                        "resource_type": resource_type,
                        "reason": f"scope state {state.value}",
                    })
                    await route.abort("blockedbyclient")
                    return

                if result.total_requests >= self.request_budget:
                    result.budget_exhausted = True
                    await route.abort("blockedbyclient")
                    return
                await self.safety.before_request(allowed_url)
                result.total_requests += 1
                headers = dict(request.headers)
                headers.update(identity.headers)
                record = {
                    "method": str(request.method).upper(),
                    "url": allowed_url,
                    "resource_type": resource_type,
                }
                content_type = headers.get("content-type") or headers.get("Content-Type")
                if content_type:
                    record["content_type"] = str(content_type).split(";", 1)[0].strip().lower()
                if "graphql" in (urlsplit(allowed_url).path or "").lower():
                    operation = _graphql_operation_from_post_data(request.post_data)
                    if operation:
                        record["graphql_operation"] = operation
                result.requests.append(record)
                if resource_type in {"xhr", "fetch"}:
                    result.network_urls.append(allowed_url)
                await route.continue_(headers=headers)

            await context.route("**/*", route_request)
            page = await context.new_page()

            async def observe_response(response) -> None:
                url = str(response.url)
                host = urlsplit(url).hostname or ""
                if not self.scope.allows_host(host):
                    return
                headers = await response.all_headers()
                selected_headers = {
                    key: value for key, value in headers.items()
                    if key.lower() in _SAFE_RESPONSE_HEADERS
                }
                result.responses.append({
                    "url": url,
                    "status": int(response.status),
                    "content_type": str(headers.get("content-type", "")),
                    "headers": selected_headers,
                })
                try:
                    self.safety.observe_response(url, int(response.status), headers)
                except LiveSafetyStop as exc:
                    result.rate_limit_stop = str(exc)

            def observe_websocket(socket) -> None:
                url = str(socket.url)
                host = urlsplit(url).hostname or ""
                if self.scope.allows_host(host) and url not in result.websockets:
                    result.websockets.append(url)

            page.on("response", lambda response: asyncio.create_task(observe_response(response)))
            page.on("websocket", observe_websocket)

            async def verify_authentication(stage: str) -> tuple[bool, str]:
                if identity.role == "anonymous":
                    return True, "anonymous identity"
                if not identity.auth_check_url:
                    return False, f"{stage} authentication check has no auth_check_url"
                try:
                    check_url = self.scope.assert_url(identity.auth_check_url)
                    response = await page.goto(check_url, wait_until="domcontentloaded", timeout=20_000)
                    await page.wait_for_timeout(min(self.settle_ms, 500))
                    ok = response is not None and 200 <= int(response.status) < 400
                    reasons: list[str] = []
                    if identity.auth_check_selector:
                        selector_ok = await page.locator(identity.auth_check_selector).count() > 0
                        ok = ok and selector_ok
                        if not selector_ok:
                            reasons.append("auth selector not found")
                    if identity.auth_check_contains:
                        body_text = await page.locator("body").inner_text()
                        contains_ok = identity.auth_check_contains in body_text
                        ok = ok and contains_ok
                        if not contains_ok:
                            reasons.append("auth marker text not found")
                    if not identity.auth_check_selector and not identity.auth_check_contains:
                        ok = False
                        reasons.append("auth check requires selector or text marker")
                    if result.rate_limit_stop:
                        return False, f"{stage} authentication check stopped by live-safety control"
                    return ok, f"{stage} verified" if ok else f"{stage} failed: {'; '.join(reasons) or 'unexpected status'}"
                except Exception as exc:
                    return False, f"{stage} authentication check failed: {type(exc).__name__}"

            if identity.role != "anonymous":
                initial_ok, initial_reason = await verify_authentication("initial")
                auth_verified = initial_ok
                result.authentication_initial_verified = initial_ok
                result.authentication_verified = initial_ok
                result.authentication_reason = initial_reason

            while queue and len(seen) < self.max_pages and not result.budget_exhausted:
                if result.rate_limit_stop:
                    raise LiveSafetyStop(result.rate_limit_stop)
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
                final_url = str(page.url)
                try:
                    final_url = self.scope.assert_url(final_url)
                except Exception:
                    continue
                result.pages.append(final_url)
                rendered = await page.content()
                result.page_evidence.append({
                    "url": final_url,
                    "title": (await page.title())[:200],
                    "dom_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
                })
                hrefs = await page.locator("a[href]").evaluate_all(
                    "els => els.map(e => e.getAttribute('href')).filter(Boolean)"
                )
                for href in hrefs:
                    candidate = urljoin(final_url, str(href))
                    try:
                        candidate = self.scope.assert_url(candidate)
                    except Exception:
                        continue
                    if candidate not in seen and candidate not in queue:
                        queue.append(candidate)

            if identity.role != "anonymous" and not result.budget_exhausted and not result.rate_limit_stop:
                final_ok, final_reason = await verify_authentication("final")
                result.authentication_final_verified = final_ok
                result.authentication_verified = bool(result.authentication_initial_verified and final_ok)
                result.authentication_reason = (
                    "initial and final authentication verified"
                    if result.authentication_verified
                    else final_reason
                )

            await context.close()
            await browser.close()

        return result
