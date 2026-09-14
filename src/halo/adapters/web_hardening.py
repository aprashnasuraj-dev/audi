from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from .base import AdapterRun, IdentityAwareAdapter
from ..models import Finding, Identity, ResultAccounting
from ..scope import ScopeGuard


def _origin_root(url: str) -> str:
    split = urlsplit(url)
    return urlunsplit((split.scheme, split.netloc, "/", "", ""))


class WebHardeningAdapter(IdentityAwareAdapter):
    """Conservative response-policy checks for HSTS and CSP only."""

    name = "halo-web-hardening"
    family = "web-hardening"

    async def run_one(self, target: dict[str, Any], identity: Identity, context: dict[str, Any]) -> AdapterRun:
        limits = target.get("limits", {})
        configured_budget = int(limits.get("request_budget", 250))
        remaining = int(context.setdefault("request_budget_remaining", configured_budget))
        if remaining < 1:
            raise RuntimeError("request budget exhausted before web-hardening scan")

        guard = ScopeGuard(tuple(target["allow_hosts"]))
        seed = guard.assert_url(str(target["url"]))
        discovered = (context.get("discovered") or {}).get(identity.name) or {}
        candidates: list[str] = [seed]
        for value in discovered.get("urls") or []:
            try:
                candidate = guard.assert_url(str(value))
            except Exception:
                continue
            path = (urlsplit(candidate).path or "/").lower()
            if path.startswith("/api/") or "graphql" in path:
                continue
            if candidate not in candidates:
                candidates.append(candidate)
        candidates = candidates[: int(limits.get("max_pages", 25))]

        findings: list[Finding] = []
        checked = 0
        hsts_reported = False
        timeout = float(limits.get("timeout_seconds", 10))
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            headers=identity.headers,
            cookies=identity.cookies,
        ) as client:
            for url in candidates:
                if remaining < 1:
                    raise RuntimeError("request budget exhausted during web-hardening scan")
                response = await client.get(url)
                remaining -= 1
                context["request_budget_remaining"] = remaining
                checked += 1

                split = urlsplit(str(response.url))
                content_type = response.headers.get("content-type", "").lower()
                if split.scheme == "https" and not hsts_reported:
                    hsts_reported = True
                    if "strict-transport-security" not in response.headers:
                        findings.append(Finding(
                            tool=self.name,
                            family=self.family,
                            rule_id="halo.missing-hsts",
                            title="Strict-Transport-Security was not observed",
                            severity="low",
                            url=_origin_root(url),
                            identity=identity.name,
                            confidence=95,
                            evidence_grade="direct",
                            evidence={
                                "method": "GET",
                                "observed_url": url,
                                "status": response.status_code,
                                "header": "Strict-Transport-Security",
                                "interpretation": "hardening gap; not proof of downgrade exploitation",
                            },
                        ))

                if response.status_code < 400 and "text/html" in content_type:
                    if "content-security-policy" not in response.headers:
                        findings.append(Finding(
                            tool=self.name,
                            family=self.family,
                            rule_id="halo.missing-csp",
                            title="Content-Security-Policy was not observed",
                            severity="low",
                            url=url,
                            identity=identity.name,
                            confidence=95,
                            evidence_grade="direct",
                            evidence={
                                "method": "GET",
                                "status": response.status_code,
                                "header": "Content-Security-Policy",
                                "content_type": content_type,
                                "interpretation": "defense-in-depth gap; not proof of injection",
                            },
                        ))

        accounting = ResultAccounting(
            raw_result_count=len(findings),
            normalized_count=len(findings),
            excluded_count=0,
        )
        return AdapterRun(
            findings=findings,
            metadata={
                "responses_checked": checked,
                "request_budget_remaining": remaining,
            },
            accounting=accounting,
        )
