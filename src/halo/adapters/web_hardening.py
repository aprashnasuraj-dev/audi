from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from .base import AdapterRun, IdentityAwareAdapter
from ..live_safety import live_safety
from ..models import Finding, Identity, ResultAccounting
from ..scope import ScopePolicy

_SESSION_COOKIE = re.compile(r"(?:session|sess|auth|token|sid|login)", re.I)


def _origin_root(url: str) -> str:
    split = urlsplit(url)
    return urlunsplit((split.scheme, split.netloc, "/", "", ""))


def _finding(
    *,
    rule_id: str,
    title: str,
    severity: str,
    url: str,
    identity: Identity,
    evidence: dict[str, Any],
    confidence: int = 95,
) -> Finding:
    return Finding(
        tool="halo-web-hardening",
        family="web-hardening",
        rule_id=rule_id,
        title=title,
        severity=severity,
        url=url,
        identity=identity.name,
        confidence=confidence,
        evidence_grade="direct",
        evidence=evidence,
    )


class WebHardeningAdapter(IdentityAwareAdapter):
    """Passive response-policy checks on already-authorized URLs only."""

    name = "halo-web-hardening"
    family = "web-hardening"

    async def run_one(self, target: dict[str, Any], identity: Identity, context: dict[str, Any]) -> AdapterRun:
        limits = target.get("limits", {})
        configured_budget = int(limits.get("request_budget", 250))
        remaining = int(context.setdefault("request_budget_remaining", configured_budget))
        if remaining < 1:
            raise RuntimeError("request budget exhausted before web-hardening scan")

        policy = context.get("_scope_policy")
        if policy is None:
            policy = ScopePolicy.from_target(target)
            context["_scope_policy"] = policy
        if not isinstance(policy, ScopePolicy):
            raise TypeError("context contains invalid scope policy")

        safety = live_safety(context, target)
        seed = policy.assert_url(str(target["url"]))
        discovered = (context.get("discovered") or {}).get(identity.name) or {}
        candidates: list[str] = [seed]
        for value in discovered.get("urls") or []:
            try:
                candidate = policy.assert_url(str(value))
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
        hsts_origins: set[str] = set()
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
                await safety.before_request(url)
                response = await client.get(url)
                safety.observe_response(url, response.status_code, response.headers)
                remaining -= 1
                context["request_budget_remaining"] = remaining
                checked += 1

                observed_url = str(response.url)
                split = urlsplit(observed_url)
                content_type = response.headers.get("content-type", "").lower()
                is_html = response.status_code < 400 and "text/html" in content_type
                base_evidence = {
                    "method": "GET",
                    "status": response.status_code,
                    "observed_url": observed_url,
                    "scope_state": policy.state_for_host(split.hostname or "").value,
                }

                origin = _origin_root(observed_url)
                if split.scheme == "https" and origin not in hsts_origins:
                    hsts_origins.add(origin)
                    if "strict-transport-security" not in response.headers:
                        findings.append(_finding(
                            rule_id="halo.missing-hsts",
                            title="Strict-Transport-Security was not observed",
                            severity="low",
                            url=origin,
                            identity=identity,
                            evidence={
                                **base_evidence,
                                "header": "Strict-Transport-Security",
                                "interpretation": "hardening gap; not proof of downgrade exploitation",
                            },
                        ))

                if is_html:
                    csp = response.headers.get("content-security-policy", "")
                    report_only = response.headers.get("content-security-policy-report-only", "")
                    if not csp:
                        findings.append(_finding(
                            rule_id="halo.missing-csp",
                            title="Enforcing Content-Security-Policy was not observed",
                            severity="low",
                            url=observed_url,
                            identity=identity,
                            evidence={
                                **base_evidence,
                                "header": "Content-Security-Policy",
                                "report_only_present": bool(report_only),
                                "interpretation": "defense-in-depth gap; not proof of injection",
                            },
                        ))
                    if response.headers.get("x-content-type-options", "").lower() != "nosniff":
                        findings.append(_finding(
                            rule_id="halo.missing-nosniff",
                            title="X-Content-Type-Options nosniff was not observed",
                            severity="info",
                            url=observed_url,
                            identity=identity,
                            evidence={**base_evidence, "header": "X-Content-Type-Options"},
                            confidence=90,
                        ))
                    frame_ancestors = "frame-ancestors" in csp.lower()
                    xfo = response.headers.get("x-frame-options", "").strip()
                    if not frame_ancestors and not xfo:
                        findings.append(_finding(
                            rule_id="halo.missing-frame-protection",
                            title="No frame-embedding policy was observed",
                            severity="low",
                            url=observed_url,
                            identity=identity,
                            evidence={
                                **base_evidence,
                                "headers": ["Content-Security-Policy frame-ancestors", "X-Frame-Options"],
                                "interpretation": "clickjacking protection gap; exploitability depends on page actions",
                            },
                            confidence=90,
                        ))

                acao = response.headers.get("access-control-allow-origin", "").strip()
                acac = response.headers.get("access-control-allow-credentials", "").strip().lower()
                if acao == "*" and acac == "true":
                    findings.append(_finding(
                        rule_id="halo.cors-wildcard-with-credentials",
                        title="CORS advertises wildcard origin with credentials",
                        severity="low",
                        url=observed_url,
                        identity=identity,
                        evidence={
                            **base_evidence,
                            "access_control_allow_origin": acao,
                            "access_control_allow_credentials": acac,
                            "interpretation": "misconfiguration signal; browsers reject wildcard credential sharing",
                        },
                        confidence=90,
                    ))

                for cookie in response.headers.get_list("set-cookie"):
                    name = cookie.split("=", 1)[0].strip()
                    if not _SESSION_COOKIE.search(name):
                        continue
                    lower = cookie.lower()
                    if split.scheme == "https" and "; secure" not in lower:
                        findings.append(_finding(
                            rule_id="halo.session-cookie-missing-secure",
                            title="Session-like cookie is missing Secure",
                            severity="medium",
                            url=observed_url,
                            identity=identity,
                            evidence={**base_evidence, "cookie_name": name, "attribute": "Secure"},
                        ))
                    if "; httponly" not in lower:
                        findings.append(_finding(
                            rule_id="halo.session-cookie-missing-httponly",
                            title="Session-like cookie is missing HttpOnly",
                            severity="medium",
                            url=observed_url,
                            identity=identity,
                            evidence={**base_evidence, "cookie_name": name, "attribute": "HttpOnly"},
                        ))
                    if "samesite=" not in lower:
                        findings.append(_finding(
                            rule_id="halo.session-cookie-missing-samesite",
                            title="Session-like cookie is missing SameSite",
                            severity="low",
                            url=observed_url,
                            identity=identity,
                            evidence={**base_evidence, "cookie_name": name, "attribute": "SameSite"},
                            confidence=90,
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
                "scope_transitions": policy.provenance(),
            },
            accounting=accounting,
        )
