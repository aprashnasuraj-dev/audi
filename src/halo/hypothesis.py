from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import yaml

from .adapters.graphql_schema import _schema_roots
from .adapters.trivy_exec import TrivyContainerAdapter, TrivyIaCAdapter
from .identity import IdentityVault
from .input_gate import evaluate_family_input
from .live_safety import live_safety
from .models import FamilyStatus, Finding
from .replay import CapturedRequest, ReplayTransport
from .scope import ScopePolicy

_HTTP_METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})


def enrich_threat_model(findings: list[Finding]) -> list[Finding]:
    enriched: list[Finding] = []
    for finding in findings:
        evidence = dict(finding.evidence)
        rule = finding.rule_id.lower()
        if any(token in rule for token in ("auth", "identity", "nonadmin", "admin-surface", "access")):
            threat = "authorization"
            asset = "authenticated application data"
        elif "secret" in rule:
            threat = "information-disclosure"
            asset = "confidential data"
        elif finding.family in {"container", "iac"}:
            threat = "supply-chain-or-configuration"
            asset = "deployment environment"
        elif finding.family in {"api-contract", "graphql-schema"}:
            threat = "contract-drift"
            asset = "application interface"
        elif finding.family == "web-hardening":
            threat = "browser-policy-hardening"
            asset = "web response policy"
        else:
            threat = "application-surface"
            asset = "web application"
        evidence["threat_model"] = {
            "threat": threat,
            "asset": asset,
            "entry_point": urlsplit(finding.url).path or finding.url or "/",
        }
        enriched.append(replace(finding, evidence=evidence))
    return enriched


def compose_chains(findings: list[Finding]) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str | None], list[Finding]] = {}
    for finding in findings:
        buckets.setdefault((finding.url, finding.identity), []).append(finding)
    chains: list[dict[str, Any]] = []
    for (url, identity), items in buckets.items():
        if len(items) < 2:
            continue
        chains.append({
            "url": url,
            "identity": identity,
            "finding_rules": sorted({item.rule_id for item in items}),
            "confidence": min(item.confidence for item in items),
            "status": "hypothesis",
        })
    return chains


class ReproductionVerifier:
    """Re-test each supported candidate before final-report admission."""

    def __init__(
        self,
        target: dict[str, Any],
        vault: IdentityVault,
        *,
        repo_root: Path | None = None,
        context: dict[str, Any] | None = None,
        target_name: str = "target",
    ):
        self.target = target
        self.vault = vault
        self.repo_root = (repo_root or Path(".")).resolve()
        self.context = context if context is not None else {}
        self.target_name = target_name
        policy = self.context.get("_scope_policy")
        if policy is None:
            policy = ScopePolicy.from_target(target)
            self.context["_scope_policy"] = policy
        if not isinstance(policy, ScopePolicy):
            raise TypeError("context contains invalid scope policy")
        self.policy = policy
        self.safety = live_safety(self.context, target)
        self.replay = ReplayTransport(
            self.policy,
            timeout=float(target.get("limits", {}).get("timeout_seconds", 10)),
            safety=self.safety,
        )
        self._tool_reproduction_cache: dict[str, set[tuple[str, str]]] = {}
        self.errors: list[str] = []
        self.budget_exhausted = False
        self.reproduced = 0
        self.rejected = 0

    def _consume_target_requests(self, count: int) -> None:
        configured = int(self.target.get("limits", {}).get("request_budget", 250))
        remaining = int(self.context.setdefault("request_budget_remaining", configured))
        if remaining < count:
            self.budget_exhausted = True
            raise RuntimeError(f"request budget exhausted during reproduction: need {count}, have {remaining}")
        self.context["request_budget_remaining"] = remaining - count

    async def _request(self, finding: Finding) -> httpx.Response:
        identity = self.vault.get(str(finding.identity or "anonymous"))
        url = self.policy.assert_url(finding.url)
        self._consume_target_requests(1)
        await self.safety.before_request(url)
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=float(self.target.get("limits", {}).get("timeout_seconds", 10)),
            headers=identity.headers,
            cookies=identity.cookies,
        ) as client:
            response = await client.get(url)
        self.safety.observe_response(url, response.status_code, response.headers)
        return response

    async def _replay_status(self, finding: Finding) -> int | None:
        method = str(finding.evidence.get("method", "GET")).upper()
        if method not in {"GET", "HEAD"} or not finding.identity:
            return None
        request = CapturedRequest(method=method, url=finding.url, headers={})
        identity = self.vault.get(finding.identity)
        self._consume_target_requests(2)
        diff = await self.replay.compare(request, identity, identity)
        return diff.a.status_code

    async def _verify_header_absence(self, finding: Finding, header: str) -> bool:
        response = await self._request(finding)
        return response.status_code < 500 and header.lower() not in {key.lower() for key in response.headers}

    async def _verify_frame_protection_absence(self, finding: Finding) -> bool:
        response = await self._request(finding)
        csp = response.headers.get("content-security-policy", "").lower()
        xfo = response.headers.get("x-frame-options", "").strip()
        return response.status_code < 500 and "frame-ancestors" not in csp and not xfo

    async def _verify_cookie_attribute_absence(self, finding: Finding, attribute: str) -> bool:
        response = await self._request(finding)
        cookie_name = str(finding.evidence.get("cookie_name") or "")
        if not cookie_name:
            return False
        cookies = [value for value in response.headers.get_list("set-cookie") if value.split("=", 1)[0].strip() == cookie_name]
        if not cookies:
            return False
        needle = attribute.lower()
        return any(needle not in cookie.lower() for cookie in cookies)

    async def _verify_cors_wildcard_credentials(self, finding: Finding) -> bool:
        response = await self._request(finding)
        return (
            response.headers.get("access-control-allow-origin", "").strip() == "*"
            and response.headers.get("access-control-allow-credentials", "").strip().lower() == "true"
        )

    def _load_openapi_paths(self) -> dict[str, set[str]]:
        spec_path = (self.repo_root / str(self.target.get("openapi", ""))).resolve()
        spec = yaml.safe_load(spec_path.read_text(encoding="utf-8")) or {}
        paths = spec.get("paths") or {}
        output: dict[str, set[str]] = {}
        for path, payload in paths.items():
            methods = set()
            if isinstance(payload, dict):
                methods = {
                    str(key).lower() for key in payload
                    if str(key).lower() in _HTTP_METHODS
                }
            output[str(path)] = methods
        return output

    async def _verify_openapi(self, finding: Finding) -> bool:
        declared = self._load_openapi_paths()
        path = urlsplit(finding.url).path or "/"
        method = str(finding.evidence.get("method", "GET")).upper()
        captured = bool(finding.evidence.get("captured_request"))

        if finding.rule_id == "halo.openapi-undeclared-endpoint":
            if path in declared:
                return False
            status = await self._replay_status(finding)
            if status is not None:
                return status not in {404, 410}
            return captured

        if finding.rule_id == "halo.openapi-undeclared-method":
            if path not in declared:
                return False
            allowed = declared[path]
            normalized = method.lower()
            if normalized == "head" and "get" in allowed:
                return False
            if normalized in allowed:
                return False
            # Do not replay POST/PUT/PATCH/DELETE. The browser-observed request is
            # direct evidence that the method occurred; reproduction revalidates
            # only the contract mismatch.
            if method not in {"GET", "HEAD"}:
                return captured
            status = await self._replay_status(finding)
            return status is not None and status not in {404, 410}

        return False

    async def _verify_graphql(self, finding: Finding) -> bool:
        schema_path = (self.repo_root / str(self.target.get("graphql_schema", ""))).resolve()
        roots = _schema_roots(schema_path.read_text(encoding="utf-8"))
        operation = str(finding.evidence.get("operation") or "")
        if not operation or operation in roots:
            return False
        method = str(finding.evidence.get("method", "GET")).upper()
        if method not in {"GET", "HEAD"}:
            return bool(finding.evidence.get("captured_request"))
        status = await self._replay_status(finding)
        return status is not None and status not in {404, 410}

    async def _repeat_tool_family(self, family: str) -> set[tuple[str, str]]:
        if family in self._tool_reproduction_cache:
            return self._tool_reproduction_cache[family]
        gate = evaluate_family_input(family, self.target, self.repo_root)
        if gate.status is not FamilyStatus.RAN:
            self._tool_reproduction_cache[family] = set()
            return set()
        if family == "container":
            findings, coverage = await TrivyContainerAdapter().run(self.target_name, str(gate.value))
        elif family == "iac":
            findings, coverage = await TrivyIaCAdapter().run(self.target_name, [str(path) for path in gate.value])
        else:
            findings, coverage = [], None
        reproduced = set()
        if coverage is not None and coverage.status is FamilyStatus.RAN:
            reproduced = {(item.rule_id, item.url) for item in findings}
        elif coverage is not None:
            raise RuntimeError(f"{family} reproduction scan did not complete: {coverage.status.value} {coverage.reason}")
        self._tool_reproduction_cache[family] = reproduced
        return reproduced

    async def verify(self, finding: Finding) -> bool:
        method = str(finding.evidence.get("method", "GET")).upper()
        request = CapturedRequest(method=method, url=finding.url, headers={})

        if finding.rule_id == "halo.nonadmin-admin-surface-access":
            identity = self.vault.get(str(finding.identity))
            self._consume_target_requests(2)
            diff = await self.replay.compare(request, identity, self.vault.get("anonymous"))
            return 200 <= diff.a.status_code < 300

        if finding.rule_id == "halo.identity-response-differential":
            if not finding.identity or not finding.compared_identity:
                return False
            self._consume_target_requests(2)
            diff = await self.replay.compare(
                request,
                self.vault.get(finding.identity),
                self.vault.get(finding.compared_identity),
            )
            return diff.material

        if finding.rule_id == "halo.missing-hsts":
            return await self._verify_header_absence(finding, "Strict-Transport-Security")
        if finding.rule_id == "halo.missing-csp":
            return await self._verify_header_absence(finding, "Content-Security-Policy")
        if finding.rule_id == "halo.missing-nosniff":
            return await self._verify_header_absence(finding, "X-Content-Type-Options")
        if finding.rule_id == "halo.missing-frame-protection":
            return await self._verify_frame_protection_absence(finding)
        if finding.rule_id == "halo.session-cookie-missing-secure":
            return await self._verify_cookie_attribute_absence(finding, "secure")
        if finding.rule_id == "halo.session-cookie-missing-httponly":
            return await self._verify_cookie_attribute_absence(finding, "httponly")
        if finding.rule_id == "halo.session-cookie-missing-samesite":
            return await self._verify_cookie_attribute_absence(finding, "samesite=")
        if finding.rule_id == "halo.cors-wildcard-with-credentials":
            return await self._verify_cors_wildcard_credentials(finding)
        if finding.rule_id in {"halo.openapi-undeclared-endpoint", "halo.openapi-undeclared-method"}:
            return await self._verify_openapi(finding)
        if finding.rule_id == "halo.graphql-operation-outside-schema":
            return await self._verify_graphql(finding)
        if finding.family in {"container", "iac"}:
            reproduced = await self._repeat_tool_family(finding.family)
            return (finding.rule_id, finding.url) in reproduced

        raise NotImplementedError(f"no reproduction verifier registered for {finding.family}/{finding.rule_id}")

    async def verified_only(self, findings: list[Finding]) -> list[Finding]:
        verified: list[Finding] = []
        for finding in findings:
            try:
                confirmed = await self.verify(finding)
            except Exception as exc:
                self.errors.append(f"{finding.rule_id} @ {finding.url}: {type(exc).__name__}: {exc}")
                continue
            if not confirmed:
                self.rejected += 1
                continue
            self.reproduced += 1
            evidence = dict(finding.evidence)
            evidence["reproduction"] = {"confirmed": True}
            verified.append(replace(finding, evidence=evidence))
        return verified
