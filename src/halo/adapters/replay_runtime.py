from __future__ import annotations

from itertools import combinations
from typing import Any
from urllib.parse import urlsplit

from .base import VaultBoundAdapter
from ..identity import IdentityVault
from ..models import CoverageRecord, FamilyStatus, Finding
from ..replay import CapturedRequest, ReplayTransport
from ..scope import ScopeGuard


class ReplayRuntimeAdapter(VaultBoundAdapter):
    name = "identity-replay"
    family = "runtime-verification"

    async def run_for_identities(
        self,
        target_name: str,
        target: dict[str, Any],
        vault: IdentityVault,
        *,
        identities: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> tuple[list[Finding], CoverageRecord]:
        selected = vault.selected(identities)
        coverage = CoverageRecord(
            target=target_name,
            family=self.family,
            status=FamilyStatus.RAN,
            tools_expected=1,
            identities_attempted=[item.name for item in selected],
        )
        if len(selected) < 2:
            coverage.status = FamilyStatus.SKIPPED
            coverage.reason = "runtime replay requires at least two identities"
            return [], coverage

        ctx = context if context is not None else {}
        discovered = ctx.get("discovered") or {}
        request_index: dict[tuple[str, str], dict[str, str]] = {}
        for payload in discovered.values():
            for item in payload.get("requests", []):
                method = str(item.get("method", "GET")).upper()
                url = str(item.get("url", ""))
                if method in {"GET", "HEAD"} and url:
                    request_index[(method, url)] = item
        if not request_index:
            coverage.status = FamilyStatus.SKIPPED
            coverage.reason = "browser discovery produced no replayable GET/HEAD requests"
            return [], coverage

        guard = ScopeGuard(tuple(target["allow_hosts"]))
        replay = ReplayTransport(guard, timeout=float(target.get("limits", {}).get("timeout_seconds", 10)))
        configured_budget = int(target.get("limits", {}).get("request_budget", 250))
        remaining = int(ctx.setdefault("request_budget_remaining", configured_budget))
        findings: list[Finding] = []
        seen_authz: set[tuple[str, str]] = set()
        comparisons_completed = 0
        try:
            for identity_a, identity_b in combinations(selected, 2):
                for (method, url), item in sorted(request_index.items()):
                    if remaining < 2:
                        coverage.status = FamilyStatus.FAILED
                        coverage.reason = "request budget exhausted before runtime replay completed"
                        coverage.findings = len(findings)
                        coverage.metadata.update({
                            "replayable_requests": len(request_index),
                            "comparisons_completed": comparisons_completed,
                            "request_budget_remaining": remaining,
                        })
                        ctx["request_budget_remaining"] = remaining
                        return findings, coverage
                    diff = await replay.compare(
                        CapturedRequest(method=method, url=url, headers={}),
                        identity_a,
                        identity_b,
                    )
                    remaining -= 2
                    comparisons_completed += 1

                    if "/admin" in (urlsplit(url).path or "").lower():
                        for identity, fp in ((identity_a, diff.a), (identity_b, diff.b)):
                            if identity.role == "user" and 200 <= fp.status_code < 300:
                                key = (identity.name, url)
                                if key not in seen_authz:
                                    seen_authz.add(key)
                                    findings.append(Finding(
                                        tool=self.name,
                                        family=self.family,
                                        rule_id="halo.nonadmin-admin-surface-access",
                                        title="Non-admin identity reached an admin surface",
                                        severity="high",
                                        url=url,
                                        identity=identity.name,
                                        confidence=90,
                                        evidence_grade="differential",
                                        evidence={
                                            "method": method,
                                            "status": fp.status_code,
                                            "identity_role": identity.role,
                                            "comparison": f"captured/replayed across {identity_a.name} and {identity_b.name}",
                                        },
                                    ))

                    if not diff.different:
                        continue
                    findings.append(Finding(
                        tool=self.name,
                        family=self.family,
                        rule_id="halo.identity-response-differential",
                        title="Response differs across identities",
                        severity="medium",
                        url=url,
                        identity=identity_a.name,
                        compared_identity=identity_b.name,
                        confidence=70,
                        evidence_grade="differential",
                        evidence={
                            "method": method,
                            "identity_a": {
                                "name": identity_a.name,
                                "role": identity_a.role,
                                "status": diff.a.status_code,
                                "body_length": diff.a.body_length,
                                "content_type": diff.a.content_type,
                                "json_shape": diff.a.json_shape,
                            },
                            "identity_b": {
                                "name": identity_b.name,
                                "role": identity_b.role,
                                "status": diff.b.status_code,
                                "body_length": diff.b.body_length,
                                "content_type": diff.b.content_type,
                                "json_shape": diff.b.json_shape,
                            },
                        },
                    ))
            coverage.tools_executed = 1
            coverage.findings = len(findings)
            coverage.metadata.update({
                "replayable_requests": len(request_index),
                "comparisons_completed": comparisons_completed,
                "request_budget_remaining": remaining,
            })
            ctx["request_budget_remaining"] = remaining
        except TimeoutError as exc:
            coverage.status = FamilyStatus.TIMEOUT
            coverage.reason = str(exc)
            ctx["request_budget_remaining"] = remaining
        except Exception as exc:
            coverage.status = FamilyStatus.FAILED
            coverage.reason = f"{type(exc).__name__}: {exc}"
            ctx["request_budget_remaining"] = remaining
        return findings, coverage
