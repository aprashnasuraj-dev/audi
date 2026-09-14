from __future__ import annotations

from itertools import combinations
from typing import Any

from ..identity import IdentityVault
from ..models import CoverageRecord, FamilyStatus, Finding
from ..replay import CapturedRequest, ReplayTransport
from ..scope import ScopeGuard


class ReplayRuntimeAdapter:
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

        ctx = context or {}
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
        findings: list[Finding] = []
        try:
            for identity_a, identity_b in combinations(selected, 2):
                for (method, url), item in sorted(request_index.items()):
                    diff = await replay.compare(
                        CapturedRequest(method=method, url=url, headers={}),
                        identity_a,
                        identity_b,
                    )
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
                                "status": diff.a.status_code,
                                "body_length": diff.a.body_length,
                                "content_type": diff.a.content_type,
                                "json_shape": diff.a.json_shape,
                            },
                            "identity_b": {
                                "name": identity_b.name,
                                "status": diff.b.status_code,
                                "body_length": diff.b.body_length,
                                "content_type": diff.b.content_type,
                                "json_shape": diff.b.json_shape,
                            },
                        },
                    ))
            coverage.tools_executed = 1
            coverage.findings = len(findings)
            coverage.metadata["replayable_requests"] = len(request_index)
        except TimeoutError as exc:
            coverage.status = FamilyStatus.TIMEOUT
            coverage.reason = str(exc)
        except Exception as exc:
            coverage.status = FamilyStatus.FAILED
            coverage.reason = f"{type(exc).__name__}: {exc}"
        return findings, coverage
