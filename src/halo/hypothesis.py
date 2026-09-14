from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from .adapters.graphql_schema import _schema_roots
from .adapters.trivy_exec import TrivyContainerAdapter, TrivyIaCAdapter
from .identity import IdentityVault
from .input_gate import evaluate_family_input
from .models import FamilyStatus, Finding
from .replay import CapturedRequest, ReplayTransport
from .scope import ScopeGuard


def enrich_threat_model(findings: list[Finding]) -> list[Finding]:
    """Attach a compact threat-model interpretation without changing severity."""
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
    """Link related findings by URL/identity; chains are hypotheses, not findings."""
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
    """Re-test each supported candidate before final-report admission.

    Network candidates are replayed. Contract candidates are re-read from the
    declared contract and, when safe, the observed GET/HEAD is replayed. Trivy
    candidates trigger one cached repeat scan per family and are admitted only
    when the same rule/target is produced again.
    """

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
        self.context = context or {}
        self.target_name = target_name
        self.replay = ReplayTransport(
            ScopeGuard(tuple(target["allow_hosts"])),
            timeout=float(target.get("limits", {}).get("timeout_seconds", 10)),
        )
        self._tool_reproduction_cache: dict[str, set[tuple[str, str]]] = {}

    async def _replay_status(self, finding: Finding) -> int | None:
        method = str(finding.evidence.get("method", "GET")).upper()
        if method not in {"GET", "HEAD"} or not finding.identity:
            return None
        request = CapturedRequest(method=method, url=finding.url, headers={})
        identity = self.vault.get(finding.identity)
        diff = await self.replay.compare(request, identity, identity)
        return diff.a.status_code

    async def _verify_openapi(self, finding: Finding) -> bool:
        spec_path = (self.repo_root / str(self.target.get("openapi", ""))).resolve()
        spec = yaml.safe_load(spec_path.read_text(encoding="utf-8")) or {}
        declared = set((spec.get("paths") or {}).keys())
        path = urlsplit(finding.url).path or "/"
        if path in declared:
            return False
        status = await self._replay_status(finding)
        return status is not None and status not in {404, 410}

    async def _verify_graphql(self, finding: Finding) -> bool:
        schema_path = (self.repo_root / str(self.target.get("graphql_schema", ""))).resolve()
        roots = _schema_roots(schema_path.read_text(encoding="utf-8"))
        operation = str(finding.evidence.get("operation") or "")
        if not operation or operation in roots:
            return False
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
            findings, coverage = await TrivyContainerAdapter().run(
                self.target_name, str(gate.value)
            )
        elif family == "iac":
            findings, coverage = await TrivyIaCAdapter().run(
                self.target_name, [str(path) for path in gate.value]
            )
        else:
            findings, coverage = [], None
        reproduced = set()
        if coverage is not None and coverage.status is FamilyStatus.RAN:
            reproduced = {(item.rule_id, item.url) for item in findings}
        self._tool_reproduction_cache[family] = reproduced
        return reproduced

    async def verify(self, finding: Finding) -> bool:
        method = str(finding.evidence.get("method", "GET")).upper()
        request = CapturedRequest(method=method, url=finding.url, headers={})

        if finding.rule_id == "halo.nonadmin-admin-surface-access":
            identity = self.vault.get(str(finding.identity))
            diff = await self.replay.compare(request, identity, self.vault.get("anonymous"))
            return 200 <= diff.a.status_code < 300

        if finding.rule_id == "halo.identity-response-differential":
            if not finding.identity or not finding.compared_identity:
                return False
            diff = await self.replay.compare(
                request,
                self.vault.get(finding.identity),
                self.vault.get(finding.compared_identity),
            )
            return diff.different

        if finding.rule_id == "halo.openapi-undeclared-endpoint":
            return await self._verify_openapi(finding)

        if finding.rule_id == "halo.graphql-operation-outside-schema":
            return await self._verify_graphql(finding)

        if finding.family in {"container", "iac"}:
            reproduced = await self._repeat_tool_family(finding.family)
            return (finding.rule_id, finding.url) in reproduced

        # A new finding type is not reportable until it gets a reproduction path.
        return False

    async def verified_only(self, findings: list[Finding]) -> list[Finding]:
        verified: list[Finding] = []
        for finding in findings:
            try:
                confirmed = await self.verify(finding)
            except Exception:
                confirmed = False
            if not confirmed:
                continue
            evidence = dict(finding.evidence)
            evidence["reproduction"] = {"confirmed": True}
            verified.append(replace(finding, evidence=evidence))
        return verified
