from __future__ import annotations

from dataclasses import replace
from typing import Any
from urllib.parse import urlsplit

from .identity import IdentityVault
from .models import Finding
from .replay import CapturedRequest, ReplayTransport
from .scope import ScopeGuard


def enrich_threat_model(findings: list[Finding]) -> list[Finding]:
    """Attach a compact threat-model interpretation without changing severity."""
    enriched: list[Finding] = []
    for finding in findings:
        evidence = dict(finding.evidence)
        if "auth" in finding.rule_id or "identity" in finding.rule_id:
            threat = "authorization"
            asset = "authenticated application data"
        elif "secret" in finding.rule_id:
            threat = "information-disclosure"
            asset = "confidential data"
        else:
            threat = "application-surface"
            asset = "web application"
        evidence["threat_model"] = {
            "threat": threat,
            "asset": asset,
            "entry_point": urlsplit(finding.url).path or "/",
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
    """Re-test candidate replay findings before report admission."""

    def __init__(self, target: dict[str, Any], vault: IdentityVault):
        self.target = target
        self.vault = vault
        self.replay = ReplayTransport(
            ScopeGuard(tuple(target["allow_hosts"])),
            timeout=float(target.get("limits", {}).get("timeout_seconds", 10)),
        )

    async def verify(self, finding: Finding) -> bool:
        method = str(finding.evidence.get("method", "GET")).upper()
        request = CapturedRequest(method=method, url=finding.url, headers={})

        if finding.rule_id == "halo.nonadmin-admin-surface-access":
            identity = self.vault.get(str(finding.identity))
            # Compare to anonymous so the request is exercised twice and the
            # authenticated 2xx must still reproduce.
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

        # Unknown finding types require a dedicated verifier before entering a
        # report. Failing closed prevents "candidate" from becoming "reported".
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
