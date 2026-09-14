from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .adapters.browser_discovery import BrowserDiscoveryAdapter
from .adapters.replay_runtime import ReplayRuntimeAdapter
from .hypothesis import ReproductionVerifier, compose_chains, enrich_threat_model
from .identity import IdentityVault
from .input_gate import evaluate_family_input
from .models import CoverageRecord, FamilyStatus, Finding


OPTIONAL_INPUT_FAMILIES = ("api-contract", "graphql-schema", "container", "iac")


@dataclass
class TargetRun:
    target: str
    findings: list[Finding] = field(default_factory=list)
    coverage: list[CoverageRecord] = field(default_factory=list)
    chains: list[dict[str, Any]] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "findings": [finding.to_dict() for finding in self.findings],
            "coverage": [record.to_dict() for record in self.coverage],
            "chains": self.chains,
            "discovery": self.context.get("discovered", {}),
        }


async def run_target(
    target_name: str,
    target: dict[str, Any],
    vault: IdentityVault,
    *,
    repo_root: Path,
    enable_hypothesis: bool = False,
) -> TargetRun:
    """Run one target through discovery, replay, gates, and optional Phase 3."""
    run = TargetRun(target=target_name)
    identities = [str(name) for name in target.get("identities") or vault.names()]

    discovery = BrowserDiscoveryAdapter()
    _, discovery_coverage = await discovery.run_for_identities(
        target_name,
        target,
        vault,
        identities=identities,
        context=run.context,
    )
    run.coverage.append(discovery_coverage)

    if discovery_coverage.status is FamilyStatus.RAN:
        replay = ReplayRuntimeAdapter()
        replay_findings, replay_coverage = await replay.run_for_identities(
            target_name,
            target,
            vault,
            identities=identities,
            context=run.context,
        )
        run.findings.extend(replay_findings)
        run.coverage.append(replay_coverage)
    else:
        run.coverage.append(CoverageRecord(
            target=target_name,
            family="runtime-verification",
            status=FamilyStatus.SKIPPED,
            reason=f"browser discovery did not run successfully: {discovery_coverage.status.value}",
            tools_expected=1,
        ))

    for family in OPTIONAL_INPUT_FAMILIES:
        gate = evaluate_family_input(family, target, repo_root)
        if gate.status is FamilyStatus.SKIPPED:
            run.coverage.append(CoverageRecord(
                target=target_name,
                family=family,
                status=FamilyStatus.SKIPPED,
                reason=gate.reason,
                tools_expected=1,
            ))
        else:
            # Input presence is not equivalent to execution. Until a family
            # executor is implemented, say FAILED loudly rather than laundering
            # "nothing ran" into PASS/RAN.
            run.coverage.append(CoverageRecord(
                target=target_name,
                family=family,
                status=FamilyStatus.FAILED,
                reason="required input is present but this family executor is not implemented yet",
                tools_expected=1,
            ))

    if enable_hypothesis:
        enriched = enrich_threat_model(run.findings)
        verifier = ReproductionVerifier(target, vault)
        run.findings = await verifier.verified_only(enriched)
        run.chains = compose_chains(run.findings)

    return run
