from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .adapters.browser_discovery import BrowserDiscoveryAdapter
from .adapters.graphql_schema import GraphQLSchemaAdapter
from .adapters.openapi_contract import OpenAPIContractAdapter
from .adapters.replay_runtime import ReplayRuntimeAdapter
from .adapters.trivy_exec import TrivyContainerAdapter, TrivyIaCAdapter
from .adapters.web_hardening import WebHardeningAdapter
from .applicability import TechnologyProfile, family_applicability, resolve_technologies
from .canonical import CanonicalIssue, canonicalize_findings
from .hypothesis import ReproductionVerifier, compose_chains, enrich_threat_model
from .identity import IdentityVault
from .input_gate import evaluate_family_input
from .models import CoverageRecord, FamilyStatus, Finding
from .publication import PublicationDecision, evaluate_publication


OPTIONAL_INPUT_FAMILIES = ("api-contract", "graphql-schema", "container", "iac")
DISCOVERY_DEPENDENT_FAMILIES = frozenset({"api-contract", "graphql-schema"})


@dataclass
class TargetRun:
    target: str
    findings: list[Finding] = field(default_factory=list)
    canonical_issues: list[CanonicalIssue] = field(default_factory=list)
    coverage: list[CoverageRecord] = field(default_factory=list)
    chains: list[dict[str, Any]] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    technology_profile: TechnologyProfile | None = None
    publication: PublicationDecision | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "observations": [finding.to_dict() for finding in self.findings],
            "canonical_issues": [issue.to_dict() for issue in self.canonical_issues],
            "coverage": [record.to_dict() for record in self.coverage],
            "chains": self.chains,
            "discovery": self.context.get("discovered", {}),
            "scope_transitions": self.context.get("scope_transitions", []),
            "request_budget_remaining": self.context.get("request_budget_remaining"),
            "technology_profile": self.technology_profile.to_dict() if self.technology_profile else None,
            "publication": self.publication.to_dict() if self.publication else None,
        }


async def _run_optional_family(
    family: str,
    target_name: str,
    target: dict[str, Any],
    vault: IdentityVault,
    identities: list[str],
    context: dict[str, Any],
    gate_value: Any,
) -> tuple[list[Finding], CoverageRecord]:
    if family == "api-contract":
        return await OpenAPIContractAdapter().run_for_identities(target_name, target, vault, identities=identities, context=context)
    if family == "graphql-schema":
        return await GraphQLSchemaAdapter().run_for_identities(target_name, target, vault, identities=identities, context=context)
    if family == "container":
        return await TrivyContainerAdapter().run(target_name, str(gate_value))
    if family == "iac":
        return await TrivyIaCAdapter().run(target_name, [str(path) for path in gate_value])
    raise ValueError(f"unknown optional family {family!r}")


async def run_target(
    target_name: str,
    target: dict[str, Any],
    vault: IdentityVault,
    *,
    repo_root: Path,
    enable_hypothesis: bool = False,
) -> TargetRun:
    run = TargetRun(target=target_name)
    run.context["repo_root"] = str(repo_root.resolve())
    run.context["request_budget_remaining"] = int(target.get("limits", {}).get("request_budget", 250))
    run.technology_profile = resolve_technologies(repo_root, target)
    run.context["technology_profile"] = run.technology_profile.to_dict()
    identities = [str(name) for name in target.get("identities") or vault.names()]

    web_applicable, web_reason = family_applicability("browser-discovery", target, run.technology_profile)
    if not web_applicable:
        discovery_coverage = CoverageRecord(
            target=target_name,
            family="browser-discovery",
            status=FamilyStatus.SKIPPED,
            reason=f"not applicable: {web_reason}",
        )
    else:
        _, discovery_coverage = await BrowserDiscoveryAdapter().run_for_identities(
            target_name, target, vault, identities=identities, context=run.context
        )
    run.coverage.append(discovery_coverage)

    hardening_applicable, hardening_reason = family_applicability("web-hardening", target, run.technology_profile)
    if hardening_applicable:
        hardening_findings, hardening_coverage = await WebHardeningAdapter().run_for_identities(
            target_name, target, vault, identities=identities, context=run.context
        )
        run.findings.extend(hardening_findings)
    else:
        hardening_coverage = CoverageRecord(
            target=target_name,
            family="web-hardening",
            status=FamilyStatus.SKIPPED,
            reason=f"not applicable: {hardening_reason}",
        )
    run.coverage.append(hardening_coverage)

    if discovery_coverage.status is FamilyStatus.RAN:
        replay_findings, replay_coverage = await ReplayRuntimeAdapter().run_for_identities(
            target_name, target, vault, identities=identities, context=run.context
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
            continue
        applicable, reason = family_applicability(family, target, run.technology_profile)
        if not applicable:
            run.coverage.append(CoverageRecord(
                target=target_name,
                family=family,
                status=FamilyStatus.SKIPPED,
                reason=f"not applicable: {reason}",
                tools_expected=1,
            ))
            continue
        if family in DISCOVERY_DEPENDENT_FAMILIES and discovery_coverage.status is not FamilyStatus.RAN:
            run.coverage.append(CoverageRecord(
                target=target_name,
                family=family,
                status=FamilyStatus.SKIPPED,
                reason=f"browser discovery prerequisite unavailable: {discovery_coverage.status.value}",
                tools_expected=1,
            ))
            continue
        findings, coverage = await _run_optional_family(
            family, target_name, target, vault, identities, run.context, gate.value
        )
        run.findings.extend(findings)
        run.coverage.append(coverage)

    if enable_hypothesis:
        enriched = enrich_threat_model(run.findings)
        verifier = ReproductionVerifier(
            target,
            vault,
            repo_root=repo_root,
            context=run.context,
            target_name=target_name,
        )
        run.findings = await verifier.verified_only(enriched)
        run.chains = compose_chains(run.findings)
        failed = bool(verifier.errors or verifier.budget_exhausted)
        run.coverage.append(CoverageRecord(
            target=target_name,
            family="reproduction-verification",
            status=FamilyStatus.FAILED if failed else FamilyStatus.RAN,
            reason="; ".join(verifier.errors[:5]) if verifier.errors else (
                "request budget exhausted during reproduction" if verifier.budget_exhausted else ""
            ),
            tools_expected=1,
            tools_executed=0 if failed else 1,
            findings=len(run.findings),
            metadata={
                "reproduced": verifier.reproduced,
                "rejected": verifier.rejected,
                "errors": len(verifier.errors),
                "request_budget_remaining": run.context.get("request_budget_remaining"),
            },
        ))

    run.canonical_issues = canonicalize_findings(run.findings, target_name)
    run.publication = evaluate_publication(
        target,
        run.coverage,
        run.canonical_issues,
        hypothesis_enabled=enable_hypothesis,
    )
    return run
