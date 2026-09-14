from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date
from typing import Any

from .canonical import CanonicalIssue
from .integrity import PARITY_REQUIRED_FAMILIES
from .models import CoverageRecord, FamilyStatus


@dataclass
class PublicationDecision:
    passed: bool
    coverage_ratio: float
    required_families: list[str]
    ran_required_families: list[str]
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    authenticated_identities: list[str] = field(default_factory=list)
    scope_transition_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_publication(
    target: dict[str, Any],
    coverage: list[CoverageRecord],
    canonical_issues: list[CanonicalIssue],
    *,
    hypothesis_enabled: bool,
) -> PublicationDecision:
    by_family = {record.family: record for record in coverage}
    required = set(target.get("required_families") or [
        "browser-discovery",
        "runtime-verification",
        "web-hardening",
    ])
    if hypothesis_enabled:
        required.add("reproduction-verification")

    errors: list[str] = []
    warnings: list[str] = []

    for record in coverage:
        if record.status in {FamilyStatus.FAILED, FamilyStatus.TIMEOUT}:
            errors.append(f"{record.family} is {record.status.value}: {record.reason or 'no reason recorded'}")
        if record.status is FamilyStatus.SKIPPED and record.family not in required:
            warnings.append(f"{record.family} skipped: {record.reason or 'no reason recorded'}")
        if record.status is FamilyStatus.RAN and record.tools_expected > 0 and record.tools_executed < 1:
            errors.append(f"{record.family} reports RAN but no tool executed")
        if record.status is FamilyStatus.RAN and record.family in PARITY_REQUIRED_FAMILIES:
            if record.accounting is None:
                errors.append(f"{record.family} ran without raw/normalized/excluded accounting")
            else:
                if not record.accounting.parity_ok:
                    errors.append(
                        f"{record.family} result parity failed: "
                        f"raw={record.accounting.raw_result_count} "
                        f"normalized={record.accounting.normalized_count} "
                        f"excluded={record.accounting.excluded_count} "
                        f"parse_errors={record.accounting.parse_error_count}"
                    )
                if record.accounting.normalized_count != record.findings:
                    errors.append(
                        f"{record.family} normalized_count={record.accounting.normalized_count} "
                        f"does not match coverage findings={record.findings}"
                    )

    ran_required: list[str] = []
    for family in sorted(required):
        record = by_family.get(family)
        if record is None:
            errors.append(f"required family {family} has no coverage record")
            continue
        if record.status is not FamilyStatus.RAN:
            errors.append(f"required family {family} did not run: {record.status.value} {record.reason}".strip())
            continue
        ran_required.append(family)

    for issue in canonical_issues:
        if not issue.evidence_sources:
            errors.append(f"canonical issue {issue.canonical_id} has no retained evidence sources")

    browser = by_family.get("browser-discovery")
    authenticated_identities: list[str] = []
    scope_transitions: list[dict[str, Any]] = []
    if browser is not None:
        per_identity = browser.metadata.get("per_identity") or {}
        for name, metadata in per_identity.items():
            if (
                str(metadata.get("identity_role", "")).lower() != "anonymous"
                and bool(metadata.get("authentication_verified"))
            ):
                authenticated_identities.append(str(name))
            for transition in metadata.get("scope_transitions") or []:
                if transition not in scope_transitions:
                    scope_transitions.append(transition)

    if bool(target.get("require_authenticated_identity")) and not authenticated_identities:
        errors.append("target requires authenticated coverage but no non-anonymous identity was verified")

    for transition in scope_transitions:
        if str(transition.get("identity_role", "")).lower() == "anonymous":
            errors.append("scope transition was attributed to an anonymous identity")
        if not transition.get("source_url") or not transition.get("destination_url"):
            errors.append("scope transition is missing source/destination provenance")

    live_target = bool(target.get("live_target"))
    snapshot = target.get("scope_snapshot")
    max_age = target.get("scope_max_age_days")
    if live_target and not snapshot:
        errors.append("live target has no scope_snapshot")
    if snapshot:
        try:
            snapshot_date = date.fromisoformat(str(snapshot))
        except ValueError:
            errors.append(f"scope_snapshot is not ISO date YYYY-MM-DD: {snapshot!r}")
        else:
            age_days = (date.today() - snapshot_date).days
            if age_days < 0:
                errors.append(f"scope_snapshot {snapshot_date.isoformat()} is in the future")
            if max_age is not None and age_days > int(max_age):
                errors.append(
                    f"scope snapshot is stale: age={age_days}d exceeds scope_max_age_days={int(max_age)}"
                )

    ratio = len(ran_required) / len(required) if required else 1.0
    minimum = float(target.get("minimum_coverage_ratio", 1.0))
    if ratio < minimum:
        errors.append(f"required-family coverage ratio {ratio:.3f} is below minimum {minimum:.3f}")

    return PublicationDecision(
        passed=not errors,
        coverage_ratio=ratio,
        required_families=sorted(required),
        ran_required_families=sorted(ran_required),
        errors=errors,
        warnings=warnings,
        authenticated_identities=sorted(authenticated_identities),
        scope_transition_count=len(scope_transitions),
    )
