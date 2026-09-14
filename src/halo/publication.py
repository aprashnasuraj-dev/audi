from __future__ import annotations

from dataclasses import asdict, dataclass, field
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
    )
