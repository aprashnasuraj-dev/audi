from __future__ import annotations

from .models import CoverageRecord, FamilyStatus, ResultAccounting


PARITY_REQUIRED_FAMILIES = frozenset({
    "runtime-verification",
    "web-hardening",
    "api-contract",
    "graphql-schema",
    "container",
    "iac",
})


def finalize_accounting(coverage: CoverageRecord, accounting: ResultAccounting) -> CoverageRecord:
    """Attach result accounting and fail closed on loss/parse errors."""
    coverage.accounting = accounting
    if coverage.status is FamilyStatus.RAN and not accounting.parity_ok:
        coverage.status = FamilyStatus.FAILED
        coverage.reason = (
            "result-accounting parity failure: "
            f"raw={accounting.raw_result_count} normalized={accounting.normalized_count} "
            f"excluded={accounting.excluded_count} parse_errors={accounting.parse_error_count}"
        )
        coverage.tools_executed = 0
    return coverage


def merge_accounting(parts: list[ResultAccounting]) -> ResultAccounting:
    merged = ResultAccounting()
    for part in parts:
        merged = merged.merge(part)
    return merged


def scanner_exit_completed(tool: str, exit_code: int, *, mode: str = "json") -> bool:
    """Tool-specific process semantics; result presence is not execution failure."""
    key = (tool.strip().lower(), mode.strip().lower())
    completed = {
        ("bandit", "json"): {0, 1},
        ("trivy", "json"): {0},
    }.get(key, {0})
    return exit_code in completed
