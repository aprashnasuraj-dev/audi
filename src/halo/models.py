from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class FamilyStatus(StrEnum):
    RAN = "RAN"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


@dataclass
class ResultAccounting:
    """Loss-accounting invariant for scanner/adapter result ingestion."""

    raw_result_count: int = 0
    normalized_count: int = 0
    excluded_count: int = 0
    parse_error_count: int = 0
    exclusion_reasons: dict[str, int] = field(default_factory=dict)

    @property
    def parity_ok(self) -> bool:
        exclusion_total = sum(int(value) for value in self.exclusion_reasons.values())
        exclusions_explicit = self.excluded_count == 0 or exclusion_total == self.excluded_count
        return (
            self.parse_error_count == 0
            and self.raw_result_count == self.normalized_count + self.excluded_count
            and exclusions_explicit
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["parity_ok"] = self.parity_ok
        data["exclusion_reason_total"] = sum(int(value) for value in self.exclusion_reasons.values())
        return data

    def merge(self, other: "ResultAccounting") -> "ResultAccounting":
        reasons = dict(self.exclusion_reasons)
        for reason, count in other.exclusion_reasons.items():
            reasons[reason] = reasons.get(reason, 0) + count
        return ResultAccounting(
            raw_result_count=self.raw_result_count + other.raw_result_count,
            normalized_count=self.normalized_count + other.normalized_count,
            excluded_count=self.excluded_count + other.excluded_count,
            parse_error_count=self.parse_error_count + other.parse_error_count,
            exclusion_reasons=reasons,
        )


@dataclass(frozen=True)
class Identity:
    name: str
    role: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    storage_state_path: str | None = None
    auth_check_url: str | None = None
    auth_check_contains: str | None = None
    auth_check_selector: str | None = None

    def __post_init__(self) -> None:
        role = self.role.strip().lower()
        if not role:
            if self.name == "anonymous":
                role = "anonymous"
            elif self.name == "admin" or self.name.endswith("-admin"):
                role = "admin"
            else:
                role = "user"
        if role not in {"anonymous", "user", "admin"}:
            raise ValueError(f"unsupported identity role {role!r}")
        object.__setattr__(self, "role", role)
        if role != "anonymous" and self.storage_state_path is None and not self.headers and not self.cookies:
            # The identity can still be declared lazily, but once instantiated it
            # must carry some authentication material rather than masquerading as
            # an authenticated role.
            raise ValueError(f"authenticated identity {self.name!r} has no authentication material")


@dataclass(frozen=True)
class Finding:
    tool: str
    family: str
    rule_id: str
    title: str
    severity: str
    url: str
    identity: str | None = None
    compared_identity: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: int = 100
    evidence_grade: str = "direct"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CoverageRecord:
    target: str
    family: str
    status: FamilyStatus
    reason: str = ""
    tools_expected: int = 1
    tools_executed: int = 0
    identities_attempted: list[str] = field(default_factory=list)
    findings: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    accounting: ResultAccounting | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["accounting"] = self.accounting.to_dict() if self.accounting else None
        return data
