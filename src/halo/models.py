from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class FamilyStatus(StrEnum):
    RAN = "RAN"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


@dataclass(frozen=True)
class Identity:
    name: str
    role: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

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

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data
