from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import FamilyStatus


@dataclass(frozen=True)
class GateResult:
    status: FamilyStatus
    reason: str
    value: Any = None


_REQUIRED_KEYS = {
    "api-contract": "openapi",
    "graphql-schema": "graphql_schema",
    "container": "container_image",
}


def evaluate_family_input(family: str, target: dict[str, Any], repo_root: Path) -> GateResult:
    """Return RAN-ready or explicit SKIPPED; missing inputs are never PASS."""
    if family in _REQUIRED_KEYS:
        key = _REQUIRED_KEYS[family]
        value = target.get(key)
        if not value:
            return GateResult(FamilyStatus.SKIPPED, f"required input {key!r} is absent")
        if family != "container":
            path = (repo_root / str(value)).resolve()
            try:
                path.relative_to(repo_root.resolve())
            except ValueError:
                return GateResult(FamilyStatus.SKIPPED, f"{key} resolves outside repository")
            if not path.is_file():
                return GateResult(FamilyStatus.SKIPPED, f"required file does not exist: {value}")
            return GateResult(FamilyStatus.RAN, "input available", str(path))
        return GateResult(FamilyStatus.RAN, "container image declared", str(value))

    if family == "iac":
        patterns = target.get("iac_globs") or ["**/*.tf", "**/*.yaml", "**/*.yml"]
        matches: list[str] = []
        for pattern in patterns:
            for path in repo_root.glob(str(pattern)):
                if path.is_file() and ".git" not in path.parts:
                    matches.append(str(path))
        if not matches:
            return GateResult(FamilyStatus.SKIPPED, "no IaC files matched configured patterns")
        return GateResult(FamilyStatus.RAN, "IaC files available", sorted(set(matches)))

    return GateResult(FamilyStatus.RAN, "no additional family input required")
