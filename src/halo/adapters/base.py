from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..identity import IdentityVault
from ..models import CoverageRecord, FamilyStatus, Finding, Identity


@dataclass
class AdapterRun:
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class IdentityAwareAdapter(ABC):
    """Base contract for every DAST/API adapter.

    Adapters do not choose a privileged singleton identity. The runner expands
    the selected identity set and records which identities were actually used.
    """

    name = "base"
    family = "unknown"

    @abstractmethod
    async def run_one(self, target: dict[str, Any], identity: Identity, context: dict[str, Any]) -> AdapterRun:
        raise NotImplementedError

    async def run_for_identities(
        self,
        target_name: str,
        target: dict[str, Any],
        vault: IdentityVault,
        *,
        identities: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> tuple[list[Finding], CoverageRecord]:
        selected = vault.selected(identities)
        coverage = CoverageRecord(
            target=target_name,
            family=self.family,
            status=FamilyStatus.RAN,
            tools_expected=1,
            identities_attempted=[item.name for item in selected],
        )
        findings: list[Finding] = []
        try:
            for identity in selected:
                result = await self.run_one(target, identity, context or {})
                findings.extend(result.findings)
            coverage.tools_executed = 1
            coverage.findings = len(findings)
        except TimeoutError as exc:
            coverage.status = FamilyStatus.TIMEOUT
            coverage.reason = str(exc)
        except Exception as exc:
            coverage.status = FamilyStatus.FAILED
            coverage.reason = f"{type(exc).__name__}: {exc}"
        return findings, coverage
