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


class VaultBoundAdapter(ABC):
    """Mandatory contract for every DAST/API adapter.

    The identity vault is part of the public run signature. An adapter that does
    not inherit this contract cannot be registered as a network-facing family.
    """

    name = "base"
    family = "unknown"

    @abstractmethod
    async def run_for_identities(
        self,
        target_name: str,
        target: dict[str, Any],
        vault: IdentityVault,
        *,
        identities: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> tuple[list[Finding], CoverageRecord]:
        raise NotImplementedError


class IdentityAwareAdapter(VaultBoundAdapter):
    """Base contract for adapters that execute once per selected identity."""

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
        shared_context = context if context is not None else {}
        per_identity: dict[str, Any] = {}
        try:
            for identity in selected:
                result = await self.run_one(target, identity, shared_context)
                findings.extend(result.findings)
                per_identity[identity.name] = result.metadata
            coverage.tools_executed = 1
            coverage.findings = len(findings)
            coverage.metadata["per_identity"] = per_identity
        except TimeoutError as exc:
            coverage.status = FamilyStatus.TIMEOUT
            coverage.reason = str(exc)
            coverage.metadata["per_identity"] = per_identity
        except Exception as exc:
            coverage.status = FamilyStatus.FAILED
            coverage.reason = f"{type(exc).__name__}: {exc}"
            coverage.metadata["per_identity"] = per_identity
        return findings, coverage
