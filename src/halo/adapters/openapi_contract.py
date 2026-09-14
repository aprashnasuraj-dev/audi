from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from .base import VaultBoundAdapter
from ..identity import IdentityVault
from ..models import CoverageRecord, FamilyStatus, Finding


class OpenAPIContractAdapter(VaultBoundAdapter):
    name = "openapi-contract"
    family = "api-contract"

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
            identities_attempted=[identity.name for identity in selected],
        )
        ctx = context or {}
        repo_root = Path(ctx.get("repo_root") or ".").resolve()
        spec_path = (repo_root / str(target["openapi"])).resolve()
        try:
            spec = yaml.safe_load(spec_path.read_text(encoding="utf-8")) or {}
            paths = spec.get("paths") or {}
            if not isinstance(paths, dict):
                raise ValueError("OpenAPI 'paths' must be a mapping")
            declared = {str(path) for path in paths}
            discovered = ctx.get("discovered") or {}
            findings: list[Finding] = []
            for identity in selected:
                payload = discovered.get(identity.name) or {}
                for url in sorted(set(payload.get("urls") or [])):
                    path = urlsplit(url).path or "/"
                    if not path.startswith("/api/"):
                        continue
                    if path in declared:
                        continue
                    findings.append(Finding(
                        tool=self.name,
                        family=self.family,
                        rule_id="halo.openapi-undeclared-endpoint",
                        title="Discovered API endpoint is absent from the OpenAPI contract",
                        severity="medium",
                        url=url,
                        identity=identity.name,
                        confidence=90,
                        evidence_grade="direct",
                        evidence={"method": "GET", "spec": str(target["openapi"]), "path": path},
                    ))
            coverage.tools_executed = 1
            coverage.findings = len(findings)
            coverage.metadata["declared_paths"] = len(declared)
            return findings, coverage
        except Exception as exc:
            coverage.status = FamilyStatus.FAILED
            coverage.reason = f"{type(exc).__name__}: {exc}"
            return [], coverage
