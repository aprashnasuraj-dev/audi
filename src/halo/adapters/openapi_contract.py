from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from .base import VaultBoundAdapter
from ..identity import IdentityVault
from ..integrity import finalize_accounting
from ..models import CoverageRecord, FamilyStatus, Finding, ResultAccounting

_HTTP_METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})


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
            declared_methods: dict[str, set[str]] = {}
            for path, payload in paths.items():
                methods = set()
                if isinstance(payload, dict):
                    methods = {
                        str(key).lower() for key in payload
                        if str(key).lower() in _HTTP_METHODS
                    }
                declared_methods[str(path)] = methods

            discovered = ctx.get("discovered") or {}
            findings: list[Finding] = []
            raw_candidates = 0
            seen: set[tuple[str, str, str, str]] = set()

            for identity in selected:
                payload = discovered.get(identity.name) or {}
                observations: list[tuple[str, str]] = []
                request_urls: set[str] = set()
                for request in payload.get("requests", []):
                    url = str(request.get("url", ""))
                    method = str(request.get("method", "GET")).upper()
                    if url:
                        observations.append((method, url))
                        request_urls.add(url)
                for url in payload.get("urls") or []:
                    text = str(url)
                    if text and text not in request_urls:
                        observations.append(("GET", text))

                for method, url in observations:
                    path = urlsplit(url).path or "/"
                    if not path.startswith("/api/"):
                        continue
                    if path not in declared_methods:
                        key = (identity.name, "endpoint", method, url)
                        if key in seen:
                            continue
                        seen.add(key)
                        raw_candidates += 1
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
                            evidence={
                                "method": method,
                                "spec": str(target["openapi"]),
                                "path": path,
                                "captured_request": True,
                            },
                        ))
                        continue

                    normalized_method = method.lower()
                    allowed = declared_methods[path]
                    if normalized_method == "options":
                        continue
                    if normalized_method == "head" and "get" in allowed:
                        continue
                    if normalized_method not in allowed:
                        key = (identity.name, "method", method, url)
                        if key in seen:
                            continue
                        seen.add(key)
                        raw_candidates += 1
                        findings.append(Finding(
                            tool=self.name,
                            family=self.family,
                            rule_id="halo.openapi-undeclared-method",
                            title="Observed API method is absent from the OpenAPI contract",
                            severity="low",
                            url=url,
                            identity=identity.name,
                            confidence=90,
                            evidence_grade="direct",
                            evidence={
                                "method": method,
                                "declared_methods": sorted(value.upper() for value in allowed),
                                "spec": str(target["openapi"]),
                                "path": path,
                                "captured_request": True,
                            },
                        ))

            coverage.tools_executed = 1
            coverage.findings = len(findings)
            coverage.metadata.update({
                "declared_paths": len(declared_methods),
                "declared_operations": sum(len(value) for value in declared_methods.values()),
            })
            finalize_accounting(coverage, ResultAccounting(
                raw_result_count=raw_candidates,
                normalized_count=len(findings),
                excluded_count=0,
            ))
            return findings, coverage
        except Exception as exc:
            coverage.status = FamilyStatus.FAILED
            coverage.reason = f"{type(exc).__name__}: {exc}"
            return [], coverage
