from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .base import VaultBoundAdapter
from ..identity import IdentityVault
from ..integrity import finalize_accounting
from ..models import CoverageRecord, FamilyStatus, Finding, ResultAccounting

_FIELD = re.compile(r"^\s*([_A-Za-z][_0-9A-Za-z]*)\s*(?:\([^)]*\))?\s*:", re.M)
_TYPE_BLOCK = re.compile(r"type\s+(Query|Mutation)\s*\{(.*?)\}", re.S)
_OPERATION = re.compile(r"\b(?:query|mutation)\s+([_A-Za-z][_0-9A-Za-z]*)")
_ROOT_FIELD = re.compile(r"\{\s*([_A-Za-z][_0-9A-Za-z]*)")


def _schema_roots(text: str) -> set[str]:
    roots: set[str] = set()
    for _kind, body in _TYPE_BLOCK.findall(text):
        roots.update(_FIELD.findall(body))
    return roots


def _observed_operation(url: str) -> str | None:
    query = parse_qs(urlsplit(url).query).get("query", [])
    if not query:
        return None
    text = query[0]
    match = _OPERATION.search(text)
    if match:
        return match.group(1)
    match = _ROOT_FIELD.search(text)
    return match.group(1) if match else None


class GraphQLSchemaAdapter(VaultBoundAdapter):
    name = "graphql-schema"
    family = "graphql-schema"

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
        schema_path = (repo_root / str(target["graphql_schema"])).resolve()
        try:
            text = schema_path.read_text(encoding="utf-8")
            roots = _schema_roots(text)
            if not roots:
                raise ValueError("GraphQL schema defines no Query/Mutation root fields")
            findings: list[Finding] = []
            observed = 0
            raw_candidates = 0
            for identity in selected:
                payload = (ctx.get("discovered") or {}).get(identity.name) or {}
                for request in payload.get("requests", []):
                    url = str(request.get("url", ""))
                    path = (urlsplit(url).path or "").lower()
                    if "graphql" not in path:
                        continue
                    operation = _observed_operation(url)
                    if operation is None:
                        continue
                    observed += 1
                    if operation in roots:
                        continue
                    raw_candidates += 1
                    findings.append(Finding(
                        tool=self.name,
                        family=self.family,
                        rule_id="halo.graphql-operation-outside-schema",
                        title="Observed GraphQL operation is absent from the declared schema",
                        severity="medium",
                        url=url,
                        identity=identity.name,
                        confidence=85,
                        evidence_grade="direct",
                        evidence={
                            "method": str(request.get("method", "GET")).upper(),
                            "schema": str(target["graphql_schema"]),
                            "operation": operation,
                        },
                    ))
            coverage.tools_executed = 1
            coverage.findings = len(findings)
            coverage.metadata.update({"schema_root_fields": len(roots), "observed_get_operations": observed})
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
