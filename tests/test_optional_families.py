from __future__ import annotations

from pathlib import Path

import pytest

from halo.adapters.graphql_schema import GraphQLSchemaAdapter
from halo.adapters.openapi_contract import OpenAPIContractAdapter
from halo.adapters.trivy_exec import TrivyContainerAdapter, _misconfig_findings, _vulnerability_findings
from halo.identity import IdentityVault
from halo.models import FamilyStatus, Identity


def _vault() -> IdentityVault:
    return IdentityVault({
        "anonymous": Identity("anonymous"),
        "user": Identity("user", headers={"Authorization": "Bearer synthetic"}),
    })


@pytest.mark.asyncio
async def test_openapi_present_executes_and_finds_contract_drift(tmp_path: Path):
    spec = tmp_path / "openapi.yml"
    spec.write_text(
        "openapi: 3.1.0\ninfo: {title: demo, version: '1'}\npaths:\n  /api/me:\n    get: {responses: {'200': {description: ok}}}\n",
        encoding="utf-8",
    )
    target = {"openapi": "openapi.yml"}
    context = {
        "repo_root": str(tmp_path),
        "discovered": {
            "user": {
                "urls": ["https://example.test/api/me", "https://example.test/api/hidden"],
                "requests": [],
            }
        },
    }
    findings, coverage = await OpenAPIContractAdapter().run_for_identities(
        "demo", target, _vault(), identities=["user"], context=context
    )
    assert coverage.status is FamilyStatus.RAN
    assert coverage.tools_executed == 1
    assert coverage.accounting is not None and coverage.accounting.parity_ok
    assert [f.rule_id for f in findings] == ["halo.openapi-undeclared-endpoint"]
    assert findings[0].identity == "user"
    assert findings[0].url.endswith("/api/hidden")


@pytest.mark.asyncio
async def test_graphql_present_executes_and_finds_observed_operation_outside_schema(tmp_path: Path):
    schema = tmp_path / "schema.graphql"
    schema.write_text("type Query { viewer: String }\n", encoding="utf-8")
    target = {"graphql_schema": "schema.graphql"}
    context = {
        "repo_root": str(tmp_path),
        "discovered": {
            "user": {
                "urls": [],
                "requests": [{
                    "method": "GET",
                    "url": "https://example.test/graphql?query=%7BadminPanel%7D",
                    "resource_type": "fetch",
                }],
            }
        },
    }
    findings, coverage = await GraphQLSchemaAdapter().run_for_identities(
        "demo", target, _vault(), identities=["user"], context=context
    )
    assert coverage.status is FamilyStatus.RAN
    assert coverage.tools_executed == 1
    assert coverage.accounting is not None and coverage.accounting.parity_ok
    assert [f.rule_id for f in findings] == ["halo.graphql-operation-outside-schema"]
    assert findings[0].evidence["operation"] == "adminPanel"


def test_trivy_misconfiguration_parser_preserves_direct_evidence():
    findings, raw_count = _misconfig_findings({
        "Results": [{
            "Target": "infra/main.tf",
            "Misconfigurations": [{
                "ID": "AVD-TEST-1",
                "Title": "Public resource",
                "Severity": "HIGH",
                "Message": "synthetic",
            }],
        }]
    }, "iac")
    assert raw_count == 1
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].evidence_grade == "direct"


def test_trivy_vulnerability_parser_preserves_package_details():
    findings, raw_count = _vulnerability_findings({
        "Results": [{
            "Target": "demo:latest",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2099-0001",
                "PkgName": "demo-lib",
                "InstalledVersion": "1.0",
                "FixedVersion": "1.1",
                "Severity": "CRITICAL",
            }],
        }]
    }, "container")
    assert raw_count == 1
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].evidence["package"] == "demo-lib"


@pytest.mark.asyncio
async def test_present_container_input_without_trivy_is_failed(monkeypatch: pytest.MonkeyPatch):
    import halo.adapters.trivy_exec as module

    monkeypatch.setattr(module, "_trivy_binary", lambda: (_ for _ in ()).throw(RuntimeError("trivy missing")))
    findings, coverage = await TrivyContainerAdapter().run("demo", "demo:latest")
    assert findings == []
    assert coverage.status is FamilyStatus.FAILED
    assert "trivy missing" in coverage.reason
