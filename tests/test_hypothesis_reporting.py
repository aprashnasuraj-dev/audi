from __future__ import annotations

import json
from pathlib import Path

import pytest

from halo.hypothesis import ReproductionVerifier, compose_chains, enrich_threat_model
from halo.identity import IdentityVault
from halo.mock_target import mock_server
from halo.models import CoverageRecord, FamilyStatus, Finding, Identity
from halo.orchestrator import TargetRun
from halo.reporting.bundle import write_bundle


def _finding(**overrides) -> Finding:
    data = dict(
        tool="identity-replay",
        family="runtime-verification",
        rule_id="halo.nonadmin-admin-surface-access",
        title="Non-admin identity reached an admin surface",
        severity="high",
        url="http://127.0.0.1/api/admin/secret",
        identity="user",
        evidence={"method": "GET"},
        confidence=90,
        evidence_grade="differential",
    )
    data.update(overrides)
    return Finding(**data)


def test_threat_enrichment_preserves_severity():
    finding = _finding()
    enriched = enrich_threat_model([finding])[0]
    assert enriched.severity == "high"
    assert enriched.evidence["threat_model"]["threat"] == "authorization"


def test_chain_composer_is_hypothesis_only():
    findings = [_finding(rule_id="a"), _finding(rule_id="b")]
    chains = compose_chains(findings)
    assert len(chains) == 1
    assert chains[0]["status"] == "hypothesis"
    assert chains[0]["finding_rules"] == ["a", "b"]


@pytest.mark.asyncio
async def test_reproduction_verifier_retests_seeded_candidate():
    with mock_server() as seed:
        target = {"url": seed, "allow_hosts": ["127.0.0.1"], "limits": {"timeout_seconds": 5}}
        vault = IdentityVault({
            "anonymous": Identity("anonymous"),
            "user": Identity("user", headers={"Authorization": "Bearer user-token"}),
        })
        finding = _finding(url=seed.rstrip("/") + "/api/admin/secret")
        verifier = ReproductionVerifier(target, vault)
        assert await verifier.verify(finding) is True


def test_report_bundle_emits_all_phase4_formats(tmp_path: Path):
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "pyproject.toml").write_text(
        '[project]\nname="demo"\ndependencies=["httpx>=0.27"]\n', encoding="utf-8"
    )
    run = TargetRun(
        target="mock-local",
        findings=[_finding()],
        coverage=[
            CoverageRecord("mock-local", "runtime-verification", FamilyStatus.RAN, tools_executed=1, findings=1),
            CoverageRecord("mock-local", "api-contract", FamilyStatus.SKIPPED, reason="required input 'openapi' is absent"),
        ],
    )
    paths = write_bundle([run], tmp_path / "out", repo_root)
    assert set(paths) == {"json", "markdown", "html", "pdf", "sarif", "sbom", "vex"}
    assert all(path.exists() for path in paths.values())
    report = paths["markdown"].read_text(encoding="utf-8")
    assert "runtime-verification`: **RAN**" in report
    assert "api-contract`: **SKIPPED**" in report
    sarif = json.loads(paths["sarif"].read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"][0]["properties"]["identity"] == "user"
