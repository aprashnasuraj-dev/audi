from __future__ import annotations

import pytest

from halo.adapters.web_hardening import WebHardeningAdapter
from halo.canonical import canonicalize_findings
from halo.identity import IdentityVault
from halo.mock_target import mock_server
from halo.models import CoverageRecord, FamilyStatus, Finding, Identity, ResultAccounting
from halo.publication import evaluate_publication


@pytest.mark.asyncio
async def test_web_hardening_detects_mock_csp_gap_with_parity():
    with mock_server() as seed:
        target = {
            "url": seed,
            "allow_hosts": ["127.0.0.1"],
            "limits": {
                "max_pages": 5,
                "request_budget": 20,
                "timeout_seconds": 5,
                "max_requests_per_second": 20,
            },
        }
        vault = IdentityVault({
            "anonymous": Identity("anonymous"),
            "user": Identity("user", headers={"Authorization": "Bearer user-token"}),
        })
        context = {"request_budget_remaining": 20}
        findings, coverage = await WebHardeningAdapter().run_for_identities(
            "mock-local", target, vault, identities=["anonymous", "user"], context=context
        )
        assert coverage.status is FamilyStatus.RAN
        assert coverage.accounting is not None and coverage.accounting.parity_ok
        assert coverage.accounting.raw_result_count == coverage.accounting.normalized_count
        assert any(item.rule_id == "halo.missing-csp" for item in findings)
        assert not any(item.rule_id == "halo.missing-hsts" for item in findings)


def _passing_coverage() -> list[CoverageRecord]:
    return [
        CoverageRecord(
            "fixture",
            "browser-discovery",
            FamilyStatus.RAN,
            tools_executed=1,
            metadata={
                "per_identity": {
                    "anonymous": {
                        "identity_role": "anonymous",
                        "authentication_verified": True,
                        "scope_transitions": [],
                    }
                }
            },
        ),
        CoverageRecord(
            "fixture", "runtime-verification", FamilyStatus.RAN, tools_executed=1,
            accounting=ResultAccounting(0, 0, 0),
        ),
        CoverageRecord(
            "fixture", "web-hardening", FamilyStatus.RAN, tools_executed=1, findings=1,
            accounting=ResultAccounting(1, 1, 0),
        ),
        CoverageRecord("fixture", "reproduction-verification", FamilyStatus.RAN, tools_executed=1),
    ]


def test_publication_gate_requires_coverage_and_parity():
    observation = Finding(
        tool="fixture",
        family="web-hardening",
        rule_id="halo.missing-csp",
        title="Content-Security-Policy was not observed",
        severity="low",
        url="https://example.test/",
        identity="anonymous",
        evidence={"header": "Content-Security-Policy"},
    )
    issues = canonicalize_findings([observation], "fixture")
    coverage = _passing_coverage()
    decision = evaluate_publication({}, coverage, issues, hypothesis_enabled=True)
    assert decision.passed
    assert decision.coverage_ratio == 1.0

    coverage[2].accounting = ResultAccounting(2, 1, 0)
    rejected = evaluate_publication({}, coverage, issues, hypothesis_enabled=True)
    assert not rejected.passed
    assert any("parity" in error for error in rejected.errors)


def test_publication_rejects_stale_scope_and_unverified_authentication():
    coverage = _passing_coverage()
    target = {
        "live_target": True,
        "scope_snapshot": "2020-01-01",
        "scope_max_age_days": 30,
        "require_authenticated_identity": True,
    }
    decision = evaluate_publication(target, coverage, [], hypothesis_enabled=True)
    assert not decision.passed
    assert any("stale" in error for error in decision.errors)
    assert any("authenticated coverage" in error for error in decision.errors)


def test_publication_accepts_verified_auth_and_transition_provenance():
    coverage = _passing_coverage()
    coverage[0].metadata["per_identity"]["user"] = {
        "identity_role": "user",
        "authentication_verified": True,
        "scope_transitions": [{
            "host": "account.example.test",
            "source_url": "https://app.example.test/",
            "destination_url": "https://account.example.test/home",
            "identity": "user",
            "identity_role": "user",
            "event": "top-level-navigation",
        }],
    }
    target = {"require_authenticated_identity": True}
    decision = evaluate_publication(target, coverage, [], hypothesis_enabled=True)
    assert decision.passed
    assert decision.authenticated_identities == ["user"]
    assert decision.scope_transition_count == 1


def test_publication_accepts_truthful_public_surface_when_auth_is_optional():
    coverage = _passing_coverage()
    coverage[1] = CoverageRecord(
        "fixture",
        "runtime-verification",
        FamilyStatus.SKIPPED,
        reason="runtime differential verification requires at least two trusted identities",
        tools_expected=1,
        identities_attempted=["anonymous"],
    )
    target = {
        "authentication_mode": "optional",
        "required_families": ["browser-discovery", "web-hardening"],
    }
    decision = evaluate_publication(target, coverage, [], hypothesis_enabled=True)
    assert decision.passed, decision.errors
    assert decision.authentication_mode == "optional"
    assert decision.coverage_ratio == 1.0
    assert "runtime-verification" not in decision.required_families
    assert any("public/anonymous surface" in warning for warning in decision.warnings)
    assert any("runtime-verification skipped" in warning for warning in decision.warnings)
