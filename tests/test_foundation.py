from __future__ import annotations

from pathlib import Path

import pytest

from halo.adapters.replay_runtime import ReplayRuntimeAdapter
from halo.identity import IdentityVault
from halo.input_gate import evaluate_family_input
from halo.models import FamilyStatus, Identity
from halo.replay import SAFE_METHODS
from halo.scope import ScopeGuard


def test_scope_rejects_global_wildcard():
    with pytest.raises(ValueError):
        ScopeGuard(["*"])


def test_scope_wildcard_excludes_apex():
    guard = ScopeGuard(["*.example.test"])
    assert guard.allows_host("a.example.test")
    assert not guard.allows_host("example.test")


def test_identity_vault_resolves_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HALO_USER_TOKEN", "synthetic-user-token")
    path = tmp_path / "identities.yml"
    path.write_text(
        "schema_version: 1\nidentities:\n  user:\n    bearer_token: ${HALO_USER_TOKEN}\n",
        encoding="utf-8",
    )
    vault = IdentityVault.from_file(path)
    assert vault.names() == ["anonymous", "user"]
    assert vault.get("user").headers["Authorization"] == "Bearer synthetic-user-token"


def test_identity_vault_fails_closed_when_secret_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("HALO_MISSING_TOKEN", raising=False)
    path = tmp_path / "identities.yml"
    path.write_text(
        "schema_version: 1\nidentities:\n  user:\n    bearer_token: ${HALO_MISSING_TOKEN}\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="HALO_MISSING_TOKEN"):
        IdentityVault.from_file(path)


def test_api_contract_missing_is_skipped(tmp_path: Path):
    gate = evaluate_family_input("api-contract", {}, tmp_path)
    assert gate.status is FamilyStatus.SKIPPED
    assert "openapi" in gate.reason


def test_graphql_missing_is_skipped(tmp_path: Path):
    gate = evaluate_family_input("graphql-schema", {}, tmp_path)
    assert gate.status is FamilyStatus.SKIPPED
    assert "graphql_schema" in gate.reason


def test_container_missing_is_skipped(tmp_path: Path):
    gate = evaluate_family_input("container", {}, tmp_path)
    assert gate.status is FamilyStatus.SKIPPED


def test_iac_missing_is_skipped(tmp_path: Path):
    gate = evaluate_family_input("iac", {"iac_globs": ["infra/**/*.tf"]}, tmp_path)
    assert gate.status is FamilyStatus.SKIPPED


def test_replay_transport_is_safe_method_only():
    assert SAFE_METHODS == frozenset({"GET", "HEAD"})


@pytest.mark.asyncio
async def test_replay_budget_exhaustion_is_explicit_and_sends_no_request():
    vault = IdentityVault({
        "anonymous": Identity("anonymous"),
        "user": Identity("user", headers={"Authorization": "Bearer synthetic"}),
    })
    target = {
        "allow_hosts": ["example.test"],
        "limits": {"request_budget": 10, "timeout_seconds": 1},
    }
    context = {
        "request_budget_remaining": 1,
        "discovered": {
            "anonymous": {
                "requests": [{"method": "GET", "url": "https://example.test/api/me"}]
            }
        },
    }
    findings, coverage = await ReplayRuntimeAdapter().run_for_identities(
        "demo", target, vault, context=context
    )
    assert findings == []
    assert coverage.status is FamilyStatus.FAILED
    assert "request budget exhausted" in coverage.reason
    assert context["request_budget_remaining"] == 1
