from __future__ import annotations

from pathlib import Path

import pytest

from halo.adapters.replay_runtime import ReplayRuntimeAdapter
from halo.identity import IdentityVault
from halo.input_gate import evaluate_family_input
from halo.live_safety import LiveSafetyController, LiveSafetyStop
from halo.models import FamilyStatus, Identity
from halo.replay import SAFE_METHODS
from halo.scope import ScopeGuard, ScopePolicy, ScopeState


def test_scope_rejects_global_wildcard():
    with pytest.raises(ValueError):
        ScopeGuard(["*"])


def test_scope_wildcard_excludes_apex():
    guard = ScopeGuard(["*.example.test"])
    assert guard.allows_host("a.example.test")
    assert not guard.allows_host("example.test")


def test_scope_transition_requires_verified_authenticated_top_level_navigation():
    policy = ScopePolicy(
        ["app.example.test"],
        deny_hosts=["blocked.example.test"],
        authenticated_flow_suffixes=["example.test"],
    )
    user = Identity("user", headers={"Authorization": "Bearer synthetic"})
    with pytest.raises(PermissionError, match="authenticated navigation proof"):
        policy.try_navigation_transition(
            "https://account.example.test/home",
            source_url="https://app.example.test/",
            identity=user,
            top_level_navigation=True,
            authentication_verified=False,
        )
    destination, state = policy.try_navigation_transition(
        "https://account.example.test/home",
        source_url="https://app.example.test/",
        identity=user,
        top_level_navigation=True,
        authentication_verified=True,
    )
    assert destination == "https://account.example.test/home"
    assert state is ScopeState.FLOW_ALLOWED
    assert policy.assert_url("https://account.example.test/api/me").startswith("https://account.example.test/")
    assert policy.provenance()[0]["identity"] == "user"

    with pytest.raises(PermissionError, match="explicitly denied"):
        policy.try_navigation_transition(
            "https://blocked.example.test/",
            source_url="https://app.example.test/",
            identity=user,
            top_level_navigation=True,
            authentication_verified=True,
        )


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


def test_identity_vault_loads_storage_state_and_auth_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state = tmp_path / "state.json"
    state.write_text('{"cookies": [], "origins": []}', encoding="utf-8")
    monkeypatch.setenv("HALO_STATE", str(state))
    path = tmp_path / "identities.yml"
    path.write_text(
        "schema_version: 1\nidentities:\n  user:\n    role: user\n    storage_state_path: ${HALO_STATE}\n"
        "    auth_check_url: https://app.example.test/me\n    auth_check_contains: signed-in\n",
        encoding="utf-8",
    )
    identity = IdentityVault.from_file(path).get("user")
    assert identity.storage_state_path == str(state.resolve())
    assert identity.auth_check_url == "https://app.example.test/me"
    assert identity.auth_check_contains == "signed-in"


def test_identity_vault_fails_closed_when_selected_secret_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("HALO_MISSING_TOKEN", raising=False)
    path = tmp_path / "identities.yml"
    path.write_text(
        "schema_version: 1\nidentities:\n  user:\n    bearer_token: ${HALO_MISSING_TOKEN}\n",
        encoding="utf-8",
    )
    vault = IdentityVault.from_file(path)
    assert "user" in vault.names()
    with pytest.raises(RuntimeError, match="HALO_MISSING_TOKEN"):
        vault.get("user")


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


def test_live_safety_treats_429_as_stop_signal():
    controller = LiveSafetyController(max_requests_per_second=5, max_retry_after_seconds=10)
    with pytest.raises(LiveSafetyStop, match="HTTP 429"):
        controller.observe_response("https://example.test/", 429, {"retry-after": "60"})


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
