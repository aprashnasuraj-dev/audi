from __future__ import annotations

import pytest

pytest.importorskip("playwright.async_api")

from halo.adapters.browser_discovery import BrowserDiscoveryAdapter
from halo.adapters.replay_runtime import ReplayRuntimeAdapter
from halo.identity import IdentityVault
from halo.mock_target import mock_server
from halo.models import FamilyStatus, Identity


@pytest.mark.asyncio
async def test_mock_target_proves_authenticated_discovery_and_replay():
    with mock_server() as seed:
        target = {
            "url": seed,
            "allow_hosts": ["127.0.0.1"],
            "limits": {
                "max_pages": 10,
                "request_budget": 100,
                "timeout_seconds": 5,
                "max_requests_per_second": 20,
            },
            "browser": {"settle_ms": 150},
        }
        vault = IdentityVault({
            "anonymous": Identity("anonymous"),
            "user": Identity("user", headers={"Authorization": "Bearer user-token"}),
            "admin": Identity("admin", headers={"Authorization": "Bearer admin-token"}),
        })
        context: dict = {}

        discovery = BrowserDiscoveryAdapter()
        _, discovery_coverage = await discovery.run_for_identities(
            "mock-local", target, vault, context=context
        )
        assert discovery_coverage.status is FamilyStatus.RAN
        assert discovery_coverage.tools_executed == 1
        assert set(context["discovered"]) == {"anonymous", "user", "admin"}

        user_urls = set(context["discovered"]["user"]["urls"])
        assert any("/api/me" in url for url in user_urls)
        assert any("/api/account/42" in url for url in user_urls)
        assert any("/api/admin/secret" in url for url in user_urls)
        assert len(user_urls) > 2, "browser discovery must reach beyond the SPA shell"

        replay = ReplayRuntimeAdapter()
        findings, replay_coverage = await replay.run_for_identities(
            "mock-local", target, vault, context=context
        )
        assert replay_coverage.status is FamilyStatus.RAN
        assert replay_coverage.metadata["replayable_requests"] >= 3
        assert findings, "authenticated/replay findings must be non-zero"

        seeded = [
            finding for finding in findings
            if finding.rule_id == "halo.nonadmin-admin-surface-access"
        ]
        assert seeded, "pipeline must detect the planted admin authorization weakness"
        assert any(finding.identity == "user" for finding in seeded)
        assert any("/api/admin/secret" in finding.url for finding in seeded)

        differentials = [
            finding for finding in findings
            if finding.rule_id == "halo.identity-response-differential"
        ]
        assert differentials, "cross-identity replay must detect at least one material response difference"


@pytest.mark.asyncio
async def test_authenticated_navigation_can_grant_exact_flow_host_but_blocks_unrelated_host():
    with mock_server() as seed:
        port = seed.rstrip("/").rsplit(":", 1)[1]
        target = {
            "url": f"{seed}?flow=1",
            "allow_hosts": ["127.0.0.1"],
            "authenticated_flow_hosts": ["localhost"],
            "deny_hosts": ["blocked.invalid", "*.blocked.invalid"],
            "require_authenticated_identity": True,
            "limits": {
                "max_pages": 5,
                "request_budget": 80,
                "timeout_seconds": 5,
                "max_requests_per_second": 20,
            },
            "browser": {"settle_ms": 250, "allow_third_party_resources": False},
        }
        user = Identity(
            "user",
            role="user",
            headers={"Authorization": "Bearer user-token"},
            auth_check_url=f"{seed}api/me",
            auth_check_contains='"user": "user"',
        )
        vault = IdentityVault({"anonymous": Identity("anonymous"), "user": user})
        context: dict = {}

        _, coverage = await BrowserDiscoveryAdapter().run_for_identities(
            "mock-flow", target, vault, identities=["user"], context=context
        )
        assert coverage.status is FamilyStatus.RAN
        user_meta = coverage.metadata["per_identity"]["user"]
        assert user_meta["authentication_verified"] is True
        assert any(item["host"] == "localhost" for item in context["scope_transitions"])
        assert any(item["identity"] == "user" for item in context["scope_transitions"])
        assert any(
            url.startswith(f"http://localhost:{port}/flow")
            for url in context["discovered"]["user"]["urls"]
        )
        assert any("blocked.invalid" in item["url"] for item in user_meta["blocked_requests"])
