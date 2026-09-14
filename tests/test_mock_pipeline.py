from __future__ import annotations

import pytest

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
            "limits": {"max_pages": 10, "request_budget": 100, "timeout_seconds": 5},
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
        assert differentials, "cross-identity replay must detect at least one response difference"
