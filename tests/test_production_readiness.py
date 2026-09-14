from __future__ import annotations

from datetime import date
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from halo.canonical import canonicalize_findings
from halo.identity import IdentityVault
from halo.models import Finding, Identity
from halo.preflight import preflight_target
from halo.privacy import redact_url_for_evidence, sanitize_for_report


def _live_target() -> dict:
    return {
        "url": "https://app.example.test/",
        "live_target": True,
        "scope_snapshot": date.today().isoformat(),
        "scope_max_age_days": 60,
        "allow_hosts": ["app.example.test"],
        "authenticated_flow_suffixes": ["example.test"],
        "deny_hosts": ["blocked.example.test"],
        "identities": ["anonymous", "user"],
        "require_authenticated_identity": True,
        "required_families": ["browser-discovery", "runtime-verification", "web-hardening"],
        "minimum_coverage_ratio": 1.0,
        "limits": {
            "max_pages": 25,
            "request_budget": 250,
            "timeout_seconds": 10,
            "max_requests_per_second": 2,
            "stop_on_429": True,
        },
        "browser": {"allow_third_party_resources": True},
    }


def _vault() -> IdentityVault:
    return IdentityVault({
        "anonymous": Identity("anonymous"),
        "user": Identity(
            "user",
            role="user",
            headers={"Authorization": "Bearer synthetic"},
            auth_check_url="https://app.example.test/account",
            auth_check_contains="signed in",
        ),
    })


def test_report_url_redaction_preserves_route_but_removes_oauth_values():
    safe = redact_url_for_evidence(
        "https://app.example.test/callback?code=secret-code&state=secret-state&next=%2Faccount"
    )
    parsed = urlsplit(safe)
    query = parse_qs(parsed.query)
    assert parsed.path == "/callback"
    assert query["code"] == ["<redacted>"]
    assert query["state"] == ["<redacted>"]
    assert query["next"] == ["/account"]
    assert "secret-code" not in safe
    assert "secret-state" not in safe


def test_nested_report_sanitizer_redacts_auth_headers_and_urls():
    payload = sanitize_for_report({
        "headers": {"Authorization": "Bearer top-secret", "X-Test": "ok"},
        "url": "https://example.test/?access_token=abc&view=profile",
    })
    assert payload["headers"]["Authorization"] == "<redacted>"
    assert payload["headers"]["X-Test"] == "ok"
    assert "abc" not in payload["url"]
    assert "view=profile" in payload["url"]


def test_canonical_issue_never_persists_sensitive_query_values():
    finding = Finding(
        tool="test",
        family="runtime-verification",
        rule_id="halo.test",
        title="Synthetic",
        severity="low",
        url="https://example.test/object/1?token=secret&view=full",
        evidence={"request_url": "https://example.test/object/1?token=secret"},
    )
    issue = canonicalize_findings([finding], "demo")[0]
    rendered = issue.to_dict()
    assert "secret" not in rendered["url"]
    assert "secret" not in str(rendered["evidence_sources"])


def test_live_preflight_ready_with_exact_scope_and_operational_auth(tmp_path: Path):
    result = preflight_target("demo", _live_target(), _vault(), repo_root=tmp_path)
    assert result.ready, result.errors
    assert result.authenticated_identities == ["user"]


def test_live_preflight_rejects_wildcard_seed_scope(tmp_path: Path):
    target = _live_target()
    target["allow_hosts"] = ["*.example.test"]
    result = preflight_target("demo", target, _vault(), repo_root=tmp_path)
    assert not result.ready
    assert any("must be exact" in error for error in result.errors)


def test_live_preflight_rejects_missing_authenticated_identity(tmp_path: Path):
    result = preflight_target(
        "demo",
        _live_target(),
        IdentityVault({"anonymous": Identity("anonymous")}),
        repo_root=tmp_path,
    )
    assert not result.ready
    assert any("not operational" in error for error in result.errors)
    assert any("non-anonymous" in error for error in result.errors)
