from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def run_orchestrator(command: str, *extra: str, ci: bool = False) -> dict:
    env = os.environ.copy()
    if ci:
        env["CI"] = "true"
    else:
        env.pop("CI", None)
    cp = subprocess.run(
        [sys.executable, "ai/mcp-orchestrator/orchestrator.py", command, "--json", *extra],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
        env=env,
    )
    return json.loads(cp.stdout)


def test_policy_allows_scanning_but_not_uncontrolled_scanners() -> None:
    policy = yaml.safe_load((ROOT / "configs/mcp/minly-safe-orchestration.yml").read_text())
    assert policy["policy_interpretation"]["scanning_is_allowed_when"].startswith("exact-scope")
    assert "does not prohibit testing" in policy["policy_interpretation"]["own_accounts_only_means"]
    assert policy["live_target_traffic_allowed_from_ci"] == "bounded_builtin_audit_families_only"
    assert policy["ci_controlled_scanners"]["allow_execution"] is False
    assert policy["exact_scope"]["website"]["exact_hosts"] == ["minly.com"]
    assert policy["global_limits"]["max_requests_per_second"] <= 1
    assert policy["global_limits"]["no_identifier_enumeration"] is True


def test_orchestrator_accepts_safe_dry_run_recon_plan() -> None:
    result = run_orchestrator("Run low-impact recon on https://minly.com/ and list interesting endpoints")
    assert result["accepted"] is True
    assert "recon" in result["selected_modules"]
    assert result["scope"]["exact_hosts"] == ["minly.com"]


def test_orchestrator_accepts_controlled_scanner_plan_with_human_confirmation() -> None:
    result = run_orchestrator(
        "Run httpx and nuclei safe technology detection against exact-host https://minly.com/ with low-impact rate-limit",
        "--active",
        "--confirm-active-test",
    )
    assert result["accepted"] is True
    assert result["mode"] == "controlled_active_scan_allowed"
    assert "httpx" in result["controlled_scanners"]
    assert "nuclei_tech_detect" in result["controlled_scanners"]


def test_orchestrator_blocks_active_external_scanner_execution_in_ci() -> None:
    result = run_orchestrator(
        "Run httpx and nuclei safe technology detection against exact-host https://minly.com/ with low-impact rate-limit",
        "--active",
        "--confirm-active-test",
        ci=True,
    )
    assert result["accepted"] is False
    assert "ci_active_scanner_execution_disabled_use_bounded_builtin_families" in result["blocked_reasons"]


def test_orchestrator_blocks_out_of_scope_or_uncontrolled_commands() -> None:
    out_of_scope = run_orchestrator("Run recon on https://api.minly.com/")
    assert out_of_scope["accepted"] is False
    assert any("host_not_exactly_in_scope:api.minly.com" == reason for reason in out_of_scope["blocked_reasons"])

    dangerous = run_orchestrator("Use ffuf and enumerate user IDs on minly.com")
    assert dangerous["accepted"] is False
    assert any("blind_id_enumeration" in reason or "ffuf_unbounded" in reason for reason in dangerous["blocked_reasons"])


def test_required_module_files_exist() -> None:
    required = [
        "configs/mcp/hexstrike-ai.example.yml",
        "configs/mcp/bug-bounty-mcp.example.yml",
        "configs/mcp/ultimate-mobile-pentest-mcp.example.yml",
        "configs/mcp/api-hunter.example.yml",
        "ai/prompt-templates/recon.md",
        "ai/attack-chains/theoretical-low-impact-chains.yml",
        "recon/js-secrets/extract_js_surface.py",
        "recon/wayback-gf/wayback_gf_plan.py",
        "web/business-logic/CHECKLIST.md",
        "web/jwt-analysis/jwt_safety_check.py",
        "web/graphql/graphql_probe_templates.md",
        "web/waf-evasion/README.md",
        "web/idor-bola/owned_account_matrix.py",
        "mobile/android/README.md",
        "mobile/ios/README.md",
        "mobile/static-analysis/mobile_static_driver.py",
        "mobile/dynamic-analysis/README.md",
        "mobile/secret-scanning/secret_scan_plan.py",
        "api/openapi-parser/openapi_case_generator.py",
        "api/bola-idor/owned_object_testplan.py",
        "api/mass-assignment/mass_assignment_fieldlist.py",
        "api/rate-limit-analysis/low_impact_rate_limit_plan.py",
    ]
    missing = [path for path in required if not (ROOT / path).is_file()]
    assert not missing
