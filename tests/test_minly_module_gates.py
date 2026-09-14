from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def run_orchestrator(command: str, *extra: str) -> dict:
    cp = subprocess.run(
        [sys.executable, "ai/mcp-orchestrator/orchestrator.py", command, "--json", *extra],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(cp.stdout)


def test_mcp_policy_is_manual_gated_and_exact_scope() -> None:
    policy = yaml.safe_load((ROOT / "configs/mcp/minly-safe-orchestration.yml").read_text())
    assert policy["manual_trigger_required"] is True
    assert policy["manual_confirmation_required_for_active_tests"] is True
    assert policy["live_target_traffic_allowed_from_ci"] is False
    assert policy["exact_scope"]["website"]["exact_hosts"] == ["minly.com"]
    assert policy["global_limits"]["max_requests_per_second"] <= 1
    assert policy["global_limits"]["no_identifier_enumeration"] is True


def test_orchestrator_accepts_safe_dry_run_recon_plan() -> None:
    result = run_orchestrator("Run low-impact recon on https://minly.com/ and list interesting endpoints")
    assert result["accepted"] is True
    assert "recon" in result["selected_modules"]
    assert result["scope"]["exact_hosts"] == ["minly.com"]


def test_orchestrator_blocks_out_of_scope_or_dangerous_commands() -> None:
    out_of_scope = run_orchestrator("Run recon on https://api.minly.com/")
    assert out_of_scope["accepted"] is False
    assert any("host_not_exactly_in_scope:api.minly.com" == reason for reason in out_of_scope["blocked_reasons"])

    dangerous = run_orchestrator("Use ffuf and enumerate user IDs on minly.com")
    assert dangerous["accepted"] is False
    assert any("high_volume" in reason or "id_enumeration" in reason for reason in dangerous["blocked_reasons"])


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
