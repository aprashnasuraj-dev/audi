#!/usr/bin/env python3
"""Safe MCP/AI orchestration planner for the Minly VDP.

This module intentionally produces an auditable plan. It does not connect to
external MCP servers, does not run scanners, and does not send attack payloads.
Active testing requires a human to run a separate approved command after scope
and stop conditions are confirmed.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import yaml
except Exception:  # pragma: no cover - CI installs PyYAML before using this.
    yaml = None  # type: ignore[assignment]

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = REPO_ROOT / "configs" / "mcp" / "minly-safe-orchestration.yml"
DEFAULT_SCOPE = REPO_ROOT / "programs" / "minly-vdp" / "scope.yml"

DANGEROUS_PATTERNS = {
    "waf_evasion": re.compile(r"(?i)\b(waf\s*evasion|waf[-_ ]?bypass|tamper payload|payload generator)\b"),
    "id_enumeration": re.compile(r"(?i)\b(enumerate|bruteforce|brute force|spray|sweep|mass test)\b.*\b(id|object|user|account|booking|order)\b"),
    "high_volume": re.compile(r"(?i)\b(ffuf|naabu|subfinder|nuclei|sqlmap|xray|masscan|zmap|dirbuster|dirsearch)\b"),
    "credential_attack": re.compile(r"(?i)\b(password spray|credential stuffing|otp brute|token brute|hash crack)\b"),
    "third_party": re.compile(r"(?i)\b(cdn|payment provider|apple|google play|firebase|cloudfront|stripe|paypal)\b"),
}

MODULE_KEYWORDS = {
    "mcp_ai_orchestration": ("mcp", "agent", "orchestr", "natural-language", "ai"),
    "recon": ("recon", "endpoint", "javascript", "wayback", "gf", "katana", "httpx"),
    "web_application_testing": ("business logic", "jwt", "graphql", "idor", "bola", "coupon", "payment"),
    "mobile_deep_dive": ("mobile", "android", "ios", "apk", "ipa", "jadx", "apktool", "mobsf"),
    "api_security_testing": ("api", "openapi", "swagger", "mass assignment", "rate limit", "bfla"),
}


@dataclass
class Decision:
    accepted: bool
    mode: str
    selected_modules: list[str]
    blocked_reasons: list[str]
    scope: dict[str, Any]
    limits: dict[str, Any]
    next_steps: list[str]


def load_yaml(path: Path) -> dict[str, Any]:
    if yaml is None:
        raise SystemExit("PyYAML is required for orchestrator config parsing")
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def extract_hosts(command: str) -> list[str]:
    hosts: list[str] = []
    for match in re.findall(r"https?://[^\s)>\]\"']+", command):
        parsed = urlparse(match)
        if parsed.hostname:
            hosts.append(parsed.hostname.lower())
    bare = re.findall(r"(?<![@\w.-])([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?![\w.-])", command, flags=re.I)
    for host in bare:
        host = host.lower().strip(".")
        if host not in hosts and not host.endswith((".md", ".yml", ".json", ".py")):
            hosts.append(host)
    return hosts


def exact_scope_gate(command: str, scope: dict[str, Any], config: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    web_scope = scope.get("in_scope", {}).get("website", [{}])[0]
    exact_hosts = set(web_scope.get("exact_hosts") or [])
    exact_hosts.update(config.get("exact_scope", {}).get("website", {}).get("exact_hosts") or [])
    blocked: list[str] = []

    for host in extract_hosts(command):
        if host not in exact_hosts:
            blocked.append(f"host_not_exactly_in_scope:{host}")

    if scope.get("account_policy", {}).get("own_accounts_only") is not True:
        blocked.append("own_accounts_only_not_confirmed")
    if scope.get("account_policy", {}).get("access_other_user_data") != "forbidden":
        blocked.append("privacy_stop_rule_missing")
    if "high_volume_automated_scanning" not in (scope.get("prohibited_actions") or []):
        blocked.append("high_volume_scan_exclusion_missing")

    return {"exact_hosts": sorted(exact_hosts), "target_package": scope.get("in_scope", {}).get("android", [{}])[0].get("package"), "ios_app_store_id": scope.get("in_scope", {}).get("ios", [{}])[0].get("app_store_id")}, blocked


def classify_modules(command: str) -> list[str]:
    lowered = command.lower()
    selected = [module for module, keys in MODULE_KEYWORDS.items() if any(key in lowered for key in keys)]
    return selected or ["mcp_ai_orchestration"]


def safety_scan(command: str) -> list[str]:
    reasons: list[str] = []
    for name, pattern in DANGEROUS_PATTERNS.items():
        if pattern.search(command):
            reasons.append(f"requires_manual_review_or_is_blocked:{name}")
    return reasons


def build_plan(command: str, *, active_requested: bool, confirmed: bool, config_path: Path, scope_path: Path) -> Decision:
    config = load_yaml(config_path)
    scope_raw = load_yaml(scope_path)
    scope, blocked = exact_scope_gate(command, scope_raw, config)
    blocked.extend(safety_scan(command))

    manual_required = bool(config.get("manual_confirmation_required_for_active_tests", True))
    mode = "dry_run_plan_only"
    if active_requested:
        if not confirmed or manual_required:
            blocked.append("active_execution_not_permitted_by_orchestrator_use_manual_gate")
        mode = "blocked_active_request"

    selected = classify_modules(command)
    limits = config.get("global_limits", {})
    next_steps = [
        "Confirm current VDP scope and exact asset before any manual test.",
        "Use only researcher-controlled Account A and Account B for authorization hypotheses.",
        "Prefer local artifact/HAR/OpenAPI analysis before generating any live target traffic.",
        "Keep public repository output sanitized; never commit tokens, raw HAR, screenshots, or unpublished findings.",
    ]
    if "recon" in selected:
        next_steps.append("Run recon helpers only against local artifacts or exact-host low-rate public mapping.")
    if "api_security_testing" in selected:
        next_steps.append("Generate owned-object BOLA/BFLA/mass-assignment matrices; do not enumerate IDs.")
    if "mobile_deep_dive" in selected:
        next_steps.append("Use static mobile output as candidates only; require manual device proof for impact.")

    return Decision(
        accepted=not blocked and not active_requested,
        mode=mode,
        selected_modules=selected,
        blocked_reasons=blocked,
        scope=scope,
        limits=limits,
        next_steps=next_steps,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Plan safe Minly VDP MCP/AI module execution")
    parser.add_argument("command", help="Natural-language research instruction to classify and gate")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--scope", type=Path, default=DEFAULT_SCOPE)
    parser.add_argument("--active", action="store_true", help="Request active execution; normally blocked here")
    parser.add_argument("--confirm-active-test", action="store_true", help="Human confirmation flag; still blocked in CI")
    parser.add_argument("--json", action="store_true", help="Emit JSON only")
    args = parser.parse_args(argv)

    decision = build_plan(
        args.command,
        active_requested=args.active,
        confirmed=args.confirm_active_test,
        config_path=args.config,
        scope_path=args.scope,
    )
    payload = asdict(decision)
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print("MINLY_MCP_ORCHESTRATOR_DECISION=" + json.dumps(payload, sort_keys=True))
    # The policy verdict lives in JSON. Returning 0 lets CI inspect blocked decisions
    # explicitly instead of failing before assertions can check the guardrail.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
