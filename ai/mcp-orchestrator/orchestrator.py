#!/usr/bin/env python3
"""Scoped MCP/AI orchestration planner for the Minly VDP.

The policy here is deliberately practical: it does not treat "scanning" as
forbidden. It separates controlled, exact-scope, low-rate audit work from
uncontrolled/high-volume/off-scope automation and from scanner-only reporting.

This module plans and gates work. It never publishes live findings or commits
private evidence. CI may exercise the gate and run bounded audit families, while
researcher-owned active testing remains explicitly confirmed and evidence stays
private/sanitized.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
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

# These are categorically blocked because they are not "testing"; they cross
# privacy, credential, scope, or availability boundaries.
BLOCKED_PATTERNS = {
    "credential_attack": re.compile(r"(?i)\b(password spray|credential stuffing|otp brute|token brute|hash crack)\b"),
    "privacy_boundary": re.compile(r"(?i)\b(other users?|victim|real user|customer data|dump database|exfiltrate|scrape private)\b"),
    "destructive_or_dos": re.compile(r"(?i)\b(dos|ddos|stress test|load test|flood|delete all|drop table|wipe|destroy)\b"),
    "blind_id_enumeration": re.compile(
        r"(?i)\b(enumerate|bruteforce|brute force|spray|sweep|mass test|iterate)\b.*\b(id|object|user|account|booking|order)\b"
    ),
    "third_party_targeting": re.compile(r"(?i)\b(stripe|paypal|apple|google play|cloudfront|cdn|firebase|payment provider)\b"),
}

# These tools are allowed only as controlled scanners. The gate permits them
# when scope/limits/intent are clear; it blocks them when paired with fuzzing,
# sweeping, brute force, off-scope hosts, or missing confirmation for active use.
CONTROLLED_SCANNER_PATTERNS = {
    "httpx": re.compile(r"(?i)\bhttpx\b"),
    "katana": re.compile(r"(?i)\bkatana\b"),
    "gau": re.compile(r"(?i)\bgau\b"),
    "waybackurls": re.compile(r"(?i)\bwaybackurls\b"),
    "gf": re.compile(r"(?i)\bgf\b"),
    "nuclei_tech_detect": re.compile(r"(?i)\bnuclei\b.*\b(tech[-_ ]?detect|technology|exposure|headers?|ssl|safe|low[-_ ]?impact)\b"),
    "ffuf_bounded": re.compile(r"(?i)\bffuf\b.*\b(bounded|allowlist|wordlist[-_ ]size|rate[-_ ]limit|safe|low[-_ ]?impact)\b"),
}

UNCONTROLLED_SCANNER_PATTERNS = {
    "nuclei_unbounded": re.compile(r"(?i)\bnuclei\b(?!.*\b(tech[-_ ]?detect|technology|exposure|headers?|ssl|safe|low[-_ ]?impact)\b)"),
    "ffuf_unbounded": re.compile(r"(?i)\bffuf\b(?!.*\b(bounded|allowlist|wordlist[-_ ]size|rate[-_ ]?limit|safe|low[-_ ]?impact)\b)"),
    "fuzzing": re.compile(r"(?i)\b(fuzz|fuzzer|payload spray|wordlist all|recursive brute|clusterbomb)\b"),
    "port_or_subdomain_sweep": re.compile(r"(?i)\b(subfinder|naabu|masscan|zmap)\b"),
    "exploit_automation": re.compile(r"(?i)\b(sqlmap|xray|active-zap|zap active scan)\b"),
    "waf_evasion_as_goal": re.compile(r"(?i)\b(waf\s*evasion|waf[-_ ]?bypass|tamper payload|payload generator)\b"),
}

MODULE_KEYWORDS = {
    "mcp_ai_orchestration": ("mcp", "agent", "orchestr", "natural-language", "ai"),
    "recon": ("recon", "endpoint", "javascript", "wayback", "gf", "katana", "httpx", "gau", "nuclei"),
    "web_application_testing": ("business logic", "jwt", "graphql", "idor", "bola", "coupon", "payment", "waf"),
    "mobile_deep_dive": ("mobile", "android", "ios", "apk", "ipa", "jadx", "apktool", "mobsf", "frida", "objection"),
    "api_security_testing": ("api", "openapi", "swagger", "mass assignment", "rate limit", "bfla"),
}


@dataclass
class Decision:
    accepted: bool
    mode: str
    selected_modules: list[str]
    controlled_scanners: list[str]
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
        if host not in hosts and not host.endswith((".md", ".yml", ".yaml", ".json", ".py", ".txt")):
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
        blocked.append("own_accounts_only_policy_missing")
    if scope.get("account_policy", {}).get("access_other_user_data") != "forbidden":
        blocked.append("privacy_stop_rule_missing")
    if "high_volume_automated_scanning" not in (scope.get("prohibited_actions") or []):
        blocked.append("high_volume_scan_limit_missing")

    return {
        "exact_hosts": sorted(exact_hosts),
        "target_package": scope.get("in_scope", {}).get("android", [{}])[0].get("package"),
        "ios_app_store_id": scope.get("in_scope", {}).get("ios", [{}])[0].get("app_store_id"),
        "testing_interpretation": "own-account-only permits testing only with researcher-controlled identities; it does not mean no testing",
    }, blocked


def classify_modules(command: str) -> list[str]:
    lowered = command.lower()
    selected = [module for module, keys in MODULE_KEYWORDS.items() if any(key in lowered for key in keys)]
    return selected or ["mcp_ai_orchestration"]


def scanner_matches(command: str) -> list[str]:
    return [name for name, pattern in CONTROLLED_SCANNER_PATTERNS.items() if pattern.search(command)]


def policy_scan(command: str, *, active_requested: bool, confirmed: bool, config: dict[str, Any]) -> tuple[list[str], list[str]]:
    blocked: list[str] = []
    controlled_scanners = scanner_matches(command)

    for name, pattern in BLOCKED_PATTERNS.items():
        if pattern.search(command):
            blocked.append(f"blocked:{name}")

    for name, pattern in UNCONTROLLED_SCANNER_PATTERNS.items():
        if pattern.search(command):
            blocked.append(f"blocked_uncontrolled_scanner:{name}")

    if controlled_scanners:
        limits = config.get("global_limits", {})
        if limits.get("exact_host_only") is not True:
            blocked.append("controlled_scanner_missing_exact_host_only_limit")
        if int(limits.get("max_requests_per_second", 99)) > 1:
            blocked.append("controlled_scanner_rate_limit_too_high")
        if int(limits.get("request_budget", 9999)) > 120:
            blocked.append("controlled_scanner_request_budget_too_high")
        if bool(limits.get("no_identifier_enumeration", False)) is not True:
            blocked.append("controlled_scanner_identifier_enumeration_not_disabled")
        if active_requested and not confirmed:
            blocked.append("active_controlled_scan_requires_explicit_confirmation")
        if active_requested and os.environ.get("CI", "").lower() == "true" and not config.get("ci_controlled_scanners", {}).get("allow_execution", False):
            blocked.append("ci_active_scanner_execution_disabled_use_bounded_builtin_families")

    return controlled_scanners, blocked


def build_plan(command: str, *, active_requested: bool, confirmed: bool, config_path: Path, scope_path: Path) -> Decision:
    config = load_yaml(config_path)
    scope_raw = load_yaml(scope_path)
    scope, blocked = exact_scope_gate(command, scope_raw, config)
    controlled_scanners, policy_blocks = policy_scan(command, active_requested=active_requested, confirmed=confirmed, config=config)
    blocked.extend(policy_blocks)

    selected = classify_modules(command)
    limits = config.get("global_limits", {})
    mode = "dry_run_plan_only"
    if active_requested and confirmed and controlled_scanners and not blocked:
        mode = "controlled_active_scan_allowed"
    elif active_requested and confirmed and not blocked:
        mode = "controlled_active_test_allowed"
    elif active_requested:
        mode = "blocked_active_request"

    next_steps = [
        "Treat scanning as allowed when it is exact-host, low-rate, bounded, non-destructive, and evidence is sanitized.",
        "Use only researcher-controlled Account A and Account B for authenticated authorization testing.",
        "Do not submit scanner output alone; convert candidates into manual reproduction with concrete Minly impact.",
        "Keep live findings, raw HAR, tokens, screenshots, and unpublished report evidence outside the public repository.",
    ]
    if controlled_scanners:
        next_steps.append("Run controlled scanner modules with exact-host allowlist, request budget, delay/rate limit, and stop-on-429 controls.")
    if "recon" in selected:
        next_steps.append("Use recon helpers for naturally observed URLs, same-origin JavaScript, archived URLs, and technology detection only.")
    if "api_security_testing" in selected:
        next_steps.append("Generate BOLA/BFLA and mass-assignment matrices from owned objects or supplied contracts; do not enumerate unknown IDs.")
    if "mobile_deep_dive" in selected:
        next_steps.append("Use mobile static/dynamic output as candidate evidence until verified on a researcher-controlled account/device.")

    return Decision(
        accepted=not blocked,
        mode=mode,
        selected_modules=selected,
        controlled_scanners=controlled_scanners,
        blocked_reasons=blocked,
        scope=scope,
        limits=limits,
        next_steps=next_steps,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gate scoped Minly VDP MCP/AI module execution")
    parser.add_argument("command", help="Natural-language research instruction to classify and gate")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--scope", type=Path, default=DEFAULT_SCOPE)
    parser.add_argument("--active", action="store_true", help="Request controlled active testing or scanning")
    parser.add_argument("--confirm-active-test", action="store_true", help="Explicit human confirmation for controlled active work")
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
    # The policy verdict lives in JSON. Returning 0 lets CI inspect the decision
    # explicitly instead of hiding useful context behind a process failure.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
