#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urlparse

import yaml


def fail(message: str) -> None:
    raise SystemExit(f"POLICY BLOCK: {message}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate Minly VDP adaptive audit policy")
    parser.add_argument(
        "--profile",
        default="programs/minly-vdp/adaptive-audit-profile.yml",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    profile_path = Path(args.profile)
    data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))

    if data.get("program") != "Minly VDP":
        fail("unexpected program")

    scope = data.get("scope") or {}
    origins = scope.get("exact_web_origins") or []
    if origins != ["https://minly.com/"]:
        fail(f"web scope must be exactly https://minly.com/: {origins!r}")
    if scope.get("wildcard_hosts_allowed") is not False:
        fail("wildcard hosts must remain disabled")
    if scope.get("third_party_testing_allowed") is not False:
        fail("third-party testing must remain disabled")

    parsed = urlparse(origins[0])
    if parsed.scheme != "https" or parsed.hostname != "minly.com":
        fail("invalid exact origin")

    modes = {item["name"]: item for item in data.get("research_modes") or []}
    required_modes = {
        "public_surface",
        "own_account_manual",
        "two_account_differential",
        "offline_artifact_analysis",
    }
    missing_modes = sorted(required_modes - set(modes))
    if missing_modes:
        fail(f"missing research modes: {missing_modes}")

    public = modes["public_surface"]
    if set(public.get("allowed_methods") or []) - {"GET", "HEAD"}:
        fail("public-surface mode may only use GET/HEAD")
    if int(public.get("max_requests", 0)) > 24:
        fail("public-surface request budget exceeds 24")
    if float(public.get("max_requests_per_second", 0)) > 0.4:
        fail("public-surface pacing exceeds 0.4 req/s")
    if public.get("follow_cross_host_redirects") is not False:
        fail("cross-host redirects must not be followed")
    if public.get("mutate_state") is not False:
        fail("public-surface mode must be non-mutating")

    owned = modes["own_account_manual"]
    if int(owned.get("max_requests", 0)) > 40:
        fail("own-account request budget exceeds 40")
    if float(owned.get("max_requests_per_second", 0)) > 0.5:
        fail("own-account pacing exceeds 0.5 req/s")
    if owned.get("automation") != "browser_assisted_only":
        fail("own-account automation must remain browser-assisted only")

    differential = modes["two_account_differential"]
    if differential.get("object_enumeration") is not False:
        fail("two-account mode must not enumerate object IDs")
    if differential.get("mutate_only_owned_objects") is not True:
        fail("two-account mode may mutate only researcher-owned objects")

    risk_classes = data.get("risk_classes") or {}
    if risk_classes.get("confirmed_exploitable", {}).get("reportable") is not True:
        fail("confirmed exploitable class must remain reportable")
    for name in (
        "security_weakness",
        "latent_vulnerability",
        "attack_path_precursor",
        "security_enhancement",
    ):
        if risk_classes.get(name, {}).get("reportable") is not False:
            fail(f"{name} must not be directly reportable")

    gate = data.get("submission_gate") or {}
    for key in ("scanner_only_output", "best_practice_only", "speculative_future_risk_only"):
        if gate.get(key) != "reject":
            fail(f"submission gate must reject {key}")

    result = {
        "ready": True,
        "program": data["program"],
        "profile": data.get("profile"),
        "exact_origin": origins[0],
        "public_max_requests": public["max_requests"],
        "public_max_rps": public["max_requests_per_second"],
        "risk_classes": sorted(risk_classes),
        "priority_lenses": len(data.get("priority_lenses") or []),
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("Minly adaptive audit policy: PASS")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
