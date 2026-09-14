#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from halo.config import load_targets
from halo.identity import IdentityVault
from halo.integrity import PARITY_REQUIRED_FAMILIES
from halo.models import FamilyStatus
from halo.orchestrator import run_target
from halo.reporting.bundle import write_bundle


REPO_ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run HALO targets with explicit coverage and publication gates.")
    parser.add_argument("--targets", type=Path, default=REPO_ROOT / "config" / "targets.yml")
    parser.add_argument("--identities", type=Path, default=REPO_ROOT / "config" / "identities.yml")
    parser.add_argument("--target", action="append", help="target name; repeatable; default is all")
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "artifacts" / "latest")
    parser.add_argument("--hypothesis", action="store_true", help="enable threat enrichment + reproduction gate")
    parser.add_argument("--phase2-gate", action="store_true", help="require the complete seeded architecture acceptance gate")
    return parser.parse_args()


async def main_async(args: argparse.Namespace) -> int:
    targets = load_targets(args.targets)
    vault = IdentityVault.from_file(args.identities)
    selected = args.target or list(targets)
    missing = sorted(set(selected) - set(targets))
    if missing:
        raise SystemExit(f"unknown target(s): {missing}")

    runs = []
    for name in selected:
        run = await run_target(
            name,
            targets[name],
            vault,
            repo_root=REPO_ROOT,
            enable_hypothesis=args.hypothesis,
        )
        runs.append(run)
        target_dir = args.output / "targets" / name
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / "run.json").write_text(json.dumps(run.to_dict(), indent=2, default=str), encoding="utf-8")

    paths = write_bundle(runs, args.output, REPO_ROOT)
    print("report bundle:")
    for kind, path in paths.items():
        print(f"  {kind}: {path}")

    if args.phase2_gate:
        if len(runs) != 1:
            print("[FAIL] Phase 2 gate requires exactly one target")
            return 2
        run = runs[0]
        authenticated = [f for f in run.findings if f.identity and f.identity != "anonymous"]
        api_urls = {
            url for payload in (run.context.get("discovered") or {}).values()
            for url in payload.get("urls", []) if "/api/" in url
        }
        replay_diffs = [f for f in run.findings if f.rule_id == "halo.identity-response-differential"]
        seeded = [f for f in run.findings if f.rule_id == "halo.nonadmin-admin-surface-access"]
        hardening = next((record for record in run.coverage if record.family == "web-hardening"), None)
        parity_records = [
            record for record in run.coverage
            if record.status is FamilyStatus.RAN and record.family in PARITY_REQUIRED_FAMILIES
        ]
        parity_ok = bool(parity_records) and all(
            record.accounting is not None and record.accounting.parity_ok
            for record in parity_records
        )
        canonical_evidence_ok = all(issue.evidence_sources for issue in run.canonical_issues)
        checks = {
            "authenticated_findings_gt_zero": bool(authenticated),
            "api_urls_discovered": bool(api_urls),
            "replay_diff_detected": bool(replay_diffs),
            "seeded_authorization_weakness_detected": bool(seeded),
            "web_hardening_ran": bool(hardening and hardening.status is FamilyStatus.RAN),
            "result_accounting_parity": parity_ok,
            "canonical_evidence_retained": canonical_evidence_ok,
            "publication_gate_passed": bool(run.publication and run.publication.passed),
        }
        print(json.dumps({"phase2": checks}, indent=2))
        if not all(checks.values()):
            return 1

    failed = [
        record for run in runs for record in run.coverage
        if record.status in {FamilyStatus.FAILED, FamilyStatus.TIMEOUT}
    ]
    publication_failed = [run for run in runs if not run.publication or not run.publication.passed]
    if failed:
        print("[FAIL] one or more families FAILED/TIMEOUT; see report coverage")
        return 1
    if publication_failed:
        print("[FAIL] publication quality gate rejected one or more targets")
        for run in publication_failed:
            print(f"  {run.target}: {run.publication.errors if run.publication else ['missing publication decision']}")
        return 1
    return 0


def main() -> int:
    return asyncio.run(main_async(parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
