#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from halo.config import load_targets
from halo.identity import IdentityVault
from halo.preflight import preflight_target

REPO_ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fail-closed HALO live-audit preflight; performs no target traffic.")
    parser.add_argument("--targets", type=Path, default=REPO_ROOT / "config" / "targets.yml")
    parser.add_argument("--identities", type=Path, default=REPO_ROOT / "config" / "identities.yml")
    parser.add_argument("--target", action="append", help="target name; repeatable")
    parser.add_argument("--live-only", action="store_true", help="check every target marked live_target")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.target and args.live_only:
        raise SystemExit("use either --target or --live-only, not both")
    targets = load_targets(args.targets)
    vault = IdentityVault.from_file(args.identities)
    if args.live_only:
        selected = [name for name, target in targets.items() if bool(target.get("live_target"))]
    else:
        selected = args.target or list(targets)
    missing = sorted(set(selected) - set(targets))
    if missing:
        raise SystemExit(f"unknown target(s): {missing}")
    if not selected:
        raise SystemExit("no targets selected")

    results = [
        preflight_target(name, targets[name], vault, repo_root=REPO_ROOT)
        for name in selected
    ]
    if args.json:
        print(json.dumps({"ready": all(item.ready for item in results), "targets": [item.to_dict() for item in results]}, indent=2))
    else:
        for item in results:
            print(f"[{'READY' if item.ready else 'BLOCKED'}] {item.target}")
            for warning in item.warnings:
                print(f"  WARNING: {warning}")
            for error in item.errors:
                print(f"  ERROR: {error}")
        print(f"preflight: {'READY' if all(item.ready for item in results) else 'BLOCKED'}")
    return 0 if all(item.ready for item in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
