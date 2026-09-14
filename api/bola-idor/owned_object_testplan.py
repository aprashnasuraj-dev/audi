#!/usr/bin/env python3
"""Build BOLA/IDOR test plan from a small owned-object inventory."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Create BOLA/IDOR plan without sending requests")
    parser.add_argument("--inventory", type=Path, required=True, help="JSON list of owned object labels")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    if not isinstance(inventory, list):
        raise SystemExit("inventory must be a JSON list")
    cases = []
    for item in inventory[:100]:
        cases.append({
            "object_type": item.get("object_type"),
            "location": item.get("location"),
            "owner": item.get("owner", "Account A"),
            "attacker_session": "Account B",
            "expected": "authorization denial or public-only representation",
            "active": False,
        })
    result = {"policy": {"no_enumeration": True, "no_http_requests": True, "max_inventory_items": 100}, "cases": cases}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"case_count": len(cases)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
