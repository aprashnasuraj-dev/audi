#!/usr/bin/env python3
"""Generate an Account A / Account B IDOR/BOLA manual matrix.

The script does not enumerate identifiers and does not send HTTP requests.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

ACTIONS = ("read", "update", "delete_or_cancel_if_reversible", "download_or_view_private_media")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build owned-account authorization review matrix")
    parser.add_argument("--objects-csv", type=Path, required=True, help="CSV with columns object_type,account_a_ref,account_b_ref,location")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    rows = []
    with args.objects_csv.open(newline="", encoding="utf-8") as fh:
        for source in csv.DictReader(fh):
            for action in ACTIONS:
                rows.append({
                    "object_type": source.get("object_type", ""),
                    "location": source.get("location", ""),
                    "action": action,
                    "source_account": "Account B",
                    "target_owned_by": "Account A",
                    "target_reference_label": "account_a_ref",
                    "send_request": False,
                    "manual_step": "Only perform manually with a single researcher-owned object if reversible and necessary.",
                    "expected": "403/404 or no private Account A data/state change for Account B",
                })

    result = {
        "policy": {"no_enumeration": True, "no_http_requests": True, "owned_accounts_only": True},
        "case_count": len(rows),
        "cases": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"case_count": len(rows)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
