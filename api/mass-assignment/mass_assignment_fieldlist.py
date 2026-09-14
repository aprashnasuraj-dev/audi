#!/usr/bin/env python3
"""Generate a mass-assignment field review list from local JSON samples."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SENSITIVE_FIELD = re.compile(r"(?i)(role|admin|is_|owner|user_id|account_id|price|amount|discount|status|verified|permission|balance|credit|entitlement)")


def flatten(obj: Any, prefix: str = "") -> set[str]:
    fields: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            name = f"{prefix}.{k}" if prefix else str(k)
            fields.add(name)
            fields.update(flatten(v, name))
    elif isinstance(obj, list):
        for item in obj[:5]:
            fields.update(flatten(item, prefix + "[]"))
    return fields


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract mass-assignment review fields from local JSON samples")
    parser.add_argument("samples", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    candidates = []
    for path in args.samples:
        data = json.loads(path.read_text(encoding="utf-8"))
        for field in sorted(flatten(data)):
            if SENSITIVE_FIELD.search(field):
                candidates.append({"sample": str(path), "field": field, "manual_review": True, "do_not_send_automatically": True})

    result = {"policy": {"local_samples_only": True, "no_http_requests": True}, "field_count": len(candidates), "fields": candidates[:500]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"field_count": len(candidates)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
