#!/usr/bin/env python3
"""Generate manual API security test cases from a local OpenAPI file."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception:
    yaml = None  # type: ignore

OBJECT_HINT = re.compile(r"(?i)(id|user|account|profile|order|booking|request|message|media|wallet|payment)")
STATE_HINT = re.compile(r"(?i)(put|patch|post|delete)")


def load(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        if yaml is None:
            raise SystemExit("PyYAML required for YAML OpenAPI files")
        return yaml.safe_load(text) or {}
    return json.loads(text)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate owned-account API test cases from OpenAPI")
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    spec = load(args.spec)
    cases = []
    for path, methods in (spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for method in methods:
            method_l = method.lower()
            if method_l not in {"get", "post", "put", "patch", "delete"}:
                continue
            kind = "authorization_object_boundary" if OBJECT_HINT.search(path) else "api_consistency"
            if STATE_HINT.search(method_l):
                kind = "state_changing_authorization"
            cases.append({
                "method": method_l.upper(),
                "path": path,
                "case_type": kind,
                "execute_automatically": False,
                "manual_requirement": "Use Account A and Account B controlled objects only; do not enumerate identifiers.",
            })

    result = {"policy": {"local_spec_only": True, "no_http_requests": True, "owned_accounts_only": True}, "case_count": len(cases), "cases": cases}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"case_count": len(cases)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
