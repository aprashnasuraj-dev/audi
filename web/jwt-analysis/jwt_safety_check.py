#!/usr/bin/env python3
"""Local JWT structure checker.

This script decodes JWT headers/payloads without verifying or cracking secrets.
It is meant for researcher-owned tokens only and never performs online attacks.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
from typing import Any

JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$")


def b64url_decode(part: str) -> Any:
    padded = part + "=" * ((4 - len(part) % 4) % 4)
    raw = base64.urlsafe_b64decode(padded.encode())
    return json.loads(raw.decode("utf-8"))


def assess(token: str) -> dict[str, Any]:
    if not JWT_RE.match(token):
        raise ValueError("input does not look like a compact JWT")
    header, payload, _sig = token.split(".", 2)
    h = b64url_decode(header)
    p = b64url_decode(payload)
    alg = str(h.get("alg", "")).lower()
    warnings = []
    if alg == "none":
        warnings.append("alg_none_observed_manual_server_rejection_test_required")
    if alg.startswith("hs"):
        warnings.append("hmac_algorithm_observed_do_not_bruteforce_secret")
    if "kid" in h:
        warnings.append("kid_present_review_for_key_selection_confusion_only_with_safe_manual_poc")
    return {
        "policy": {"local_decode_only": True, "secret_cracking": False, "online_testing": False},
        "header": h,
        "payload_claim_names": sorted(p.keys()),
        "warnings": warnings,
        "manual_validation_required": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Decode a researcher-owned JWT and flag manual review items")
    parser.add_argument("--token", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = assess(args.token)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
