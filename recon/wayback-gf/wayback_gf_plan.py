#!/usr/bin/env python3
"""Offline wayback/GF-style URL classifier.

This does not contact Wayback, Common Crawl, gau, or any external source.
Provide a local URL list captured separately, and it will classify paths into
safe manual review buckets.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlparse

EXACT_HOST = "minly.com"
PATTERNS = {
    "auth": re.compile(r"(?i)(login|signin|signup|register|otp|password|reset|token|session)"),
    "authorization_object": re.compile(r"(?i)(user|account|profile|order|booking|request|message|media|invoice|wallet|payment).*(id=|/\\d+|uuid|guid)"),
    "business_logic": re.compile(r"(?i)(coupon|promo|discount|price|checkout|cart|refund|subscription|entitlement)"),
    "graphql": re.compile(r"(?i)(graphql|gql)"),
    "upload_download": re.compile(r"(?i)(upload|download|file|media|attachment)"),
}


def normalize(url: str) -> tuple[str, str] | None:
    url = url.strip()
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.hostname and parsed.hostname.lower() != EXACT_HOST:
        return None
    path = parsed.path or "/"
    if parsed.query:
        keys = sorted({part.split("=", 1)[0] for part in parsed.query.split("&") if part})
        path = path + "?" + "&".join(f"{k}=<redacted>" for k in keys)
    return url, path


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify local historical URL lists into safe Minly review buckets")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    buckets: dict[str, list[dict[str, str]]] = {name: [] for name in PATTERNS}
    ignored = 0
    for line in args.input.read_text(encoding="utf-8", errors="replace").splitlines():
        item = normalize(line)
        if item is None:
            ignored += 1
            continue
        original, path = item
        for name, pattern in PATTERNS.items():
            if pattern.search(path):
                buckets[name].append({"path": path[:500], "source_sha256_12": __import__("hashlib").sha256(original.encode()).hexdigest()[:12]})

    result = {
        "policy": {
            "offline_classification_only": True,
            "exact_host": EXACT_HOST,
            "parameter_values_redacted": True,
            "manual_validation_required": True,
            "no_live_wayback_harvest_from_ci": True,
        },
        "ignored_out_of_scope_or_empty": ignored,
        "buckets": {k: v[:300] for k, v in buckets.items()},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({k: len(v) for k, v in result["buckets"].items()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
