#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit


ALLOWED_HOST = "minly.com"
OBJECT_HINTS = re.compile(
    r"(?:^|[_-])(id|uuid|order|booking|request|conversation|message|media|video|event|entitlement|user|creator|recipient|profile|token)(?:$|[_-])",
    re.IGNORECASE,
)
OPAQUE_SEGMENT = re.compile(r"^[A-Za-z0-9_-]{12,}$")
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline, privacy-preserving Minly HAR endpoint analysis.")
    parser.add_argument("har", type=Path)
    parser.add_argument("--output", type=Path, default=Path("artifacts/minly-har-analysis"))
    return parser.parse_args()


def normalize_path(path: str) -> str:
    segments = []
    for segment in (path or "/").split("/"):
        if not segment:
            continue
        if segment.isdigit() or OPAQUE_SEGMENT.fullmatch(segment):
            segments.append("{object}")
        else:
            segments.append(segment[:120])
    return "/" + "/".join(segments)


def main() -> int:
    args = parse_args()
    data = json.loads(args.har.read_text(encoding="utf-8"))
    entries = ((data.get("log") or {}).get("entries") or [])
    inventory: dict[tuple[str, str], dict] = {}
    third_party_hosts: Counter[str] = Counter()

    for entry in entries:
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        method = str(request.get("method") or "GET").upper()
        raw_url = str(request.get("url") or "")
        try:
            parts = urlsplit(raw_url)
        except Exception:
            continue
        host = (parts.hostname or "").lower().rstrip(".")
        if not host:
            continue
        if host != ALLOWED_HOST:
            third_party_hosts[host] += 1
            continue

        path = normalize_path(parts.path)
        query_names = sorted({name[:120] for name, _ in parse_qsl(parts.query, keep_blank_values=True)})
        key = (method, path)
        item = inventory.setdefault(
            key,
            {
                "method": method,
                "path_pattern": path,
                "query_parameter_names": set(),
                "statuses": set(),
                "content_types": set(),
                "seen": 0,
            },
        )
        item["seen"] += 1
        item["query_parameter_names"].update(query_names)
        status = response.get("status")
        if isinstance(status, int):
            item["statuses"].add(status)
        mime = str(((response.get("content") or {}).get("mimeType") or "")).split(";", 1)[0].strip()
        if mime:
            item["content_types"].add(mime[:120])

    rows = []
    for item in inventory.values():
        query_names = sorted(item["query_parameter_names"])
        hints = sorted({name for name in query_names if OBJECT_HINTS.search(name)})
        object_path = "{object}" in item["path_pattern"]
        state_changing = item["method"] in STATE_CHANGING
        score = (3 if object_path else 0) + (2 if hints else 0) + (2 if state_changing else 0)
        rows.append(
            {
                "method": item["method"],
                "path_pattern": item["path_pattern"],
                "query_parameter_names": query_names,
                "status_codes": sorted(item["statuses"]),
                "content_types": sorted(item["content_types"]),
                "seen": item["seen"],
                "authorization_candidate": bool(object_path or hints),
                "state_changing": state_changing,
                "candidate_score": score,
                "object_hint_parameters": hints,
            }
        )
    rows.sort(key=lambda row: (-row["candidate_score"], row["path_pattern"], row["method"]))

    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    payload = {
        "scope_host": ALLOWED_HOST,
        "request_values_retained": False,
        "headers_retained": False,
        "bodies_retained": False,
        "endpoints": rows,
        "third_party_hosts_observed_not_tested": [
            {"host": host, "request_count": count} for host, count in third_party_hosts.most_common()
        ],
    }
    (out / "endpoint-inventory.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = [
        "# Minly HAR Candidate Map",
        "",
        "Offline analysis only. Values, bodies, cookies, and headers are intentionally omitted.",
        "",
        "## Priority authorization candidates",
        "",
        "| Score | Method | Path pattern | Object hints | State-changing |",
        "|---:|---|---|---|---|",
    ]
    candidates = [row for row in rows if row["candidate_score"] > 0]
    for row in candidates:
        hints = ", ".join(row["object_hint_parameters"]) or ("path object" if "{object}" in row["path_pattern"] else "-")
        lines.append(
            f"| {row['candidate_score']} | {row['method']} | `{row['path_pattern']}` | {hints} | {'yes' if row['state_changing'] else 'no'} |"
        )
    if not candidates:
        lines.append("| 0 | - | No authorization candidates identified from this capture | - | - |")
    lines.extend(
        [
            "",
            "State-changing candidates are for manual review only; this script never replays them.",
            "Third-party hosts are inventory-only and must not be actively tested.",
        ]
    )
    (out / "candidate-map.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"endpoints": len(rows), "candidates": len(candidates), "third_party_hosts": len(third_party_hosts)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
