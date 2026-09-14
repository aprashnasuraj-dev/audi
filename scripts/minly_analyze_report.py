#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit


ALLOWED_HOST = "minly.com"
OBJECT_HINT = re.compile(
    r"(?:^|[_-])(id|uuid|order|booking|request|conversation|message|media|video|event|entitlement|user|creator|recipient|profile|token)(?:$|[_-])",
    re.IGNORECASE,
)
OPAQUE = re.compile(r"^[A-Za-z0-9_-]{12,}$")
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
EXCLUDED_FAMILIES = {"web-hardening"}
EXCLUDED_WEAKNESSES = {
    "web.missing-hsts",
    "web.missing-csp",
    "web.missing-x-frame-options",
    "web.missing-x-content-type-options",
    "web.tech-identifying-header",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a Minly VDP candidate map from a HALO report without retaining request values.")
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path, default=Path("artifacts/minly-candidates"))
    return parser.parse_args()


def path_pattern(path: str) -> str:
    parts = []
    for segment in (path or "/").split("/"):
        if not segment:
            continue
        parts.append("{object}" if segment.isdigit() or OPAQUE.fullmatch(segment) else segment[:120])
    return "/" + "/".join(parts)


def main() -> int:
    args = parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    targets = report.get("targets") or []
    if len(targets) != 1 or targets[0].get("target") != "minly-web":
        raise SystemExit("expected a single minly-web target report")
    target = targets[0]

    grouped: dict[tuple[str, str], dict] = {}
    graphql_ops: set[str] = set()
    websocket_paths: set[str] = set()
    third_party_hosts: set[str] = set()

    for payload in (target.get("discovery") or {}).values():
        for request in payload.get("requests") or []:
            raw_url = str(request.get("url") or "")
            parts = urlsplit(raw_url)
            host = (parts.hostname or "").lower().rstrip(".")
            if host != ALLOWED_HOST:
                if host:
                    third_party_hosts.add(host)
                continue
            method = str(request.get("method") or "GET").upper()
            pattern = path_pattern(parts.path)
            query_names = sorted({name[:120] for name, _ in parse_qsl(parts.query, keep_blank_values=True)})
            key = (method, pattern)
            item = grouped.setdefault(
                key,
                {
                    "method": method,
                    "path_pattern": pattern,
                    "query_parameter_names": set(),
                    "resource_types": set(),
                    "graphql_operations": set(),
                    "seen": 0,
                },
            )
            item["seen"] += 1
            item["query_parameter_names"].update(query_names)
            resource_type = request.get("resource_type")
            if resource_type:
                item["resource_types"].add(str(resource_type))
            operation = request.get("graphql_operation")
            if operation:
                item["graphql_operations"].add(str(operation))
                graphql_ops.add(str(operation))

        for raw_url in payload.get("websockets") or []:
            parts = urlsplit(str(raw_url))
            if (parts.hostname or "").lower().rstrip(".") == ALLOWED_HOST:
                websocket_paths.add(path_pattern(parts.path))

        for item in payload.get("passive_third_party_requests") or []:
            host = (urlsplit(str(item.get("url") or "")).hostname or "").lower().rstrip(".")
            if host:
                third_party_hosts.add(host)

    endpoints = []
    for item in grouped.values():
        query_names = sorted(item["query_parameter_names"])
        hints = sorted(name for name in query_names if OBJECT_HINT.search(name))
        object_path = "{object}" in item["path_pattern"]
        state_changing = item["method"] in STATE_CHANGING
        score = (4 if object_path else 0) + (3 if hints else 0) + (2 if state_changing else 0) + (2 if item["graphql_operations"] else 0)
        endpoints.append(
            {
                "method": item["method"],
                "path_pattern": item["path_pattern"],
                "query_parameter_names": query_names,
                "resource_types": sorted(item["resource_types"]),
                "graphql_operations": sorted(item["graphql_operations"]),
                "seen": item["seen"],
                "authorization_candidate": bool(object_path or hints),
                "state_changing_manual_only": state_changing,
                "candidate_score": score,
                "object_hint_parameters": hints,
            }
        )
    endpoints.sort(key=lambda row: (-row["candidate_score"], row["path_pattern"], row["method"]))

    submission_candidates = []
    excluded_program_noise = []
    for issue in target.get("canonical_issues") or []:
        families = set(issue.get("families") or [])
        weakness = str(issue.get("weakness") or "")
        if families and families.issubset(EXCLUDED_FAMILIES) or weakness in EXCLUDED_WEAKNESSES:
            excluded_program_noise.append(
                {
                    "title": issue.get("title"),
                    "weakness": weakness,
                    "reason": "Minly excludes missing/best-practice security configuration without demonstrated exploit impact",
                }
            )
            continue
        submission_candidates.append(
            {
                "title": issue.get("title"),
                "severity": issue.get("severity"),
                "url": issue.get("url"),
                "weakness": weakness,
                "confidence": issue.get("confidence"),
                "families": sorted(families),
                "human_review_required": True,
            }
        )

    output = {
        "target": "minly-web",
        "exact_scope_host": ALLOWED_HOST,
        "request_values_retained": False,
        "request_bodies_retained": False,
        "authorization_candidates": [row for row in endpoints if row["authorization_candidate"]],
        "all_endpoint_patterns": endpoints,
        "graphql_operation_names": sorted(graphql_ops),
        "websocket_path_patterns": sorted(websocket_paths),
        "third_party_hosts_observed_not_tested": sorted(third_party_hosts),
        "submission_candidates": submission_candidates,
        "excluded_program_noise": excluded_program_noise,
        "manual_review_notice": "No candidate is submission-ready until manually reproduced with researcher-controlled accounts and direct impact is demonstrated.",
    }

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "candidate-map.json").write_text(json.dumps(output, indent=2), encoding="utf-8")

    lines = [
        "# Minly Human-Review Candidate Map",
        "",
        "Generated from bounded exact-host evidence. No request values or bodies are retained.",
        "",
        "## Authorization-first endpoint candidates",
        "",
        "| Score | Method | Path pattern | Object hints | State-changing |",
        "|---:|---|---|---|---|",
    ]
    candidates = output["authorization_candidates"]
    for row in candidates:
        hints = ", ".join(row["object_hint_parameters"]) or "path object"
        lines.append(f"| {row['candidate_score']} | {row['method']} | `{row['path_pattern']}` | {hints} | {'manual only' if row['state_changing_manual_only'] else 'no'} |")
    if not candidates:
        lines.append("| 0 | - | No object-reference candidates observed in this run | - | - |")

    lines += ["", "## Program-eligible finding candidates", ""]
    if submission_candidates:
        for item in submission_candidates:
            lines.append(f"- **{item['title']}** — {item['severity']} — human reproduction required")
    else:
        lines.append("- None yet. Automated/best-practice-only observations are not treated as submissions.")

    lines += [
        "",
        "## Human gate",
        "",
        "For any candidate: reproduce minimally, use only accounts you control, stop if another user's non-public data appears, and do not continue after impact is proven.",
    ]
    (args.output / "candidate-map.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"endpoint_patterns": len(endpoints), "authorization_candidates": len(candidates), "submission_candidates": len(submission_candidates)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
