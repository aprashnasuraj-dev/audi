#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

OUT_OF_SCOPE = re.compile(
    r"(?i)(missing[- ]?(?:hsts|csp|security header)|weak tls|version disclosure|self[- ]?xss|"
    r"certificate pinning|root detection|jailbreak detection|obfuscation|password policy|spf|dkim|dmarc)"
)
HIGH_VALUE = {
    "authorization-object-boundary": 12,
    "state-changing-authorization": 11,
    "business-logic": 10,
    "authentication-session": 9,
    "observed-api": 8,
    "android-deep-link": 7,
    "android-component-exposure": 6,
    "ios-custom-url-scheme": 6,
    "universal-link-routing": 5,
    "secret-pattern": 6,
    "static-code": 4,
    "dependency-context": 1,
}


def load(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def norm_path(value: str) -> str:
    value = value or "/"
    value = value.split("?", 1)[0].split("#", 1)[0]
    value = re.sub(r"/[0-9]{2,}(?=/|$)", "/{id}", value)
    value = re.sub(r"/[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}(?=/|$)", "/{uuid}", value)
    return value[:500]


def add(rows: list[dict[str, Any]], *, source: str, kind: str, location: str, detail: str = "", base: int | None = None) -> None:
    blob = f"{kind} {location} {detail}"
    if OUT_OF_SCOPE.search(blob):
        return
    rows.append({
        "source": source,
        "candidate_type": kind,
        "location": location[:600],
        "detail": detail[:800],
        "score": base if base is not None else HIGH_VALUE.get(kind, 3),
        "verification_status": "Unverified",
        "promotion_state": "NEEDS_MANUAL_POC",
        "proof_required": (
            "Reproduce with researcher-controlled accounts/devices, capture the minimal request/response or visual proof, "
            "and demonstrate concrete security impact before submission."
        ),
    })


def ingest_web(root: Path, rows: list[dict[str, Any]], route_tokens: set[str]) -> None:
    passive = load(root / "web" / "passive" / "surface-map.json", {})
    for item in passive.get("manual_verification_queue", []) or []:
        kind = str(item.get("type") or "web-candidate")
        loc = str(item.get("url") or item.get("action") or item.get("path") or item.get("page") or "")
        add(rows, source="web-passive", kind=kind, location=loc, detail=str(item.get("instruction") or ""))
        if loc.startswith("/"):
            route_tokens.add(norm_path(loc))
    for api in passive.get("observed_api_candidates", []) or []:
        path = norm_path(str(api))
        add(rows, source="web-passive", kind="observed-api", location=str(api), detail="Naturally observed browser XHR/fetch/WebSocket route.")
        route_tokens.add(path)

    har = load(root / "web" / "authenticated-har" / "har-surface-map.json", {})
    if not har:
        har = load(root / "authenticated-har" / "har-surface-map.json", {})
    for item in har.get("manual_verification_queue", []) or []:
        kinds = item.get("candidate_types") or ["har-candidate"]
        for kind in kinds:
            loc = f"{item.get('method','GET')} {item.get('path','/')}"
            add(
                rows,
                source="authenticated-har",
                kind=str(kind),
                location=loc,
                detail=f"parameters={item.get('parameter_names') or []}; observed_status={item.get('response_status')}",
            )
        route_tokens.add(norm_path(str(item.get("path") or "/")))


def ingest_android(root: Path, rows: list[dict[str, Any]], route_tokens: set[str]) -> None:
    inspect = load(root / "android" / "artifact-inspection.json", {})
    for item in inspect.get("candidates", []) or []:
        kind = str(item.get("type") or "android-candidate")
        loc = str(item.get("location") or "")
        add(rows, source="android-inspector", kind=kind, location=loc, detail=str(item.get("note") or ""))
        if kind == "android-deep-link":
            route_tokens.add(norm_path(loc))

    summary = load(root / "android" / "summary.json", {})
    for url in summary.get("observed_urls", []) or []:
        try:
            path = "/" + str(url).split("/", 3)[3] if str(url).count("/") >= 3 else "/"
        except Exception:
            path = "/"
        route_tokens.add(norm_path(path))

    for filename, label, score in [
        ("gitleaks-candidates.json", "secret-pattern", 7),
        ("secret-pattern-candidates.json", "secret-pattern", 6),
        ("mobsfscan-candidates.json", "static-code", 5),
        ("semgrep-candidates.json", "static-code", 5),
        ("dependency-context.json", "dependency-context", 1),
    ]:
        data = load(root / "android" / filename, {})
        for item in (data.get("results") or [])[:300]:
            rule = str(item.get("rule_id") or item.get("check_id") or item.get("id") or item.get("type") or label)
            loc = str(item.get("file") or item.get("target") or "android artifact")
            add(rows, source=f"android-{filename}", kind=label, location=loc, detail=rule, base=score)


def ingest_ios(root: Path, rows: list[dict[str, Any]], route_tokens: set[str]) -> None:
    inspect = load(root / "ios" / "artifact-inspection.json", {})
    for item in inspect.get("candidates", []) or []:
        kind = str(item.get("type") or "ios-candidate")
        add(rows, source="ios-inspector", kind=kind, location=str(item.get("location") or ""), detail=str(item.get("note") or ""))

    summary = load(root / "ios" / "summary.json", {})
    for item in summary.get("candidate_markers", []) or []:
        kind = str(item.get("candidate_type") or "universal-link-routing")
        detail_obj = item.get("detail")
        if isinstance(detail_obj, dict):
            loc = str(detail_obj.get("path") or detail_obj.get("/") or detail_obj)
        else:
            loc = str(detail_obj or "")
        add(rows, source="ios-public-metadata", kind=kind, location=loc, detail=str(item.get("source") or ""))
        if loc.startswith("/"):
            route_tokens.add(norm_path(loc))


def correlate(rows: list[dict[str, Any]], route_tokens: set[str]) -> None:
    tokens = {t for t in route_tokens if len(t) > 1 and not t.startswith("http")}
    for row in rows:
        loc = norm_path(str(row.get("location") or ""))
        matches = [token for token in tokens if token != "/" and (token in loc or loc in token)]
        if len(set(matches)) >= 2:
            row["score"] += 3
            row["cross_family_corroboration"] = sorted(set(matches))[:10]
        elif matches:
            row["score"] += 1
            row["cross_family_corroboration"] = sorted(set(matches))[:10]


def dedupe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    best: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        key = (str(row.get("candidate_type")), str(row.get("location")))
        current = best.get(key)
        if current is None or int(row.get("score", 0)) > int(current.get("score", 0)):
            best[key] = row
    ordered = sorted(best.values(), key=lambda x: (-int(x.get("score", 0)), x.get("candidate_type", ""), x.get("location", "")))
    for index, row in enumerate(ordered, 1):
        score = int(row.get("score", 0))
        row["rank"] = index
        row["priority"] = "P1" if score >= 12 else "P2" if score >= 9 else "P3" if score >= 6 else "P4"
    return ordered


def main() -> int:
    ap = argparse.ArgumentParser(description="Correlate Minly web/mobile audit signals into a manual proof queue")
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    route_tokens: set[str] = set()
    ingest_web(args.root, rows, route_tokens)
    ingest_android(args.root, rows, route_tokens)
    ingest_ios(args.root, rows, route_tokens)
    correlate(rows, route_tokens)
    ranked = dedupe(rows)

    result = {
        "policy": {
            "automated_output_is_not_a_finding": True,
            "manual_poc_required": True,
            "do_not_invent_submission_ready_findings": True,
            "out_of_scope_best_practice_noise_filtered": True,
        },
        "candidate_count": len(ranked),
        "submission_ready_count": 0,
        "note": (
            "A candidate becomes submission-ready only after a human-reviewed PoC proves concrete impact. "
            "This ranker intentionally cannot promote scanner/static output by itself."
        ),
        "candidates": ranked[:500],
    }
    (args.output / "candidate-priority.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    lines = [
        "# Minly candidate priority queue",
        "",
        "> Automated/static evidence only. No item below is a vulnerability claim until a human-reviewed PoC demonstrates concrete impact.",
        "",
        f"- Candidates: **{len(ranked)}**",
        "- Submission-ready from automation alone: **0**",
        "",
        "## Highest-value manual checks",
        "",
    ]
    for row in ranked[:80]:
        lines.append(
            f"- **{row['priority']} / score {row['score']}** `{row['candidate_type']}` — `{row['location']}` — source `{row['source']}`"
        )
    (args.output / "candidate-priority.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"candidate_count": len(ranked), "submission_ready_count": 0}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
