#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def clean(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def parse_location(value: Any) -> Any:
    if isinstance(value, str) and value.strip().startswith(("{", "[")):
        try:
            return json.loads(value)
        except Exception:
            return value
    return value


def title_for(c: dict[str, Any]) -> str:
    typ = c.get("candidate_type")
    loc = parse_location(c.get("location"))
    if typ == "android-deep-link":
        route = loc.get("path_prefix") or loc.get("host") or loc.get("scheme") if isinstance(loc, dict) else clean(loc)
        return f"Android deep-link route candidate: {route or 'manifest route'}"
    if typ == "universal-link-routing":
        return f"iOS universal-link route candidate: {clean(loc)}"
    if typ == "android-component-exposure":
        return f"Android exported component candidate: {clean(loc).split(':')[-1]}"
    if typ == "secret-pattern":
        return f"Static secret/key pattern candidate: {c.get('location')}"
    if typ == "android-cleartext-policy":
        return "Android cleartext/network-security policy candidate"
    if typ == "static-code":
        return f"Static Android code/security rule candidate: {c.get('detail')}"
    return f"{typ or 'Security'} candidate: {clean(c.get('location'))}"


def evidence_for(c: dict[str, Any], root: Path) -> list[str]:
    typ = c.get("candidate_type") or "unknown"
    source = c.get("source") or "unknown"
    loc = parse_location(c.get("location"))
    evidence = [
        f"Source artifact: {source}",
        f"Candidate type: {typ}",
        f"Rank/Priority: {c.get('rank')} / {c.get('priority')}",
        f"Location: {clean(loc)}",
        f"Promotion state: {c.get('promotion_state')} / {c.get('verification_status')}",
    ]
    android = load_json(root / "android" / "summary.json", {})
    ios = load_json(root / "ios" / "summary.json", {})
    if str(typ).startswith("android"):
        pkg = android.get("observed_package")
        if pkg:
            evidence.append(f"Observed Android package: {pkg}")
        if android.get("verification_status"):
            evidence.append(f"Android analysis status: {android.get('verification_status')}")
    if typ == "universal-link-routing":
        aad = ios.get("apple_associated_domains") or {}
        evidence.append(f"AASA route components observed: {aad.get('routing_component_count', 'unknown')}")
        ids = aad.get("bundle_matching_app_ids") or []
        if ids:
            evidence.append(f"Matching app ID(s): {', '.join(map(str, ids))}")
    if c.get("cross_family_corroboration"):
        evidence.append("Corroboration sample: " + ", ".join(clean(x) for x in c.get("cross_family_corroboration", [])[:5]))
    return evidence


def safe_poc_for(c: dict[str, Any]) -> list[str]:
    typ = c.get("candidate_type")
    loc = parse_location(c.get("location"))
    if typ in {"android-deep-link", "universal-link-routing"}:
        route = loc.get("path_prefix") if isinstance(loc, dict) else loc
        return [
            "Use only researcher-controlled Account A and Account B, plus a clean browser/device session.",
            f"Open or invoke the observed route/path ({clean(route)}) through the normal app, deep-link, or universal-link flow using only Account A-created objects.",
            "Repeat from logged-out state and Account B. Compare whether private data, entitlement, request state, referral/redeem state, rating state, or account-specific content crosses the A/B boundary.",
            "Capture minimal redacted screenshots or request/response metadata showing expected denial versus actual access. Stop immediately if any non-controlled user data appears.",
        ]
    if typ == "android-component-exposure":
        return [
            "Install the exact observed Minly Android artifact on a researcher-owned device or emulator and use only controlled accounts.",
            "Open the exported component through ordinary Android entry paths and controlled link/intent context only.",
            "Verify whether login, ownership, role, entitlement, and state-transition checks are enforced before data display or writes.",
            "Record component name, account used, expected result, actual result, and redacted backend metadata where available.",
        ]
    if typ == "secret-pattern":
        return [
            "Reproduce by decompiling the exact observed APK artifact and rerunning a redacted secret scanner over the same file and line.",
            "Classify the value privately as placeholder, public identifier, third-party library noise, or sensitive Minly-owned credential; do not publish or test the raw value against third-party services.",
            "Where it appears Minly-owned, ask Minly to validate server-side scope, activity, restrictions, and rotation status.",
            "Submit only redacted file path, line, hash/fingerprint, likely service context, and impact hypothesis.",
        ]
    if typ == "android-cleartext-policy":
        return [
            "Inspect AndroidManifest.xml and network-security config from the exact APK artifact.",
            "Using a researcher-owned device/account, verify whether sensitive Minly traffic can actually be sent over HTTP or downgraded.",
            "Capture only domain/protocol metadata; do not capture or publish credentials, tokens, or private payloads.",
        ]
    if typ == "static-code":
        return [
            "Reproduce the static-analysis rule on the exact APK artifact and identify the file/rule that triggered it.",
            "Manually confirm whether the flagged condition creates realistic Minly impact beyond best-practice noise.",
            "Attach redacted file/rule evidence and a controlled impact demonstration only if one exists.",
        ]
    return ["Manually reproduce with owned accounts, redacted evidence, and exact in-scope targets before submission."]


def impact_for(c: dict[str, Any]) -> str:
    typ = c.get("candidate_type")
    text = (clean(c.get("location")) + " " + clean(c.get("detail"))).lower()
    if typ in {"android-deep-link", "universal-link-routing"}:
        impacts: list[str] = []
        if "redeem" in text or "refer" in text:
            impacts.append("abuse referral/redeem workflows, incorrectly claim incentives, or alter attribution")
        if "rate" in text:
            impacts.append("submit or manipulate rating flows outside the intended user/request boundary")
        if "/r/" in text or "request" in text:
            impacts.append("view or influence another controlled request/order state if backend authorization is weak")
        if "watch" in text or "video" in text or "/v/" in text:
            impacts.append("reach media or entitlement screens that should require ownership, purchase, or request context")
        if "chat" in text or "message" in text:
            impacts.append("reach chat/message surfaces that require participant authorization")
        if not impacts:
            impacts.append("bypass expected navigation and test whether backend authorization correctly protects route state")
        return "As an attacker, if this candidate is confirmed, I could " + "; ".join(impacts) + "."
    if typ == "android-component-exposure":
        return "As an attacker, if this candidate is confirmed, I could directly launch internal Android screens and potentially bypass client-side navigation, login prompts, or entitlement checks unless backend controls block the action."
    if typ == "secret-pattern":
        return "As an attacker, if the flagged value is a real unrestricted credential, I could access the related API/cloud/service capability, impersonate application traffic, abuse quota, or access data permitted by that credential's scope."
    if typ == "android-cleartext-policy":
        return "As an attacker on the same network, if sensitive traffic is actually cleartext or downgradeable, I could observe or tamper with account/session or business-flow traffic."
    if typ == "static-code":
        return "As an attacker, if the static rule maps to exploitable Minly behavior, I could target the affected platform weakness to bypass intended protection or expose controlled-user data."
    return "As an attacker, confirmed impact would depend on manual proof of a security-boundary failure."


def remediation_for(c: dict[str, Any]) -> list[str]:
    typ = c.get("candidate_type")
    text = (clean(c.get("location")) + " " + clean(c.get("detail"))).lower()
    if typ in {"android-deep-link", "universal-link-routing"}:
        recs = [
            "Enforce authentication, object ownership, role/entitlement, and state-transition checks server-side for every route.",
            "Reject cross-account object access by default and return generic denials without leaking object existence.",
            "Require signed, short-lived, single-purpose tokens for referral, redeem, media, or request-status links where direct links carry state.",
        ]
        if "refer" in text or "redeem" in text:
            recs.append("Bind referral/redeem actions to one account, one campaign, expiry, anti-replay checks, and server-side eligibility validation.")
        if "rate" in text:
            recs.append("Bind rating actions to completed owned requests and enforce one authorized rating per eligible transaction.")
        return recs
    if typ == "android-component-exposure":
        return [
            "Set exported=false for components that do not need external entry.",
            "For legitimate link entry points, validate intent action/data/extras and re-check session, ownership, and entitlement before rendering or writing.",
            "Move sensitive decisions to backend authorization and add regression tests for direct component-launch paths.",
        ]
    if typ == "secret-pattern":
        return [
            "Remove hard-coded secrets from mobile artifacts; prefer backend token exchange or restricted public client identifiers only.",
            "Rotate any exposed credential and restrict it by package name, signing certificate, domain, environment, quota, and least privilege.",
            "Add CI secret scanning with documented allowlists for known false positives and fail only on validated/high-confidence credentials.",
        ]
    if typ == "android-cleartext-policy":
        return [
            "Disable cleartext traffic by default in release builds and explicitly allow only non-sensitive development endpoints outside production.",
            "Use HTTPS/TLS for all Minly endpoints and monitor for accidental HTTP endpoints in release builds.",
            "Add release-build network-security checks to CI.",
        ]
    if typ == "static-code":
        return [
            "Map the rule to concrete code and affected runtime behavior before treating it as a vulnerability.",
            "Patch the insecure pattern, add platform regression tests, and suppress false positives only with documented justification.",
        ]
    return ["Apply a targeted fix after manual validation confirms exploitability and affected boundary."]


def missing_for(c: dict[str, Any]) -> list[str]:
    typ = c.get("candidate_type")
    missing = ["Manual reproduction evidence", "Expected versus actual behavior", "Concrete Minly security impact proof"]
    if typ in {"android-deep-link", "universal-link-routing", "android-component-exposure"}:
        missing += ["Researcher-controlled Account A/B comparison", "Redacted screenshot or request/response proof"]
    if typ == "secret-pattern":
        missing += ["Private raw-value classification by Minly", "Proof that the value is active, sensitive, and not a public identifier or false positive"]
    if typ == "static-code":
        missing += ["Runtime exploitability link, not scanner-only rule output"]
    return missing


def build_report(root: Path, run_id: str) -> dict[str, Any]:
    priority = load_json(root / "candidate-review" / "candidate-priority.json", {"candidates": [], "submission_ready_count": 0})
    web_manifest = load_json(root / "web" / "family-manifest.json", {})
    web_surface = load_json(root / "web" / "passive" / "surface-map.json", {})
    android = load_json(root / "android" / "summary.json", {})
    ios = load_json(root / "ios" / "summary.json", {})
    har = load_json(root / "web" / "authenticated-har" / "status.json", {})
    candidates = []
    for c in priority.get("candidates", []) or []:
        if not isinstance(c, dict):
            continue
        candidates.append({
            "rank": c.get("rank"),
            "priority": c.get("priority"),
            "candidate_type": c.get("candidate_type"),
            "source": c.get("source"),
            "title": title_for(c),
            "location": c.get("location"),
            "detail": c.get("detail"),
            "evidence_basis": evidence_for(c, root),
            "safe_poc_reproduction_plan": safe_poc_for(c),
            "attacker_impact_if_confirmed": impact_for(c),
            "recommended_solution": remediation_for(c),
            "missing_before_submission_ready": missing_for(c),
            "verification_status": c.get("verification_status"),
            "promotion_state": c.get("promotion_state"),
        })
    return {
        "report_title": "Minly Detailed Vulnerability Candidate Report",
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "candidate_count": len(candidates),
        "submission_ready_verified_findings": priority.get("submission_ready_count", 0),
        "counts_by_type": dict(Counter(x.get("candidate_type") for x in candidates)),
        "counts_by_source": dict(Counter(x.get("source") for x in candidates)),
        "coverage": {
            "web_identity_mode": web_manifest.get("identity_mode"),
            "web_counts": web_surface.get("counts"),
            "android_status": android.get("status"),
            "android_package": android.get("observed_package"),
            "ios_status": ios.get("status"),
            "ios_app_store_id": ios.get("app_store_id"),
            "authenticated_har_status": har.get("status"),
        },
        "why_zero_verified": [
            "No human-reviewed manual findings were supplied through MINLY_MANUAL_FINDINGS_B64.",
            "Authenticated HAR analysis was skipped unless researcher-owned HAR URL/SHA secrets were provided.",
            "Anonymous web coverage cannot prove authenticated authorization, ownership, entitlement, or payment-flow impact.",
            "iOS coverage is public App Store/AASA metadata unless an authorized IPA or dynamic test evidence is supplied.",
            "Android public/static output is candidate-only until owned-account runtime evidence proves concrete Minly impact.",
        ],
        "policy": {
            "candidate_not_final_finding": True,
            "manual_owned_account_reproduction_required": True,
            "do_not_publish_live_private_findings": True,
            "do_not_include_raw_tokens_hars_or_unrelated_user_data": True,
        },
        "candidates": candidates,
    }


def write_markdown(report: dict[str, Any], path: Path) -> None:
    lines = [
        f"# {report['report_title']}", "",
        f"Run ID: `{report['run_id']}`  ",
        f"Generated: `{report['generated_at']}`  ",
        f"Candidate count: **{report['candidate_count']}**  ",
        f"Submission-ready verified findings in source run: **{report['submission_ready_verified_findings']}**", "",
        "## Important handling note", "",
        "These are vulnerability candidates, not confirmed vulnerabilities. Submit them as candidates/leads unless manual owned-account evidence proves concrete Minly impact. Keep private evidence out of public repositories.", "",
        "## Why the source run produced 0 verified findings", "",
    ]
    lines += [f"- {x}" for x in report["why_zero_verified"]]
    lines += ["", "## Coverage summary", ""]
    lines += [f"- **{k}:** `{clean(v)}`" for k, v in report["coverage"].items()]
    lines += ["", "## Candidate counts by type", ""]
    lines += [f"- **{k}:** {v}" for k, v in report["counts_by_type"].items()]
    lines += ["", "## Detailed candidate inventory", ""]
    for x in report["candidates"]:
        lines += [
            f"### {x['rank']}. {x['title']}", "",
            f"- **Priority:** {x['priority']} | **Status:** {x['verification_status']} | **Source:** {x['source']}",
            f"- **Location:** `{clean(x['location'])}`",
            f"- **Observed detail:** {clean(x['detail'])}",
            "- **Evidence basis:** " + "; ".join(x["evidence_basis"]),
            "- **Safe PoC / reproduction plan:**",
        ]
        lines += [f"  - {step}" for step in x["safe_poc_reproduction_plan"]]
        lines += [f"- **What an attacker might do if confirmed:** {x['attacker_impact_if_confirmed']}", "- **Recommended solution:**"]
        lines += [f"  - {rec}" for rec in x["recommended_solution"]]
        lines += ["- **Still missing before high-confidence submission:** " + "; ".join(x["missing_before_submission_ready"]), ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_html(report: dict[str, Any], path: Path) -> None:
    css = """@page{size:A4;margin:14mm}body{font-family:DejaVu Sans,Arial,sans-serif;font-size:9.7pt;line-height:1.35;color:#111}h1{font-size:20pt;margin:0 0 8px}h2{font-size:14pt;margin-top:18px;border-bottom:1px solid #aaa;padding-bottom:3px}h3{font-size:11.5pt;margin-top:14px}code{font-family:DejaVu Sans Mono,monospace;font-size:8.5pt;word-break:break-all}li{margin-bottom:2px}.small{color:#555;font-size:8.4pt}.badge{display:inline-block;padding:1px 5px;border:1px solid #777;border-radius:4px;margin-right:4px}.box{border:1px solid #ccc;padding:7px 9px;margin:7px 0;background:#fafafa}.warn{background:#fff8e6;border:1px solid #e0bd5a;padding:8px}.candidate{break-inside:avoid;page-break-inside:avoid;border-top:1px solid #ddd;padding-top:6px}"""
    p = ["<!doctype html><html><head><meta charset='utf-8'><style>", css, "</style></head><body>"]
    p.append(f"<h1>{html.escape(report['report_title'])}</h1><p class='small'>Run ID: {html.escape(clean(report['run_id']))}<br>Generated: {html.escape(report['generated_at'])}</p>")
    p.append("<div class='warn'><b>Important:</b> These are vulnerability candidates, not confirmed vulnerabilities. Use PoC sections as safe manual reproduction plans only and keep private evidence out of public repositories.</div>")
    p.append(f"<h2>Executive summary</h2><p><b>{report['candidate_count']}</b> candidates extracted. Verified submission-ready findings: <b>{report['submission_ready_verified_findings']}</b>.</p>")
    p.append("<h3>Why zero verified</h3><ul>" + "".join(f"<li>{html.escape(x)}</li>" for x in report["why_zero_verified"]) + "</ul>")
    p.append("<h3>Counts by type</h3><ul>" + "".join(f"<li>{html.escape(clean(k))}: {v}</li>" for k, v in report["counts_by_type"].items()) + "</ul>")
    p.append("<h2>Detailed vulnerability candidate inventory</h2>")
    for x in report["candidates"]:
        p.append("<div class='candidate'>")
        p.append(f"<h3>{html.escape(clean(x['rank']))}. {html.escape(x['title'])}</h3>")
        p.append(f"<p><span class='badge'>{html.escape(clean(x['priority']))}</span><span class='badge'>{html.escape(clean(x['verification_status']))}</span><span class='badge'>{html.escape(clean(x['source']))}</span></p>")
        p.append(f"<p><b>Location:</b> <code>{html.escape(clean(x['location']))}</code><br><b>Observed detail:</b> {html.escape(clean(x['detail']))}</p>")
        p.append("<div class='box'><b>Evidence basis</b><ul>" + "".join(f"<li>{html.escape(i)}</li>" for i in x["evidence_basis"]) + "</ul></div>")
        p.append("<div class='box'><b>Safe PoC / reproduction plan</b><ol>" + "".join(f"<li>{html.escape(i)}</li>" for i in x["safe_poc_reproduction_plan"]) + "</ol></div>")
        p.append(f"<p><b>What an attacker might do if confirmed:</b> {html.escape(x['attacker_impact_if_confirmed'])}</p>")
        p.append("<p><b>Recommended solution:</b></p><ul>" + "".join(f"<li>{html.escape(i)}</li>" for i in x["recommended_solution"]) + "</ul>")
        p.append("<p><b>Still missing before high-confidence submission:</b> " + html.escape("; ".join(x["missing_before_submission_ready"])) + "</p></div>")
    p.append("</body></html>")
    path.write_text("".join(p), encoding="utf-8")


def maybe_pdf(html_path: Path, pdf_path: Path) -> None:
    try:
        from weasyprint import HTML  # type: ignore
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
    except Exception as exc:
        pdf_path.with_suffix(".pdf.error.txt").write_text(str(exc), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Build detailed Minly vulnerability candidate report from final audit artifacts")
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--run-id", default="unknown")
    ap.add_argument("--no-pdf", action="store_true")
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    report = build_report(args.root, args.run_id)
    (args.output / "detailed-vulnerability-candidates.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    write_markdown(report, args.output / "detailed-vulnerability-candidates.md")
    html_path = args.output / "detailed-vulnerability-candidates.html"
    write_html(report, html_path)
    if not args.no_pdf:
        maybe_pdf(html_path, args.output / "detailed-vulnerability-candidates.pdf")
    print(f"DETAILED_CANDIDATE_COUNT={report['candidate_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
