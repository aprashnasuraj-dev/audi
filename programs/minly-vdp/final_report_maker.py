#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}
TARGETS = {"Minly Website", "iOS App", "Android App", "Minly iOS App", "Minly Android App"}
OUT_OF_SCOPE_PATTERNS = [
    r"missing security header", r"missing hsts", r"weak tls", r"version disclosure",
    r"self[- ]?xss", r"clickjacking", r"password policy", r"spf", r"dkim", r"dmarc",
    r"certificate pinning", r"root detection", r"jailbreak detection", r"obfuscation",
]


def load_json(path: Path | None, default: Any) -> Any:
    if path is None or not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"_parse_error": str(exc), "_path": str(path)} if isinstance(default, dict) else default


def text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def target_label(value: str) -> str:
    mapping = {"Minly iOS App": "iOS App", "Minly Android App": "Android App"}
    return mapping.get(value, value)


def validate_finding(f: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = [
        "title", "target", "technical_severity", "vrt_category", "location", "status",
        "summary", "vulnerability_details", "steps_to_reproduce", "proof_of_concept",
        "impact_attacker", "suggested_remediation",
    ]
    for field in required:
        if not f.get(field):
            errors.append(f"missing required field: {field}")
    if f.get("technical_severity") and f["technical_severity"] not in SEVERITIES:
        errors.append("invalid technical_severity")
    if f.get("target") and f["target"] not in TARGETS:
        errors.append("invalid target")
    if f.get("status") not in {"Verified", "Partially verified", "Unverified"}:
        errors.append("status must be Verified, Partially verified, or Unverified")
    if f.get("status") == "Verified" and not f.get("evidence_refs"):
        errors.append("verified finding requires evidence_refs")
    steps = f.get("steps_to_reproduce") or []
    if not isinstance(steps, list) or not steps:
        errors.append("steps_to_reproduce must be a non-empty list")
    poc = text(f.get("proof_of_concept"))
    if f.get("status") == "Verified" and len(poc) < 20:
        errors.append("verified finding requires a concrete proof_of_concept")
    impact = text(f.get("impact_attacker"))
    if impact and not impact.lower().startswith("as an attacker, i could"):
        errors.append('impact_attacker must start with "As an attacker, I could..."')
    blob = " ".join([text(f.get("title")), text(f.get("vrt_category")), text(f.get("summary"))]).lower()
    if any(re.search(pattern, blob) for pattern in OUT_OF_SCOPE_PATTERNS) and not f.get("demonstrated_exploit"):
        errors.append("matches a Minly-listed out-of-scope/best-practice category without demonstrated_exploit=true")
    description = "\n".join([
        text(f.get("summary")), text(f.get("vulnerability_details")),
        "\n".join(map(str, steps)), poc, impact, text(f.get("impact_details")),
        text(f.get("suggested_remediation")),
    ])
    if len(description) >= 25_000:
        errors.append(f"description exceeds 25,000 characters ({len(description)})")
    return errors


def md_code(value: str, language: str = "") -> str:
    fence = "```"
    return f"{fence}{language}\n{value.rstrip()}\n{fence}"


def render_finding(f: dict[str, Any]) -> str:
    steps = f.get("steps_to_reproduce") or []
    step_text = "\n".join(f"{i}. {text(step)}" for i, step in enumerate(steps, 1))
    attachments = f.get("attachments") or []
    if attachments:
        attachment_text = "\n".join(
            f"- `{text(a.get('filename') if isinstance(a, dict) else a)}` — {text(a.get('description') if isinstance(a, dict) else '')}"
            for a in attachments
        )
    else:
        attachment_text = "- None included."
    request = text(f.get("raw_request"))
    response = text(f.get("raw_response"))
    visual = text(f.get("visual_evidence"))
    poc_sections = [text(f.get("proof_of_concept"))]
    if request:
        poc_sections += ["### Request", md_code(request, "http")]
    if response:
        poc_sections += ["### Response", md_code(response, "http")]
    if visual:
        poc_sections += ["### Visual evidence", visual]
    poc_rendered = "\n\n".join(poc_sections)
    limitations = text(f.get("limitations"))
    impact_detail = text(f.get("impact_details"))
    return f"""# Submission title
{text(f.get('title'))}

# Target
{target_label(text(f.get('target')))}

# Technical severity
{text(f.get('technical_severity'))}

# VRT Category
{text(f.get('vrt_category'))}

# URL / Location of vulnerability
{text(f.get('location'))}

# Description

## Summary
{text(f.get('summary'))}

## Vulnerability details
{text(f.get('vulnerability_details'))}

## Steps to reproduce
{step_text}

## Proof of concept
{poc_rendered}

### Verification status
**{text(f.get('status'))}**
{limitations}

## Impact
**{text(f.get('impact_attacker'))}**

{impact_detail}

- **Who is affected:** {text(f.get('who_affected')) or 'Not established beyond the proof above.'}
- **Data or systems affected:** {text(f.get('data_systems_affected')) or 'See proof of concept.'}
- **Worst demonstrated case:** {text(f.get('worst_case')) or 'Limited to the demonstrated proof.'}
- **Authentication required:** {text(f.get('authentication_required')) or 'Not specified.'}
- **User interaction required:** {text(f.get('user_interaction_required')) or 'Not specified.'}
- **Scope of impact:** {text(f.get('scope_of_impact')) or 'Not established beyond the demonstrated proof.'}

## Suggested remediation
{text(f.get('suggested_remediation'))}

# Attachments
{attachment_text}
"""


def summarize_halo(data: dict[str, Any]) -> dict[str, Any]:
    targets = (data.get("targets") or []) if isinstance(data, dict) else []
    findings = (data.get("findings") or []) if isinstance(data, dict) else []
    return {
        "available": bool(data),
        "target_count": len(targets) if isinstance(targets, list) else None,
        "raw_finding_count": len(findings) if isinstance(findings, list) else None,
        "note": "HALO output is supporting evidence/candidate data only for Minly; scanner/hardening observations are never auto-promoted to a submission.",
    }


def summarize_passive(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "available": bool(data),
        "counts": data.get("counts", {}) if isinstance(data, dict) else {},
        "manual_queue_count": len(data.get("manual_verification_queue", [])) if isinstance(data, dict) else 0,
    }


def tool_status(summary: dict[str, Any]) -> dict[str, Any]:
    tc = summary.get("toolchain", {}) if isinstance(summary, dict) else {}
    return {name: info.get("status") for name, info in tc.items() if isinstance(info, dict)}


def render_overview(meta: dict[str, Any], findings: list[dict[str, Any]], rejected: list[dict[str, Any]]) -> str:
    web = meta["web"]
    android = meta["android"]
    ios = meta["ios"]
    lines = [
        "# Minly VDP Final Human-Review Audit Report",
        "",
        f"Generated: `{meta['generated_at']}`",
        "",
        "> This compiled report does not invent findings. Automated/static signals remain unverified candidates unless a human-reviewed proof of concept is supplied. Minly-listed out-of-scope best-practice issues are not promoted to submissions.",
        "",
        "## Scope",
        "",
        "- Website: `https://minly.com/` (exact host only)",
        "- iOS App: App Store ID `1528802350`",
        "- Android App: package `com.minly.users`",
        "",
        "## Audit-family status",
        "",
        f"- HALO web audit evidence: **{'available' if web['halo']['available'] else 'missing'}**",
        f"- Passive browser map: **{'available' if web['passive']['available'] else 'missing'}**",
        f"- Android static family: **{'available' if android else 'SKIPPED — no researcher-supplied APK'}**",
        f"- iOS static family: **{'available' if ios else 'SKIPPED — no researcher-supplied IPA'}**",
        "- Mobile dynamic/instrumentation family: **SKIPPED unless an authorized researcher-controlled device/session is attached; hosted CI does not fabricate dynamic verification.**",
        "",
        "### Android toolchain",
        "",
        md_code(json.dumps(tool_status(android), indent=2), "json") if android else "No APK was supplied.",
        "",
        "### iOS toolchain",
        "",
        md_code(json.dumps(tool_status(ios), indent=2), "json") if ios else "No IPA was supplied.",
        "",
        "## Human-reviewed finding gate",
        "",
        f"- Submission-ready verified findings: **{sum(1 for f in findings if f.get('status') == 'Verified')}**",
        f"- Partially verified/unverified findings retained with explicit labels: **{sum(1 for f in findings if f.get('status') != 'Verified')}**",
        f"- Manual finding records rejected by validation: **{len(rejected)}**",
        "",
    ]
    if rejected:
        lines += ["### Rejected manual records", ""]
        for item in rejected:
            lines.append(f"- `{item.get('title','untitled')}` — {'; '.join(item.get('_validation_errors', []))}")
        lines.append("")
    lines += [
        "## Candidate-only evidence",
        "",
        "Candidate data below is research guidance, not a vulnerability claim. Every candidate requires manual reproduction and real impact before submission.",
        "",
        md_code(json.dumps({
            "web": web,
            "android_candidate_markers": len(android.get('candidate_markers', [])) if android else 0,
            "ios_candidate_markers": len(ios.get('candidate_markers', [])) if ios else 0,
        }, indent=2), "json"),
        "",
    ]
    return "\n".join(lines)


def html_from_markdown(md: str) -> str:
    # Deliberately simple escaped rendering; the Markdown file is canonical.
    return "<!doctype html><meta charset='utf-8'><title>Minly Final Audit Report</title><style>body{font:15px/1.5 system-ui,sans-serif;max-width:980px;margin:40px auto;padding:0 24px;color:#1f2937}pre{white-space:pre-wrap;background:#f3f4f6;padding:16px;border-radius:8px}h1,h2,h3{color:#0f2747}</style><pre>" + html.escape(md) + "</pre>"


def main() -> int:
    ap = argparse.ArgumentParser(description="Compile Minly audit families into human-reviewed submission format")
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--manual-findings", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    halo = load_json(args.root / "web" / "halo" / "report.json", {})
    passive = load_json(args.root / "web" / "passive" / "surface-map.json", {})
    android = load_json(args.root / "android" / "summary.json", {})
    ios = load_json(args.root / "ios" / "summary.json", {})
    manual_data = load_json(args.manual_findings, {"findings": []}) if args.manual_findings else {"findings": []}
    manual = manual_data.get("findings", []) if isinstance(manual_data, dict) else []

    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for raw in manual:
        f = dict(raw)
        errors = validate_finding(f)
        if errors:
            f["_validation_errors"] = errors
            rejected.append(f)
        else:
            accepted.append(f)

    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "web": {"halo": summarize_halo(halo), "passive": summarize_passive(passive)},
        "android": android,
        "ios": ios,
    }
    overview = render_overview(meta, accepted, rejected)
    finding_sections = []
    submissions = args.output / "submissions"
    submissions.mkdir(exist_ok=True)
    for idx, finding in enumerate(accepted, 1):
        rendered = render_finding(finding)
        finding_sections.append(f"\n---\n\n{rendered}")
        if finding.get("status") == "Verified":
            (submissions / f"submission-{idx:02d}.md").write_text(rendered, encoding="utf-8")

    compiled = overview + "".join(finding_sections)
    (args.output / "compiled-final-report.md").write_text(compiled, encoding="utf-8")
    (args.output / "compiled-final-report.html").write_text(html_from_markdown(compiled), encoding="utf-8")
    bundle = {
        "meta": meta,
        "accepted_manual_findings": accepted,
        "rejected_manual_findings": rejected,
        "verified_submission_count": sum(1 for f in accepted if f.get("status") == "Verified"),
        "submission_files": sorted(p.name for p in submissions.glob("*.md")),
        "policy": {
            "do_not_invent_findings": True,
            "proof_required_for_claims": True,
            "impact_phrase_required": "As an attacker, I could...",
            "description_character_limit": 25000,
            "automated_candidates_are_unverified": True,
        },
    }
    (args.output / "compiled-final-report.json").write_text(json.dumps(bundle, indent=2, default=str), encoding="utf-8")
    if rejected:
        print(f"report compiled with {len(rejected)} rejected manual finding record(s); see JSON")
    print(json.dumps({
        "accepted": len(accepted),
        "verified_submissions": bundle["verified_submission_count"],
        "rejected": len(rejected),
        "output": str(args.output),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
