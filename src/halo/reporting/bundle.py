from __future__ import annotations

import html
import json
import re
import tomllib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..canonical import CanonicalIssue, canonicalize_findings
from ..orchestrator import TargetRun


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _issues(run: TargetRun) -> list[CanonicalIssue]:
    return run.canonical_issues or canonicalize_findings(run.findings, run.target)


def _summary(runs: list[TargetRun]) -> dict[str, Any]:
    per_target: dict[str, Any] = {}
    total_issues = 0
    total_observations = 0
    family_states: Counter[str] = Counter()
    for run in runs:
        issues = _issues(run)
        total_issues += len(issues)
        total_observations += len(run.findings)
        counts = Counter(record.status.value for record in run.coverage)
        for record in run.coverage:
            family_states[f"{record.family}:{record.status.value}"] += 1
        per_target[run.target] = {
            "canonical_issues": len(issues),
            "observations": len(run.findings),
            "coverage": dict(counts),
            "families": {record.family: record.status.value for record in run.coverage},
            "publication_passed": run.publication.passed if run.publication else None,
            "coverage_ratio": run.publication.coverage_ratio if run.publication else None,
        }
    return {
        "generated_at": _now(),
        "targets": len(runs),
        "findings": total_issues,
        "canonical_issues": total_issues,
        "observations": total_observations,
        "per_target": per_target,
        "family_states": dict(family_states),
    }


def _sarif(runs: list[TargetRun]) -> dict[str, Any]:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "informational": "note"}
    results: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}
    for run in runs:
        for issue in _issues(run):
            rules.setdefault(issue.weakness, {
                "id": issue.weakness,
                "shortDescription": {"text": issue.title},
            })
            first_identity = issue.identities[0] if issue.identities else None
            results.append({
                "ruleId": issue.weakness,
                "level": level.get(issue.severity, "note"),
                "message": {"text": issue.title},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": issue.url}}}],
                "properties": {
                    "canonicalId": issue.canonical_id,
                    "canonicalKey": issue.canonical_key,
                    "target": run.target,
                    "families": issue.families,
                    "tools": issue.tools,
                    "identity": first_identity,
                    "identities": issue.identities,
                    "confidence": issue.confidence,
                    "sourceCount": len(issue.evidence_sources),
                    "evidenceSources": [source.to_dict() for source in issue.evidence_sources],
                },
            })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "HALO Audit", "rules": list(rules.values())}}, "results": results}],
    }


def _sbom(repo_root: Path) -> dict[str, Any]:
    pyproject = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    deps = pyproject.get("project", {}).get("dependencies", [])
    components = []
    for dep in deps:
        name = re.split(r"[<>=!~\[]", str(dep), 1)[0].strip()
        if name:
            components.append({"type": "library", "name": name, "purl": f"pkg:pypi/{name.lower()}"})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"timestamp": _now(), "component": {"type": "application", "name": "halo-audit"}},
        "components": components,
    }


def _vex(runs: list[TargetRun]) -> dict[str, Any]:
    statements = []
    for run in runs:
        for issue in _issues(run):
            if not ({"dependency-sbom", "container"} & set(issue.families)):
                continue
            statements.append({
                "vulnerability": {"name": issue.weakness},
                "products": [{"@id": f"pkg:generic/halo-target/{run.target}"}],
                "status": "under_investigation",
            })
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://halo.local/vex/{datetime.now(timezone.utc).timestamp()}",
        "author": "HALO Audit",
        "timestamp": _now(),
        "version": 1,
        "statements": statements,
    }


def write_bundle(runs: list[TargetRun], out_dir: Path, repo_root: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = _summary(runs)
    payload = {"summary": summary, "targets": [run.to_dict() for run in runs]}

    json_path = out_dir / "report.json"
    json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    md_lines = [
        "# HALO Combined Audit Report",
        "",
        f"Generated: {summary['generated_at']}",
        "",
        f"Targets: **{summary['targets']}**  ",
        f"Canonical issues: **{summary['canonical_issues']}**  ",
        f"Verified observations before deduplication: **{summary['observations']}**",
        "",
    ]
    for run in runs:
        issues = _issues(run)
        md_lines += [f"## {run.target}", "", f"Canonical issues: **{len(issues)}**", f"Observations: **{len(run.findings)}**", ""]
        if run.publication:
            state = "PASS" if run.publication.passed else "FAIL"
            md_lines += [
                f"### Publication gate: **{state}**",
                "",
                f"Required-family coverage: **{run.publication.coverage_ratio:.1%}**",
            ]
            for error in run.publication.errors:
                md_lines.append(f"- ERROR: {error}")
            for warning in run.publication.warnings:
                md_lines.append(f"- WARNING: {warning}")
            md_lines.append("")

        md_lines += ["### Family coverage", ""]
        for record in run.coverage:
            reason = f" — {record.reason}" if record.reason else ""
            parity = ""
            if record.accounting:
                parity = (
                    f" | raw={record.accounting.raw_result_count} "
                    f"normalized={record.accounting.normalized_count} "
                    f"excluded={record.accounting.excluded_count} "
                    f"parity={'OK' if record.accounting.parity_ok else 'FAIL'}"
                )
            md_lines.append(f"- `{record.family}`: **{record.status.value}**{reason}{parity}")

        md_lines += ["", "### Canonical issues", ""]
        if not issues:
            md_lines.append("No reportable canonical issues.")
        for issue in issues:
            md_lines += [
                f"#### {issue.title}",
                f"- Severity: **{issue.severity}**",
                f"- Weakness: `{issue.weakness}`",
                f"- Canonical ID: `{issue.canonical_id}`",
                f"- URL/resource: `{issue.url}`",
                f"- Corroborating tools: `{', '.join(issue.tools) or '-'}`",
                f"- Retained evidence sources: **{len(issue.evidence_sources)}**",
                "",
            ]
    md_path = out_dir / "report.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")

    html_path = out_dir / "report.html"
    html_path.write_text(
        "<!doctype html><meta charset='utf-8'><title>HALO Audit</title>"
        "<style>body{font-family:system-ui;max-width:1100px;margin:40px auto;padding:0 24px}"
        "pre{white-space:pre-wrap}code{background:#eee;padding:2px 4px}</style>"
        f"<h1>HALO Combined Audit Report</h1><pre>{html.escape(md_path.read_text(encoding='utf-8'))}</pre>",
        encoding="utf-8",
    )

    sarif_path = out_dir / "findings.sarif"
    sarif_path.write_text(json.dumps(_sarif(runs), indent=2, default=str), encoding="utf-8")

    sbom_path = out_dir / "sbom.cdx.json"
    sbom_path.write_text(json.dumps(_sbom(repo_root), indent=2), encoding="utf-8")

    vex_path = out_dir / "vex.openvex.json"
    vex_path.write_text(json.dumps(_vex(runs), indent=2), encoding="utf-8")

    pdf_path = out_dir / "report.pdf"
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen.canvas import Canvas
    except ImportError:
        pdf_path.write_text("PDF generation requires reportlab; install halo-audit[report].\n", encoding="utf-8")
    else:
        canvas = Canvas(str(pdf_path), pagesize=A4)
        _width, height = A4
        y = height - 48
        for raw_line in md_lines:
            line = re.sub(r"[*`#]", "", raw_line)[:110]
            if y < 48:
                canvas.showPage()
                y = height - 48
            canvas.drawString(42, y, line)
            y -= 14
        canvas.save()

    return {
        "json": json_path,
        "markdown": md_path,
        "html": html_path,
        "pdf": pdf_path,
        "sarif": sarif_path,
        "sbom": sbom_path,
        "vex": vex_path,
    }
