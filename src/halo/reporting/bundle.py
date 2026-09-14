from __future__ import annotations

import html
import json
import re
import tomllib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..orchestrator import TargetRun


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _summary(runs: list[TargetRun]) -> dict[str, Any]:
    per_target: dict[str, Any] = {}
    total_findings = 0
    family_states: Counter[str] = Counter()
    for run in runs:
        total_findings += len(run.findings)
        counts = Counter(record.status.value for record in run.coverage)
        for record in run.coverage:
            family_states[f"{record.family}:{record.status.value}"] += 1
        per_target[run.target] = {
            "findings": len(run.findings),
            "coverage": dict(counts),
            "families": {record.family: record.status.value for record in run.coverage},
        }
    return {
        "generated_at": _now(),
        "targets": len(runs),
        "findings": total_findings,
        "per_target": per_target,
        "family_states": dict(family_states),
    }


def _sarif(runs: list[TargetRun]) -> dict[str, Any]:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "informational": "note"}
    results: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}
    for run in runs:
        for finding in run.findings:
            rules.setdefault(finding.rule_id, {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.title},
            })
            results.append({
                "ruleId": finding.rule_id,
                "level": level.get(finding.severity, "note"),
                "message": {"text": finding.title},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.url}}}],
                "properties": {
                    "target": run.target,
                    "family": finding.family,
                    "tool": finding.tool,
                    "identity": finding.identity,
                    "comparedIdentity": finding.compared_identity,
                    "evidenceGrade": finding.evidence_grade,
                    "confidence": finding.confidence,
                    "evidence": finding.evidence,
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
        for finding in run.findings:
            if finding.family not in {"dependency-sbom", "container"}:
                continue
            statements.append({
                "vulnerability": {"name": finding.rule_id},
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

    md_lines = ["# HALO Combined Audit Report", "", f"Generated: {summary['generated_at']}", "",
                f"Targets: **{summary['targets']}**  ", f"Findings: **{summary['findings']}**", ""]
    for run in runs:
        md_lines += [f"## {run.target}", "", f"Findings: **{len(run.findings)}**", "", "### Family coverage", ""]
        for record in run.coverage:
            reason = f" — {record.reason}" if record.reason else ""
            md_lines.append(f"- `{record.family}`: **{record.status.value}**{reason}")
        md_lines += ["", "### Findings", ""]
        if not run.findings:
            md_lines.append("No reportable findings.")
        for finding in run.findings:
            md_lines += [
                f"#### {finding.title}",
                f"- Severity: **{finding.severity}**",
                f"- Rule: `{finding.rule_id}`",
                f"- URL: `{finding.url}`",
                f"- Identity: `{finding.identity or '-'}`",
                f"- Evidence: `{finding.evidence_grade}` / confidence `{finding.confidence}`",
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
        width, height = A4
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
