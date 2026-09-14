from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from typing import Any

from ..models import CoverageRecord, FamilyStatus, Finding


_SEVERITY = {
    "UNKNOWN": "unknown",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


def _trivy_binary() -> str:
    binary = shutil.which("trivy")
    if not binary:
        raise RuntimeError("trivy is not installed or not on PATH")
    return binary


async def _run_json(argv: list[str], *, timeout: float = 900) -> dict[str, Any]:
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        process.kill()
        await process.communicate()
        raise TimeoutError(f"trivy timed out after {timeout}s") from exc
    if process.returncode != 0:
        raise RuntimeError(stderr.decode("utf-8", errors="replace")[:2000])
    try:
        return json.loads(stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("trivy returned invalid JSON") from exc


def _misconfig_findings(payload: dict[str, Any], family: str) -> list[Finding]:
    findings: list[Finding] = []
    for result in payload.get("Results") or []:
        target = str(result.get("Target") or "")
        for item in result.get("Misconfigurations") or []:
            findings.append(Finding(
                tool="trivy",
                family=family,
                rule_id=str(item.get("ID") or "trivy-misconfiguration"),
                title=str(item.get("Title") or item.get("Message") or "Trivy misconfiguration"),
                severity=_SEVERITY.get(str(item.get("Severity") or "UNKNOWN").upper(), "unknown"),
                url=target,
                confidence=100,
                evidence_grade="direct",
                evidence={
                    "description": item.get("Description"),
                    "message": item.get("Message"),
                    "resolution": item.get("Resolution"),
                    "references": item.get("References") or [],
                },
            ))
    return findings


def _vulnerability_findings(payload: dict[str, Any], family: str) -> list[Finding]:
    findings: list[Finding] = []
    for result in payload.get("Results") or []:
        target = str(result.get("Target") or "")
        for item in result.get("Vulnerabilities") or []:
            vuln_id = str(item.get("VulnerabilityID") or "trivy-vulnerability")
            pkg = str(item.get("PkgName") or "")
            findings.append(Finding(
                tool="trivy",
                family=family,
                rule_id=vuln_id,
                title=str(item.get("Title") or f"{vuln_id} in {pkg}"),
                severity=_SEVERITY.get(str(item.get("Severity") or "UNKNOWN").upper(), "unknown"),
                url=target,
                confidence=100,
                evidence_grade="direct",
                evidence={
                    "package": pkg,
                    "installed_version": item.get("InstalledVersion"),
                    "fixed_version": item.get("FixedVersion"),
                    "primary_url": item.get("PrimaryURL"),
                },
            ))
    return findings


class TrivyIaCAdapter:
    name = "trivy-config"
    family = "iac"

    async def run(self, target_name: str, paths: list[str], *, timeout: float = 900) -> tuple[list[Finding], CoverageRecord]:
        coverage = CoverageRecord(target=target_name, family=self.family, status=FamilyStatus.RAN, tools_expected=1)
        try:
            binary = _trivy_binary()
            findings: list[Finding] = []
            for path in paths:
                payload = await _run_json([binary, "config", "--format", "json", path], timeout=timeout)
                findings.extend(_misconfig_findings(payload, self.family))
            coverage.tools_executed = 1
            coverage.findings = len(findings)
            coverage.metadata["inputs"] = len(paths)
            return findings, coverage
        except TimeoutError as exc:
            coverage.status = FamilyStatus.TIMEOUT
            coverage.reason = str(exc)
        except Exception as exc:
            coverage.status = FamilyStatus.FAILED
            coverage.reason = f"{type(exc).__name__}: {exc}"
        return [], coverage


class TrivyContainerAdapter:
    name = "trivy-image"
    family = "container"

    async def run(self, target_name: str, image: str, *, timeout: float = 1800) -> tuple[list[Finding], CoverageRecord]:
        coverage = CoverageRecord(target=target_name, family=self.family, status=FamilyStatus.RAN, tools_expected=1)
        try:
            binary = _trivy_binary()
            payload = await _run_json(
                [binary, "image", "--format", "json", "--scanners", "vuln", image],
                timeout=timeout,
            )
            findings = _vulnerability_findings(payload, self.family)
            coverage.tools_executed = 1
            coverage.findings = len(findings)
            coverage.metadata["image"] = image
            return findings, coverage
        except TimeoutError as exc:
            coverage.status = FamilyStatus.TIMEOUT
            coverage.reason = str(exc)
        except Exception as exc:
            coverage.status = FamilyStatus.FAILED
            coverage.reason = f"{type(exc).__name__}: {exc}"
        return [], coverage
