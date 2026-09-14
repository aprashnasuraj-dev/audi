from __future__ import annotations

import asyncio
import json
import shutil
from typing import Any

from ..integrity import finalize_accounting, scanner_exit_completed
from ..models import CoverageRecord, FamilyStatus, Finding, ResultAccounting


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
    if not scanner_exit_completed("trivy", int(process.returncode or 0), mode="json"):
        raise RuntimeError(stderr.decode("utf-8", errors="replace")[:2000])
    try:
        return json.loads(stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("trivy returned invalid JSON") from exc


def _misconfig_findings(payload: dict[str, Any], family: str) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    raw_count = 0
    for result in payload.get("Results") or []:
        target = str(result.get("Target") or "")
        items = result.get("Misconfigurations") or []
        raw_count += len(items)
        for item in items:
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
    return findings, raw_count


def _vulnerability_findings(payload: dict[str, Any], family: str) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    raw_count = 0
    for result in payload.get("Results") or []:
        target = str(result.get("Target") or "")
        items = result.get("Vulnerabilities") or []
        raw_count += len(items)
        for item in items:
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
    return findings, raw_count


class TrivyIaCAdapter:
    name = "trivy-config"
    family = "iac"

    async def run(self, target_name: str, paths: list[str], *, timeout: float = 900) -> tuple[list[Finding], CoverageRecord]:
        coverage = CoverageRecord(target=target_name, family=self.family, status=FamilyStatus.RAN, tools_expected=1)
        try:
            binary = _trivy_binary()
            findings: list[Finding] = []
            raw_count = 0
            for path in paths:
                payload = await _run_json([binary, "config", "--format", "json", path], timeout=timeout)
                parsed, observed = _misconfig_findings(payload, self.family)
                findings.extend(parsed)
                raw_count += observed
            coverage.tools_executed = 1
            coverage.findings = len(findings)
            coverage.metadata["inputs"] = len(paths)
            finalize_accounting(coverage, ResultAccounting(raw_count, len(findings), 0))
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
            findings, raw_count = _vulnerability_findings(payload, self.family)
            coverage.tools_executed = 1
            coverage.findings = len(findings)
            coverage.metadata["image"] = image
            finalize_accounting(coverage, ResultAccounting(raw_count, len(findings), 0))
            return findings, coverage
        except TimeoutError as exc:
            coverage.status = FamilyStatus.TIMEOUT
            coverage.reason = str(exc)
        except Exception as exc:
            coverage.status = FamilyStatus.FAILED
            coverage.reason = f"{type(exc).__name__}: {exc}"
        return [], coverage
