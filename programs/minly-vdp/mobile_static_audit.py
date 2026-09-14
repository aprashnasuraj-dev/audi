#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
SENSITIVE_WORDS = re.compile(
    r"(?i)(api[_-]?key|client[_-]?secret|authorization|bearer|private[_-]?key|access[_-]?token|refresh[_-]?token)"
)
TEXT_SUFFIXES = {
    ".java", ".kt", ".kts", ".xml", ".json", ".properties", ".js", ".ts", ".tsx",
    ".plist", ".swift", ".m", ".mm", ".h", ".txt", ".conf", ".yaml", ".yml",
}


def run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 300) -> dict[str, Any]:
    exe = shutil.which(cmd[0])
    if not exe:
        return {"status": "SKIPPED", "reason": f"{cmd[0]} not installed", "command": cmd}
    try:
        cp = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"status": "TIMEOUT", "command": cmd}
    status = "RAN" if cp.returncode == 0 else "COMPLETED_NONZERO"
    return {
        "status": status,
        "returncode": cp.returncode,
        "command": cmd,
        "stdout": cp.stdout[-12000:],
        "stderr": cp.stderr[-8000:],
    }


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_extract_zip(src: Path, dst: Path) -> None:
    with zipfile.ZipFile(src) as zf:
        for info in zf.infolist():
            target = (dst / info.filename).resolve()
            if not str(target).startswith(str(dst.resolve()) + os.sep):
                raise SystemExit(f"unsafe archive path: {info.filename}")
        zf.extractall(dst)


def text_files(root: Path, max_size: int = 2_000_000):
    for p in root.rglob("*"):
        try:
            if p.is_file() and p.stat().st_size <= max_size and p.suffix.lower() in TEXT_SUFFIXES:
                yield p
        except OSError:
            continue


def redact_url(url: str) -> str:
    clean = url.replace("\x00", "")
    return clean.split("?", 1)[0].split("#", 1)[0][:500]


def collect_urls(root: Path) -> list[str]:
    out: set[str] = set()
    for p in text_files(root):
        try:
            data = p.read_text(errors="ignore")
        except OSError:
            continue
        for match in URL_RE.findall(data):
            out.add(redact_url(match))
            if len(out) >= 1000:
                return sorted(out)
    return sorted(out)


def collect_sensitive_markers(root: Path) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for p in text_files(root):
        try:
            lines = p.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for idx, line in enumerate(lines, 1):
            if SENSITIVE_WORDS.search(line):
                results.append({
                    "file": str(p.relative_to(root)),
                    "line": idx,
                    "marker_only": True,
                    "manual_validation_required": True,
                })
                if len(results) >= 500:
                    return results
    return results


def sanitize_mobsfscan(raw_path: Path, out_path: Path) -> int:
    raw = load_json(raw_path, {"results": {}})
    cleaned: list[dict[str, Any]] = []
    for rule_id, block in (raw.get("results") or {}).items():
        if not isinstance(block, dict):
            continue
        meta = block.get("metadata") or {}
        files = block.get("files") or []
        if files:
            for item in files[:100]:
                cleaned.append({
                    "rule_id": rule_id,
                    "severity": meta.get("severity"),
                    "cwe": meta.get("cwe"),
                    "masvs": meta.get("masvs"),
                    "file": Path(str(item.get("file_path") or "")).name,
                    "lines": item.get("match_lines"),
                    "verification_status": "Unverified",
                    "manual_validation_required": True,
                    "reportability": "candidate_only_until_concrete_Minly_impact_is_proved",
                })
        else:
            cleaned.append({
                "rule_id": rule_id,
                "severity": meta.get("severity"),
                "cwe": meta.get("cwe"),
                "masvs": meta.get("masvs"),
                "file": None,
                "lines": None,
                "verification_status": "Unverified",
                "manual_validation_required": True,
                "reportability": "candidate_only_until_concrete_Minly_impact_is_proved",
            })
    out_path.write_text(json.dumps({"candidate_count": len(cleaned), "results": cleaned[:1500]}, indent=2), encoding="utf-8")
    return len(cleaned)


def sanitize_semgrep(raw_path: Path, out_path: Path) -> int:
    raw = load_json(raw_path, {"results": []})
    cleaned = []
    for r in raw.get("results", []) or []:
        cleaned.append({
            "check_id": r.get("check_id"),
            "file": Path(str(r.get("path") or "")).name,
            "start_line": (r.get("start") or {}).get("line"),
            "end_line": (r.get("end") or {}).get("line"),
            "severity": ((r.get("extra") or {}).get("severity") or "INFO"),
            "message": ((r.get("extra") or {}).get("message") or "")[:240],
            "verification_status": "Unverified",
            "manual_validation_required": True,
        })
    out_path.write_text(json.dumps({"candidate_count": len(cleaned), "results": cleaned[:1500]}, indent=2), encoding="utf-8")
    return len(cleaned)


def sanitize_detect_secrets(raw_path: Path, out_path: Path) -> int:
    raw = load_json(raw_path, {"results": {}})
    cleaned = []
    for filename, findings in (raw.get("results") or {}).items():
        for finding in findings or []:
            cleaned.append({
                "file": Path(str(filename)).name,
                "line_number": finding.get("line_number"),
                "type": finding.get("type"),
                "hashed_secret": finding.get("hashed_secret"),
                "verification_status": "Unverified",
                "manual_validation_required": True,
            })
    out_path.write_text(json.dumps({"candidate_count": len(cleaned), "results": cleaned[:1500]}, indent=2), encoding="utf-8")
    return len(cleaned)


def sanitize_gitleaks(raw_path: Path, out_path: Path) -> int:
    raw = load_json(raw_path, [])
    if not isinstance(raw, list):
        raw = []
    cleaned = []
    for finding in raw:
        if not isinstance(finding, dict):
            continue
        cleaned.append({
            "rule_id": finding.get("RuleID") or finding.get("rule_id"),
            "description": finding.get("Description") or finding.get("description"),
            "file": Path(str(finding.get("File") or finding.get("file") or "")).name,
            "start_line": finding.get("StartLine") or finding.get("start_line"),
            "tags": finding.get("Tags") or finding.get("tags") or [],
            "fingerprint": finding.get("Fingerprint") or finding.get("fingerprint"),
            "verification_status": "Unverified",
            "manual_validation_required": True,
        })
    out_path.write_text(json.dumps({"candidate_count": len(cleaned), "results": cleaned[:1500]}, indent=2), encoding="utf-8")
    return len(cleaned)


def sanitize_trivy(raw_path: Path, out_path: Path) -> int:
    raw = load_json(raw_path, {"Results": []})
    cleaned = []
    for result in raw.get("Results", []) or []:
        target = Path(str(result.get("Target") or "")).name
        for vuln in result.get("Vulnerabilities") or []:
            cleaned.append({
                "target": target,
                "id": vuln.get("VulnerabilityID"),
                "package": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "severity": vuln.get("Severity"),
                "title": str(vuln.get("Title") or "")[:240],
                "verification_status": "Unverified",
                "reportability": "dependency_context_only_unless_direct_Minly_exploit_is_demonstrated",
            })
    out_path.write_text(json.dumps({"candidate_count": len(cleaned), "results": cleaned[:1500]}, indent=2), encoding="utf-8")
    return len(cleaned)


def native_binary_context(root: Path) -> list[dict[str, Any]]:
    try:
        import lief
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for lib in sorted(root.rglob("*.so"))[:120]:
        try:
            binary = lief.parse(str(lib))
            if binary is None:
                continue
            header = getattr(binary, "header", None)
            out.append({
                "file": str(lib.relative_to(root)),
                "format": type(binary).__name__,
                "machine": str(getattr(header, "machine_type", "")),
                "is_pie": getattr(binary, "is_pie", None),
                "has_nx": getattr(binary, "has_nx", None),
                "import_count": len(getattr(binary, "imported_functions", []) or []),
                "export_count": len(getattr(binary, "exported_functions", []) or []),
                "reportability": "binary_context_only_unless_direct_Minly_exploit_is_demonstrated",
            })
        except Exception:
            continue
    return out


def android_audit(apk: Path, out: Path, expected_package: str) -> dict[str, Any]:
    decoded = out / "decoded"
    jadx_out = out / "jadx"
    decoded.mkdir(parents=True, exist_ok=True)
    toolchain: dict[str, Any] = {}

    toolchain["aapt_badging"] = run(["aapt", "dump", "badging", str(apk)])
    badging = toolchain["aapt_badging"].get("stdout", "")
    package_match = re.search(r"package: name='([^']+)'", badging)
    package = package_match.group(1) if package_match else None
    if package and package != expected_package:
        raise SystemExit(f"APK package mismatch: expected {expected_package}, got {package}")

    toolchain["apksigner"] = run(["apksigner", "verify", "--verbose", "--print-certs", str(apk)])
    toolchain["apktool"] = run(["apktool", "d", "-f", "-s", "-o", str(decoded), str(apk)], timeout=600)
    toolchain["jadx"] = run(["jadx", "--deobf", "--show-bad-code", "-d", str(jadx_out), str(apk)], timeout=1200)

    scan_root = jadx_out if jadx_out.exists() and any(jadx_out.iterdir()) else decoded

    mobsf_raw = out / "mobsfscan.raw.json"
    semgrep_raw = out / "semgrep.raw.json"
    ds_raw = out / "detect-secrets.raw.json"
    gitleaks_raw = out / "gitleaks.raw.json"
    trivy_raw = out / "trivy.raw.json"

    toolchain["mobsfscan"] = run([
        "mobsfscan", "--json", "--no-fail", "--type", "android", "-o", str(mobsf_raw), str(scan_root)
    ], timeout=1200)
    toolchain["semgrep"] = run([
        "semgrep", "scan", "--config", "auto", "--json", "--output", str(semgrep_raw), str(scan_root)
    ], timeout=1200)
    toolchain["detect_secrets"] = run([
        "detect-secrets", "scan", "--all-files", str(scan_root)
    ], timeout=900)
    if toolchain["detect_secrets"].get("stdout"):
        ds_raw.write_text(toolchain["detect_secrets"].pop("stdout"), encoding="utf-8")

    toolchain["gitleaks"] = run([
        "gitleaks", "dir", str(scan_root), "--redact", "--report-format", "json",
        "--report-path", str(gitleaks_raw), "--no-banner"
    ], timeout=900)

    toolchain["trivy"] = run([
        "trivy", "fs", "--scanners", "vuln,misconfig", "--format", "json", "--output", str(trivy_raw), str(scan_root)
    ], timeout=1200)

    candidate_counts = {
        "mobsfscan": sanitize_mobsfscan(mobsf_raw, out / "mobsfscan-candidates.json") if mobsf_raw.exists() else 0,
        "semgrep": sanitize_semgrep(semgrep_raw, out / "semgrep-candidates.json") if semgrep_raw.exists() else 0,
        "detect_secrets": sanitize_detect_secrets(ds_raw, out / "secret-pattern-candidates.json") if ds_raw.exists() else 0,
        "gitleaks": sanitize_gitleaks(gitleaks_raw, out / "gitleaks-candidates.json") if gitleaks_raw.exists() else 0,
        "trivy": sanitize_trivy(trivy_raw, out / "dependency-context.json") if trivy_raw.exists() else 0,
    }
    for raw in (mobsf_raw, semgrep_raw, ds_raw, gitleaks_raw, trivy_raw):
        raw.unlink(missing_ok=True)

    native_context = native_binary_context(decoded)
    (out / "native-binary-context.json").write_text(
        json.dumps({"count": len(native_context), "results": native_context}, indent=2), encoding="utf-8"
    )

    urls = collect_urls(scan_root)
    candidates = collect_sensitive_markers(scan_root)
    return {
        "platform": "android",
        "target": "Minly Android App",
        "expected_package": expected_package,
        "observed_package": package,
        "artifact_sha256": sha256(apk),
        "artifact_size": apk.stat().st_size,
        "scan_root": "jadx" if scan_root == jadx_out else "apktool",
        "toolchain": toolchain,
        "candidate_counts": candidate_counts,
        "observed_urls": urls,
        "candidate_markers": candidates,
        "native_binary_count": len(native_context),
        "verification_status": "UNVERIFIED_STATIC_CANDIDATES_ONLY",
        "reporting_rule": "No static-tool result is a reportable vulnerability without manual proof of exploitability and impact.",
    }


def ios_audit(ipa: Path, out: Path, expected_bundle_id: str | None) -> dict[str, Any]:
    extracted = out / "extracted"
    extracted.mkdir(parents=True, exist_ok=True)
    safe_extract_zip(ipa, extracted)
    apps = list((extracted / "Payload").glob("*.app"))
    if len(apps) != 1:
        raise SystemExit(f"expected one .app in IPA, found {len(apps)}")
    app = apps[0]
    info_path = app / "Info.plist"
    if not info_path.exists():
        raise SystemExit("IPA missing Info.plist")
    with info_path.open("rb") as fh:
        info = plistlib.load(fh)
    bundle_id = info.get("CFBundleIdentifier")
    executable = info.get("CFBundleExecutable")
    if expected_bundle_id and bundle_id != expected_bundle_id:
        raise SystemExit(f"iOS bundle mismatch: expected {expected_bundle_id}, got {bundle_id}")

    toolchain: dict[str, Any] = {}
    toolchain["codesign"] = run(["codesign", "-dvv", str(app)])
    toolchain["entitlements"] = run(["codesign", "-d", "--entitlements", ":-", str(app)])
    binary = app / executable if executable else None
    if binary and binary.exists():
        toolchain["otool"] = run(["otool", "-l", str(binary)], timeout=300)
        toolchain["nm"] = run(["nm", "-u", str(binary)], timeout=300)
        toolchain["strings"] = run(["strings", "-a", str(binary)], timeout=300)
        if toolchain["strings"].get("stdout"):
            (out / "binary-strings.txt").write_text(toolchain["strings"].pop("stdout"), encoding="utf-8")
    else:
        for name in ("otool", "nm", "strings"):
            toolchain[name] = {"status": "SKIPPED", "reason": "main executable not resolved"}

    semgrep_raw = out / "semgrep.raw.json"
    ds_raw = out / "detect-secrets.raw.json"
    gitleaks_raw = out / "gitleaks.raw.json"
    toolchain["semgrep"] = run([
        "semgrep", "scan", "--config", "auto", "--json", "--output", str(semgrep_raw), str(app)
    ], timeout=1200)
    toolchain["detect_secrets"] = run(["detect-secrets", "scan", "--all-files", str(app)], timeout=900)
    if toolchain["detect_secrets"].get("stdout"):
        ds_raw.write_text(toolchain["detect_secrets"].pop("stdout"), encoding="utf-8")
    toolchain["gitleaks"] = run([
        "gitleaks", "dir", str(app), "--redact", "--report-format", "json",
        "--report-path", str(gitleaks_raw), "--no-banner"
    ], timeout=900)

    candidate_counts = {
        "semgrep": sanitize_semgrep(semgrep_raw, out / "semgrep-candidates.json") if semgrep_raw.exists() else 0,
        "detect_secrets": sanitize_detect_secrets(ds_raw, out / "secret-pattern-candidates.json") if ds_raw.exists() else 0,
        "gitleaks": sanitize_gitleaks(gitleaks_raw, out / "gitleaks-candidates.json") if gitleaks_raw.exists() else 0,
    }
    for raw in (semgrep_raw, ds_raw, gitleaks_raw):
        raw.unlink(missing_ok=True)

    lief_context: dict[str, Any] = {}
    if binary and binary.exists():
        try:
            import lief
            parsed = lief.parse(str(binary))
            if parsed is not None:
                header = getattr(parsed, "header", None)
                lief_context = {
                    "format": type(parsed).__name__,
                    "cpu_type": str(getattr(header, "cpu_type", "")),
                    "pie": getattr(parsed, "is_pie", None),
                    "nx": getattr(parsed, "has_nx", None),
                }
        except Exception:
            lief_context = {}
    (out / "lief-binary-context.json").write_text(json.dumps(lief_context, indent=2), encoding="utf-8")

    urls = collect_urls(app)
    candidates = collect_sensitive_markers(app)
    return {
        "platform": "ios",
        "target": "Minly iOS App",
        "app_store_id": "1528802350",
        "observed_bundle_id": bundle_id,
        "expected_bundle_id": expected_bundle_id,
        "artifact_sha256": sha256(ipa),
        "artifact_size": ipa.stat().st_size,
        "info_plist": {
            "CFBundleIdentifier": bundle_id,
            "CFBundleShortVersionString": info.get("CFBundleShortVersionString"),
            "CFBundleVersion": info.get("CFBundleVersion"),
            "CFBundleURLTypes": info.get("CFBundleURLTypes", []),
        },
        "toolchain": toolchain,
        "candidate_counts": candidate_counts,
        "observed_urls": urls,
        "candidate_markers": candidates,
        "lief_binary_context": lief_context,
        "verification_status": "UNVERIFIED_STATIC_CANDIDATES_ONLY",
        "reporting_rule": "No static-tool result is a reportable vulnerability without manual proof of exploitability and impact.",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline static audit family for researcher-supplied or provenance-checked Minly mobile artifacts")
    ap.add_argument("--platform", choices=["android", "ios"], required=True)
    ap.add_argument("--artifact", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--expected-package", default="com.minly.users")
    ap.add_argument("--expected-bundle-id", default="")
    args = ap.parse_args()
    if not args.artifact.is_file():
        raise SystemExit(f"artifact not found: {args.artifact}")
    args.output.mkdir(parents=True, exist_ok=True)
    if args.platform == "android":
        summary = android_audit(args.artifact, args.output, args.expected_package)
    else:
        summary = ios_audit(args.artifact, args.output, args.expected_bundle_id or None)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print(json.dumps({
        "platform": summary["platform"],
        "verification_status": summary["verification_status"],
        "candidate_counts": summary.get("candidate_counts", {}),
        "tool_status": {k: v.get("status") for k, v in summary["toolchain"].items()},
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
