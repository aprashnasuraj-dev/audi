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
import sys
import zipfile
from pathlib import Path
from typing import Any

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
SENSITIVE_WORDS = re.compile(r"(?i)(token|secret|api[_-]?key|authorization|password|bearer)")


def run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 300) -> dict[str, Any]:
    exe = shutil.which(cmd[0])
    if not exe:
        return {"status": "SKIPPED", "reason": f"{cmd[0]} not installed", "command": cmd}
    try:
        cp = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"status": "TIMEOUT", "command": cmd}
    return {
        "status": "RAN" if cp.returncode == 0 else "COMPLETED_NONZERO",
        "returncode": cp.returncode,
        "command": cmd,
        "stdout": cp.stdout[-20000:],
        "stderr": cp.stderr[-10000:],
    }


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
            if p.is_file() and p.stat().st_size <= max_size:
                yield p
        except OSError:
            continue


def redact_url(url: str) -> str:
    return url.split("?", 1)[0].split("#", 1)[0]


def collect_urls(root: Path) -> list[str]:
    out: set[str] = set()
    for p in text_files(root):
        try:
            data = p.read_text(errors="ignore")
        except OSError:
            continue
        for match in URL_RE.findall(data):
            out.add(redact_url(match)[:500])
    return sorted(out)[:1000]


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
    toolchain["jadx"] = run(["jadx", "--deobf", "-d", str(jadx_out), str(apk)], timeout=900)

    scan_root = jadx_out if jadx_out.exists() and any(jadx_out.iterdir()) else decoded
    toolchain["mobsfscan"] = run(["mobsfscan", "--json", "-o", str(out / "mobsfscan.json"), str(scan_root)], timeout=900)
    toolchain["semgrep"] = run([
        "semgrep", "scan", "--config", "auto", "--json", "--output", str(out / "semgrep.json"), str(scan_root)
    ], timeout=900)
    toolchain["detect_secrets"] = run([
        "detect-secrets", "scan", "--all-files", str(scan_root)
    ], timeout=600)
    if toolchain["detect_secrets"].get("stdout"):
        (out / "detect-secrets.json").write_text(toolchain["detect_secrets"]["stdout"], encoding="utf-8")
        toolchain["detect_secrets"].pop("stdout", None)

    urls = collect_urls(scan_root)
    candidates = collect_sensitive_markers(scan_root)
    return {
        "platform": "android",
        "target": "Minly Android App",
        "expected_package": expected_package,
        "observed_package": package,
        "artifact_sha256": sha256(apk),
        "artifact_size": apk.stat().st_size,
        "toolchain": toolchain,
        "observed_urls": urls,
        "candidate_markers": candidates,
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
            (out / "binary-strings.txt").write_text(toolchain["strings"]["stdout"], encoding="utf-8")
            toolchain["strings"].pop("stdout", None)
    else:
        for name in ("otool", "nm", "strings"):
            toolchain[name] = {"status": "SKIPPED", "reason": "main executable not resolved"}

    toolchain["semgrep"] = run([
        "semgrep", "scan", "--config", "auto", "--json", "--output", str(out / "semgrep.json"), str(app)
    ], timeout=900)
    toolchain["detect_secrets"] = run([
        "detect-secrets", "scan", "--all-files", str(app)
    ], timeout=600)
    if toolchain["detect_secrets"].get("stdout"):
        (out / "detect-secrets.json").write_text(toolchain["detect_secrets"]["stdout"], encoding="utf-8")
        toolchain["detect_secrets"].pop("stdout", None)

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
        "observed_urls": urls,
        "candidate_markers": candidates,
        "verification_status": "UNVERIFIED_STATIC_CANDIDATES_ONLY",
        "reporting_rule": "No static-tool result is a reportable vulnerability without manual proof of exploitability and impact.",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline static audit family for researcher-supplied Minly mobile artifacts")
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
        "tool_status": {k: v.get("status") for k, v in summary["toolchain"].items()},
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
