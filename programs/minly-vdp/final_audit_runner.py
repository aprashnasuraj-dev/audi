#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
PROGRAM = REPO / "programs" / "minly-vdp"


def run(cmd: list[str], *, check: bool = True, cwd: Path = REPO, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(cmd))
    cp = subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True)
    if cp.stdout:
        print(cp.stdout)
    if cp.stderr:
        print(cp.stderr, file=sys.stderr)
    if check and cp.returncode != 0:
        raise SystemExit(cp.returncode)
    return cp


def json_load(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def scope_gate() -> dict[str, Any]:
    import yaml
    scope = yaml.safe_load((PROGRAM / "scope.yml").read_text(encoding="utf-8"))
    web = scope["in_scope"]["website"]
    assert len(web) == 1
    assert web[0]["url"] == "https://minly.com/"
    assert web[0]["exact_hosts"] == ["minly.com"]
    assert scope["in_scope"]["android"][0]["package"] == "com.minly.users"
    assert scope["in_scope"]["ios"][0]["app_store_id"] == "1528802350"
    assert scope["account_policy"]["own_accounts_only"] is True
    assert scope["account_policy"]["access_other_user_data"] == "forbidden"
    assert "high_volume_automated_scanning" in scope["prohibited_actions"]
    return scope


def sanitize_semgrep(raw_path: Path, out_path: Path) -> int:
    raw = json_load(raw_path, {"results": []})
    cleaned = []
    for r in raw.get("results", []):
        cleaned.append({
            "check_id": r.get("check_id"),
            "path": Path(r.get("path", "")).name,
            "start_line": (r.get("start") or {}).get("line"),
            "end_line": (r.get("end") or {}).get("line"),
            "message": ((r.get("extra") or {}).get("message") or "")[:240],
            "severity": ((r.get("extra") or {}).get("severity") or "INFO"),
            "candidate_only": True,
            "manual_validation_required": True,
        })
    out_path.write_text(json.dumps({"candidate_count": len(cleaned), "results": cleaned}, indent=2), encoding="utf-8")
    return len(cleaned)


def sanitize_detect_secrets(raw_path: Path, out_path: Path) -> int:
    raw = json_load(raw_path, {"results": {}})
    cleaned = []
    for filename, findings in (raw.get("results") or {}).items():
        for f in findings:
            cleaned.append({
                "file": Path(filename).name,
                "line_number": f.get("line_number"),
                "type": f.get("type"),
                "hashed_secret": f.get("hashed_secret"),
                "candidate_only": True,
                "manual_validation_required": True,
            })
    out_path.write_text(json.dumps({"candidate_count": len(cleaned), "results": cleaned}, indent=2), encoding="utf-8")
    return len(cleaned)


def sanitize_gitleaks(raw_path: Path, out_path: Path) -> int:
    raw = json_load(raw_path, [])
    if not isinstance(raw, list):
        raw = []
    cleaned = []
    for f in raw:
        if not isinstance(f, dict):
            continue
        cleaned.append({
            "rule_id": f.get("RuleID") or f.get("rule_id"),
            "description": f.get("Description") or f.get("description"),
            "file": Path(str(f.get("File") or f.get("file") or "")).name,
            "start_line": f.get("StartLine") or f.get("start_line"),
            "tags": f.get("Tags") or f.get("tags") or [],
            "fingerprint": f.get("Fingerprint") or f.get("fingerprint"),
            "candidate_only": True,
            "manual_validation_required": True,
        })
    out_path.write_text(json.dumps({"candidate_count": len(cleaned), "results": cleaned}, indent=2), encoding="utf-8")
    return len(cleaned)


def web_phase(args: argparse.Namespace) -> int:
    scope_gate()
    out = args.output / "web"
    halo_out = out / "halo"
    passive_out = out / "passive"
    out.mkdir(parents=True, exist_ok=True)
    storage_state = os.environ.get("HALO_MINLY_USER_STORAGE_STATE", "").strip()

    manifest: dict[str, Any] = {
        "phase": "web",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "scope": {"url": "https://minly.com/", "exact_host": "minly.com"},
        "identity_mode": "researcher-storage-state" if storage_state else "anonymous",
        "families": {},
    }

    halo_cmd = [
        sys.executable, "scripts/run-audit.py",
        "--targets", str(PROGRAM / "halo-targets.yml"),
        "--identities", str(PROGRAM / "halo-identities.yml"),
        "--target", "minly-web",
        "--output", str(halo_out),
    ]
    cp = run(halo_cmd, check=False)
    manifest["families"]["halo-web"] = {"status": "RAN" if cp.returncode == 0 else "FAILED", "returncode": cp.returncode}
    if cp.returncode != 0:
        (out / "family-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return cp.returncode

    passive_cmd = [
        sys.executable, str(PROGRAM / "minly_passive_map.py"),
        "--output", str(passive_out),
        "--max-pages", str(args.max_pages),
        "--request-budget", str(args.request_budget),
        "--delay-ms", str(args.delay_ms),
        "--settle-ms", "900",
    ]
    if storage_state:
        passive_cmd += ["--storage-state", storage_state]
    run(passive_cmd)
    manifest["families"]["passive-browser-map"] = {"status": "RAN", "identity_mode": manifest["identity_mode"]}

    temp_js = passive_out / "_temp_js"
    semgrep_raw = passive_out / "semgrep-raw.json"
    semgrep_clean = passive_out / "semgrep-candidates.json"
    ds_raw = passive_out / "detect-secrets-raw.json"
    ds_clean = passive_out / "secret-pattern-candidates.json"
    gitleaks_raw = passive_out / "gitleaks-raw.json"
    gitleaks_clean = passive_out / "gitleaks-candidates.json"
    retire_out = passive_out / "retire-dependency-context.json"

    if temp_js.exists() and any(temp_js.rglob("*.js")):
        cp = run([
            "semgrep", "scan", "--config", str(PROGRAM / "semgrep" / "minly-client.yml"),
            "--json", "--output", str(semgrep_raw), str(temp_js)
        ], check=False)
        count = sanitize_semgrep(semgrep_raw, semgrep_clean)
        manifest["families"]["offline-semgrep"] = {"status": "RAN", "candidate_count": count, "returncode": cp.returncode}

        cp = run(["detect-secrets", "scan", "--all-files", str(temp_js)], check=False)
        ds_raw.write_text(cp.stdout or "{}", encoding="utf-8")
        count = sanitize_detect_secrets(ds_raw, ds_clean)
        manifest["families"]["offline-secret-patterns"] = {"status": "RAN", "candidate_count": count, "returncode": cp.returncode}

        if shutil.which("gitleaks"):
            cp = run([
                "gitleaks", "dir", str(temp_js), "--redact", "--report-format", "json",
                "--report-path", str(gitleaks_raw), "--no-banner"
            ], check=False)
            count = sanitize_gitleaks(gitleaks_raw, gitleaks_clean) if gitleaks_raw.exists() else 0
            manifest["families"]["offline-gitleaks"] = {"status": "RAN", "candidate_count": count, "returncode": cp.returncode}
        else:
            manifest["families"]["offline-gitleaks"] = {"status": "SKIPPED", "reason": "gitleaks not installed"}

        if shutil.which("retire"):
            cp = run([
                "retire", "--path", str(temp_js), "--outputformat", "json", "--outputpath", str(retire_out), "--exitwith", "0"
            ], check=False)
            manifest["families"]["offline-retirejs"] = {
                "status": "RAN" if retire_out.exists() else "COMPLETED_NO_REPORT",
                "returncode": cp.returncode,
                "reportability": "dependency_context_only_until_concrete_Minly_impact_is_demonstrated",
            }
        else:
            manifest["families"]["offline-retirejs"] = {"status": "SKIPPED", "reason": "retire not installed"}
    else:
        for family in ("offline-semgrep", "offline-secret-patterns", "offline-gitleaks", "offline-retirejs"):
            manifest["families"][family] = {"status": "SKIPPED", "reason": "no naturally observed same-origin JavaScript"}

    for p in [semgrep_raw, ds_raw, gitleaks_raw]:
        p.unlink(missing_ok=True)
    shutil.rmtree(temp_js, ignore_errors=True)

    manifest["families"]["api-contract"] = {"status": "SKIPPED", "reason": "no naturally observed or researcher-supplied OpenAPI contract"}
    manifest["families"]["graphql-schema"] = {"status": "SKIPPED", "reason": "no naturally observed or researcher-supplied GraphQL schema"}
    manifest["families"]["container"] = {"status": "SKIPPED", "reason": "no authorized container image supplied"}
    manifest["families"]["iac"] = {"status": "SKIPPED", "reason": "no authorized IaC/source artifact supplied"}
    manifest["families"]["cross-account-runtime"] = {
        "status": "SKIPPED",
        "reason": "requires a second researcher-controlled account; never substitute another user's identity",
    }
    manifest["families"]["active-high-volume-scanners"] = {
        "status": "POLICY_EXCLUDED",
        "tools": ["nuclei", "ffuf", "gobuster", "dirsearch", "feroxbuster", "active-zap", "sqlmap"],
        "reason": "Minly prohibits high-volume automated scanning and scanner-only findings; these are intentionally not wired into the live runner.",
    }
    manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
    (out / "family-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return 0


def mobile_phase(args: argparse.Namespace) -> int:
    scope_gate()
    platform = args.phase
    out = args.output / platform
    cmd = [
        sys.executable, str(PROGRAM / "mobile_static_audit.py"),
        "--platform", platform,
        "--artifact", str(args.artifact),
        "--output", str(out),
    ]
    if platform == "android":
        cmd += ["--expected-package", "com.minly.users"]
    if platform == "ios" and args.expected_bundle_id:
        cmd += ["--expected-bundle-id", args.expected_bundle_id]
    rc = run(cmd, check=False).returncode
    if rc != 0:
        return rc
    inspect_out = out / "artifact-inspection.json"
    inspect_cmd = [
        sys.executable, str(PROGRAM / "mobile_artifact_inspect.py"),
        "--platform", platform,
        "--artifact", str(args.artifact),
        "--output", str(inspect_out),
    ]
    return run(inspect_cmd, check=False).returncode


def android_public_phase(args: argparse.Namespace) -> int:
    scope_gate()
    out = args.output / "android"
    out.mkdir(parents=True, exist_ok=True)
    work = args.workdir or Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "minly-public-android"
    provenance = out / "public-provenance.json"
    cp = run([
        sys.executable, str(PROGRAM / "public_mobile_fallback.py"), "android",
        "--workdir", str(work), "--output", str(provenance)
    ], check=False)
    if cp.returncode != 0:
        return cp.returncode
    apk = work / "com.minly.users.apk"
    if not apk.is_file():
        raise SystemExit("public Android acquisition did not materialize the expected base APK")
    mobile_args = argparse.Namespace(phase="android", output=args.output, artifact=apk, expected_bundle_id="")
    rc = mobile_phase(mobile_args)
    if rc != 0:
        return rc
    summary_path = out / "summary.json"
    summary = json_load(summary_path, {})
    summary["status"] = "RAN_PUBLIC_MIRROR_STATIC"
    summary["artifact_provenance"] = json_load(provenance, {})
    summary["provenance_limitation"] = (
        "Public mirror artifact; package and signing certificate are verified, including Digital Asset Links when available. "
        "The runner does not claim byte-for-byte identity with Google Play delivery."
    )
    summary_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    return 0


def ios_public_phase(args: argparse.Namespace) -> int:
    scope_gate()
    out = args.output / "ios"
    out.mkdir(parents=True, exist_ok=True)
    return run([
        sys.executable, str(PROGRAM / "public_mobile_fallback.py"), "ios",
        "--output", str(out / "summary.json")
    ], check=False).returncode


def rank_phase(args: argparse.Namespace) -> int:
    scope_gate()
    return run([
        sys.executable, str(PROGRAM / "candidate_ranker.py"),
        "--root", str(args.output), "--output", str(args.output / "candidate-review")
    ], check=False).returncode


def compile_phase(args: argparse.Namespace) -> int:
    scope_gate()
    rank_phase(args)
    cmd = [
        sys.executable, str(PROGRAM / "final_report_maker.py"),
        "--root", str(args.output),
        "--output", str(args.output / "final-report"),
    ]
    if args.manual_findings and args.manual_findings.is_file():
        cmd += ["--manual-findings", str(args.manual_findings)]
    return run(cmd, check=False).returncode


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Minly VDP final audit family runner")
    ap.add_argument(
        "--phase",
        choices=["web", "android", "ios", "android-public", "ios-public", "rank", "compile"],
        required=True,
    )
    ap.add_argument("--output", type=Path, default=REPO / "artifacts" / "minly-final")
    ap.add_argument("--artifact", type=Path)
    ap.add_argument("--workdir", type=Path)
    ap.add_argument("--expected-bundle-id", default="")
    ap.add_argument("--manual-findings", type=Path)
    ap.add_argument("--max-pages", type=int, default=12)
    ap.add_argument("--request-budget", type=int, default=80)
    ap.add_argument("--delay-ms", type=int, default=1200)
    args = ap.parse_args()
    if args.max_pages > 20 or args.request_budget > 120 or args.delay_ms < 750:
        ap.error("unsafe web limits: max_pages<=20, request_budget<=120, delay_ms>=750")
    if args.phase in {"android", "ios"} and not args.artifact:
        ap.error("--artifact is required for private mobile artifact phases")
    return args


def main() -> int:
    args = parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.phase == "web":
        return web_phase(args)
    if args.phase in {"android", "ios"}:
        return mobile_phase(args)
    if args.phase == "android-public":
        return android_public_phase(args)
    if args.phase == "ios-public":
        return ios_public_phase(args)
    if args.phase == "rank":
        return rank_phase(args)
    return compile_phase(args)


if __name__ == "__main__":
    raise SystemExit(main())
