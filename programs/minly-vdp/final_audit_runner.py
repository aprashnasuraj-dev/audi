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

    if temp_js.exists():
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
    else:
        manifest["families"]["offline-semgrep"] = {"status": "SKIPPED", "reason": "no naturally observed same-origin JavaScript"}
        manifest["families"]["offline-secret-patterns"] = {"status": "SKIPPED", "reason": "no naturally observed same-origin JavaScript"}

    for p in [semgrep_raw, ds_raw]:
        p.unlink(missing_ok=True)
    shutil.rmtree(temp_js, ignore_errors=True)

    manifest["families"]["api-contract"] = {"status": "SKIPPED", "reason": "no OpenAPI contract supplied"}
    manifest["families"]["graphql-schema"] = {"status": "SKIPPED", "reason": "no GraphQL schema supplied"}
    manifest["families"]["container"] = {"status": "SKIPPED", "reason": "no authorized container image supplied"}
    manifest["families"]["iac"] = {"status": "SKIPPED", "reason": "no authorized IaC/source artifact supplied"}
    manifest["families"]["cross-account-runtime"] = {
        "status": "SKIPPED",
        "reason": "requires a second researcher-controlled account; never substitute another user's identity",
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
    return run(cmd, check=False).returncode


def compile_phase(args: argparse.Namespace) -> int:
    scope_gate()
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
    ap.add_argument("--phase", choices=["web", "android", "ios", "compile"], required=True)
    ap.add_argument("--output", type=Path, default=REPO / "artifacts" / "minly-final")
    ap.add_argument("--artifact", type=Path)
    ap.add_argument("--expected-bundle-id", default="")
    ap.add_argument("--manual-findings", type=Path)
    ap.add_argument("--max-pages", type=int, default=12)
    ap.add_argument("--request-budget", type=int, default=80)
    ap.add_argument("--delay-ms", type=int, default=1200)
    args = ap.parse_args()
    if args.max_pages > 20 or args.request_budget > 120 or args.delay_ms < 750:
        ap.error("unsafe web limits: max_pages<=20, request_budget<=120, delay_ms>=750")
    if args.phase in {"android", "ios"} and not args.artifact:
        ap.error("--artifact is required for mobile phases")
    return args


def main() -> int:
    args = parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.phase == "web":
        return web_phase(args)
    if args.phase in {"android", "ios"}:
        return mobile_phase(args)
    return compile_phase(args)


if __name__ == "__main__":
    raise SystemExit(main())
