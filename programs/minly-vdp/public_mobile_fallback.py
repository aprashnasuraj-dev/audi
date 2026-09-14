#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

ANDROID_PACKAGE = "com.minly.users"
ANDROID_XAPK_URL = "https://d.apkpure.com/b/XAPK/com.minly.users?version=latest"
# Historical Minly signing-certificate SHA-1 fingerprint independently listed by APKPure
# for multiple Minly releases. This is a provenance check, not proof that the mirror is
# identical to the current Google Play artifact.
ANDROID_KNOWN_CERT_SHA1 = "a4392186690e3146ba2c64064d75bb5f97110f95"
IOS_APP_STORE_ID = "1528802350"
IOS_LOOKUP_URL = f"https://itunes.apple.com/lookup?id={IOS_APP_STORE_ID}&country=us"
APPLE_AASA_CDN = "https://app-site-association.cdn-apple.com/a/v1/minly.com"
GOOGLE_DAL_URL = (
    "https://digitalassetlinks.googleapis.com/v1/statements:list?"
    "source.web.site=https%3A%2F%2Fminly.com&"
    "relation=delegate_permission%2Fcommon.handle_all_urls"
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path, *, max_bytes: int, ua: str) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise SystemExit(f"unsafe download URL: {url}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=120) as response, dest.open("wb") as fh:
        final_url = response.geturl()
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            fh.write(chunk)
            if fh.tell() > max_bytes:
                fh.close()
                dest.unlink(missing_ok=True)
                raise SystemExit(f"download exceeded safety limit: {max_bytes} bytes")
    return {
        "requested_url": url,
        "final_url_host": urllib.parse.urlsplit(final_url).hostname,
        "bytes": dest.stat().st_size,
        "sha256": sha256(dest),
    }


def run(cmd: list[str], timeout: int = 180) -> subprocess.CompletedProcess[str]:
    if not shutil.which(cmd[0]):
        raise SystemExit(f"required executable not installed: {cmd[0]}")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def parse_cert_digest(apksigner_output: str, algorithm: str) -> str | None:
    pattern = rf"certificate {re.escape(algorithm)} digest:\s*([0-9A-Fa-f:]+)"
    m = re.search(pattern, apksigner_output, flags=re.I)
    if not m:
        return None
    return re.sub(r"[^0-9a-f]", "", m.group(1).lower())


def safe_xapk_extract(xapk: Path, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    apks: list[Path] = []
    with zipfile.ZipFile(xapk) as zf:
        for info in zf.infolist():
            if not info.filename.lower().endswith(".apk"):
                continue
            name = Path(info.filename).name
            target = (out_dir / name).resolve()
            if not str(target).startswith(str(out_dir.resolve()) + os.sep):
                raise SystemExit(f"unsafe archive member: {info.filename}")
            with zf.open(info) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            apks.append(target)
    if not apks:
        raise SystemExit("XAPK contained no APK files")
    return apks


def aapt_badging(apk: Path) -> dict[str, Any]:
    cp = run(["aapt", "dump", "badging", str(apk)])
    if cp.returncode != 0:
        raise SystemExit(f"aapt failed for {apk.name}: {cp.stderr[-1000:]}")
    package = re.search(r"package: name='([^']+)'", cp.stdout)
    version_code = re.search(r"versionCode='([^']+)'", cp.stdout)
    version_name = re.search(r"versionName='([^']+)'", cp.stdout)
    return {
        "package": package.group(1) if package else None,
        "version_code": version_code.group(1) if version_code else None,
        "version_name": version_name.group(1) if version_name else None,
    }


def fetch_json(url: str, *, timeout: int = 30) -> tuple[dict[str, Any] | list[Any] | None, dict[str, Any]]:
    req = urllib.request.Request(url, headers={"User-Agent": "Minly-VDP-public-metadata/1.0", "Accept": "application/json,*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read(2_000_000)
            meta = {
                "http_status": getattr(response, "status", None),
                "final_url_host": urllib.parse.urlsplit(response.geturl()).hostname,
                "bytes": len(raw),
            }
        return json.loads(raw.decode("utf-8")), meta
    except Exception as exc:
        return None, {"status": "UNAVAILABLE", "reason": f"{type(exc).__name__}: {exc}"}


def _append_fingerprints(out: list[str], value: Any) -> None:
    if isinstance(value, str) and value.strip():
        out.append(value.strip())
    elif isinstance(value, list):
        out.extend(str(x).strip() for x in value if str(x).strip())


def android(args: argparse.Namespace) -> int:
    work = args.workdir.resolve()
    out = args.output.resolve()
    work.mkdir(parents=True, exist_ok=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    xapk = work / "minly-latest.xapk"
    download_meta = download(
        args.xapk_url,
        xapk,
        max_bytes=650 * 1024 * 1024,
        ua="Minly-VDP-public-Android-acquisition/1.0",
    )
    apks = safe_xapk_extract(xapk, work / "apks")

    candidates: list[tuple[Path, dict[str, Any]]] = []
    for apk in apks:
        try:
            info = aapt_badging(apk)
        except SystemExit:
            continue
        if info.get("package") == ANDROID_PACKAGE:
            candidates.append((apk, info))
    if not candidates:
        raise SystemExit(f"no base APK with package {ANDROID_PACKAGE!r} was found")

    # The base package APK is normally the largest package-bearing member.
    base, info = max(candidates, key=lambda pair: pair[0].stat().st_size)
    canonical = work / f"{ANDROID_PACKAGE}.apk"
    if base.resolve() != canonical.resolve():
        shutil.copy2(base, canonical)
    base = canonical

    signer = run(["apksigner", "verify", "--verbose", "--print-certs", str(base)])
    if signer.returncode != 0:
        raise SystemExit(f"apksigner verification failed: {signer.stderr[-1500:]}")
    cert_sha1 = parse_cert_digest(signer.stdout + "\n" + signer.stderr, "SHA-1")
    cert_sha256 = parse_cert_digest(signer.stdout + "\n" + signer.stderr, "SHA-256")
    if not cert_sha1:
        raise SystemExit("could not extract Android signing-certificate SHA-1")
    if cert_sha1 != args.expected_cert_sha1.lower():
        raise SystemExit(
            "mirror artifact signing certificate did not match the configured Minly provenance fingerprint: "
            f"observed={cert_sha1} expected={args.expected_cert_sha1.lower()}"
        )

    # Cross-check the signing SHA-256 against Google's Digital Asset Links service for
    # minly.com. The API currently returns sha256Fingerprint as a scalar string; older
    # or alternate representations may return a list, so handle both without extending
    # a string into individual characters.
    dal, dal_meta = fetch_json(GOOGLE_DAL_URL)
    official_dal_fingerprints: list[str] = []
    if isinstance(dal, dict):
        for statement in dal.get("statements", []) or []:
            if not isinstance(statement, dict):
                continue
            target = statement.get("target") or {}
            android_app = target.get("androidApp") or {}
            if android_app.get("packageName") == ANDROID_PACKAGE:
                certificate = android_app.get("certificate") or {}
                _append_fingerprints(official_dal_fingerprints, certificate.get("sha256Fingerprint"))
                _append_fingerprints(official_dal_fingerprints, certificate.get("sha256Fingerprints"))
            if target.get("packageName") == ANDROID_PACKAGE:
                _append_fingerprints(official_dal_fingerprints, target.get("sha256CertFingerprints"))

    normalized_dal = {
        re.sub(r"[^0-9a-f]", "", value.lower())
        for value in official_dal_fingerprints
        if value
    }
    normalized_dal.discard("")
    dal_matches_cert = cert_sha256 in normalized_dal if cert_sha256 and normalized_dal else None
    if normalized_dal and cert_sha256 and not dal_matches_cert:
        raise SystemExit(
            "public Android artifact certificate did not match minly.com's published Digital Asset Links certificate: "
            f"observed={cert_sha256} published={sorted(normalized_dal)}"
        )

    result = {
        "platform": "android",
        "status": "ACQUIRED_PUBLIC_MIRROR_VERIFIED_PACKAGE_AND_CERT",
        "target_package": ANDROID_PACKAGE,
        "artifact_source": {
            "type": "public_mirror",
            "provider": "APKPure",
            "warning": (
                "This is a third-party mirror artifact, not a byte-for-byte Google Play export. "
                "Package identity and signing certificate are verified before analysis; provenance remains explicitly labeled."
            ),
            **download_meta,
        },
        "base_apk": {
            **info,
            "sha256": sha256(base),
            "bytes": base.stat().st_size,
            "signing_cert_sha1": cert_sha1,
            "signing_cert_sha256": cert_sha256,
            "known_cert_sha1_match": True,
        },
        "google_digital_asset_links": {
            "fetch": dal_meta,
            "published_sha256_fingerprints": sorted(set(official_dal_fingerprints)),
            "observed_cert_matches_published_sha256": dal_matches_cert,
        },
        "xapk_apk_members": [p.name for p in apks],
        "analysis_rule": "Static findings remain unverified until a concrete, reproducible impact is demonstrated within the VDP scope.",
    }
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({
        "status": result["status"],
        "version_name": info.get("version_name"),
        "version_code": info.get("version_code"),
        "xapk_sha256": download_meta["sha256"],
        "base_apk_sha256": result["base_apk"]["sha256"],
        "cert_sha1": cert_sha1,
        "cert_sha256": cert_sha256,
        "digital_asset_link_cert_match": dal_matches_cert,
        "base_apk_path": str(base),
    }, indent=2))
    return 0


def ios(args: argparse.Namespace) -> int:
    out = args.output.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    lookup, lookup_meta = fetch_json(IOS_LOOKUP_URL)
    app: dict[str, Any] = {}
    if isinstance(lookup, dict) and lookup.get("results"):
        first = lookup["results"][0]
        if isinstance(first, dict):
            app = first

    aasa, aasa_meta = fetch_json(APPLE_AASA_CDN)
    bundle_id = app.get("bundleId") or "com.minly.users"
    app_ids: list[str] = []
    components: list[Any] = []
    if isinstance(aasa, dict):
        applinks = aasa.get("applinks") or {}
        for detail in applinks.get("details", []) or []:
            if not isinstance(detail, dict):
                continue
            app_id = detail.get("appID") or detail.get("appIds")
            if isinstance(app_id, str):
                app_ids.append(app_id)
            elif isinstance(app_id, list):
                app_ids.extend(str(x) for x in app_id)
            if detail.get("components"):
                components.extend(detail.get("components") or [])
            if detail.get("paths"):
                components.extend({"path": p} for p in detail.get("paths") or [])

    relevant_app_ids = [x for x in app_ids if x.endswith("." + str(bundle_id))]
    candidate_markers = [
        {
            "candidate_type": "universal-link-routing",
            "source": "Apple associated-domain CDN metadata",
            "detail": component,
            "verification_status": "Unverified",
            "manual_validation_required": True,
        }
        for component in components[:100]
    ]

    summary = {
        "platform": "ios",
        "target": "Minly iOS App",
        "status": "RAN_PUBLIC_METADATA_ONLY",
        "app_store_id": IOS_APP_STORE_ID,
        "observed_bundle_id": bundle_id,
        "artifact_available": False,
        "binary_static_coverage": False,
        "artifact_sha256": None,
        "app_store_metadata": {
            "fetch": lookup_meta,
            "track_name": app.get("trackName"),
            "bundle_id": app.get("bundleId"),
            "version": app.get("version"),
            "minimum_os_version": app.get("minimumOsVersion"),
            "file_size_bytes": app.get("fileSizeBytes"),
            "current_version_release_date": app.get("currentVersionReleaseDate"),
            "seller_name": app.get("sellerName"),
            "track_view_url": app.get("trackViewUrl"),
        },
        "apple_associated_domains": {
            "fetch": aasa_meta,
            "app_ids": sorted(set(app_ids)),
            "bundle_matching_app_ids": sorted(set(relevant_app_ids)),
            "routing_component_count": len(components),
        },
        "toolchain": {
            "app_store_metadata": {"status": "RAN" if app else "UNAVAILABLE"},
            "apple_aasa_cdn": {"status": "RAN" if isinstance(aasa, dict) else "UNAVAILABLE"},
            "ipa_static_analysis": {"status": "SKIPPED", "reason": "No researcher-owned IPA and Apple requires authenticated App Store delivery for IPA acquisition."},
        },
        "candidate_markers": candidate_markers,
        "verification_status": "UNVERIFIED_METADATA_CANDIDATES_ONLY",
        "reporting_rule": (
            "Public App Store/AASA metadata can identify routes and manual test ideas, but it cannot substitute for IPA binary analysis "
            "or prove a vulnerability."
        ),
    }
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({
        "status": summary["status"],
        "bundle_id": bundle_id,
        "version": summary["app_store_metadata"]["version"],
        "aasa_app_ids": summary["apple_associated_domains"]["app_ids"],
        "candidate_count": len(candidate_markers),
    }, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Artifactless public fallback for Minly mobile audit coverage")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("android")
    a.add_argument("--workdir", type=Path, required=True)
    a.add_argument("--output", type=Path, required=True)
    a.add_argument("--xapk-url", default=ANDROID_XAPK_URL)
    a.add_argument("--expected-cert-sha1", default=ANDROID_KNOWN_CERT_SHA1)
    a.set_defaults(func=android)

    i = sub.add_parser("ios")
    i.add_argument("--output", type=Path, required=True)
    i.set_defaults(func=ios)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
