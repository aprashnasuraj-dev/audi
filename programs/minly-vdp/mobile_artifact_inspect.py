#!/usr/bin/env python3
"""Offline Minly APK/IPA surface inspector.

This script produces a *candidate research map*, never a vulnerability verdict.
It intentionally avoids exploit execution, network replay, credential extraction,
and third-party target interaction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import plistlib
import re
import zipfile
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

ANDROID_NS = "http://schemas.android.com/apk/res/android"
URL_RE = re.compile(rb"https?://[^\x00\s\"'<>]{4,300}")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def redact_url(raw: str) -> str:
    try:
        p = urlsplit(raw)
        host = p.hostname or ""
        if not host:
            return raw[:240]
        port = f":{p.port}" if p.port else ""
        return urlunsplit((p.scheme, host + port, p.path, "", ""))[:300]
    except Exception:
        return raw[:240]


def candidate(kind: str, location: str, note: str, *, priority: str = "medium") -> dict:
    return {
        "type": kind,
        "location": location,
        "note": note,
        "priority": priority,
        "verification_status": "Unverified",
        "candidate_only": True,
        "manual_validation_required": True,
        "reportable_without_manual_impact": False,
    }


def inspect_android(path: Path) -> dict:
    try:
        from androguard.core.apk import APK
    except Exception as exc:  # pragma: no cover - workflow dependency gate covers this
        raise SystemExit(f"androguard is required for Android inspection: {exc}")

    apk = APK(str(path))
    manifest = apk.get_android_manifest_xml()
    app = None
    for elem in manifest.iter():
        if elem.tag.rsplit("}", 1)[-1] == "application":
            app = elem
            break

    def aattr(elem, name: str):
        if elem is None:
            return None
        return elem.get(f"{{{ANDROID_NS}}}{name}")

    components = []
    candidates = []
    component_tags = {"activity", "activity-alias", "service", "receiver", "provider"}
    for elem in manifest.iter():
        tag = elem.tag.rsplit("}", 1)[-1]
        if tag not in component_tags:
            continue
        name = aattr(elem, "name") or "<unnamed>"
        exported = aattr(elem, "exported")
        has_intent_filter = any(c.tag.rsplit("}", 1)[-1] == "intent-filter" for c in list(elem))
        item = {
            "type": tag,
            "name": name,
            "exported_attribute": exported,
            "has_intent_filter": has_intent_filter,
        }
        components.append(item)
        if exported == "true" or (exported is None and has_intent_filter):
            candidates.append(candidate(
                "android-component-exposure",
                f"{tag}:{name}",
                "Externally reachable component candidate. This is not a vulnerability unless a safe manual PoC demonstrates a Minly security-boundary failure.",
            ))

    deep_links = []
    for elem in manifest.iter():
        if elem.tag.rsplit("}", 1)[-1] != "data":
            continue
        scheme = aattr(elem, "scheme")
        host = aattr(elem, "host")
        path_prefix = aattr(elem, "pathPrefix")
        if scheme or host or path_prefix:
            entry = {"scheme": scheme, "host": host, "path_prefix": path_prefix}
            deep_links.append(entry)
            candidates.append(candidate(
                "android-deep-link",
                json.dumps(entry, sort_keys=True),
                "Observed manifest route candidate; manually verify authentication, ownership, and state-transition enforcement using researcher-controlled accounts.",
                priority="high",
            ))

    cleartext = aattr(app, "usesCleartextTraffic")
    debuggable = aattr(app, "debuggable")
    allow_backup = aattr(app, "allowBackup")
    if cleartext == "true":
        candidates.append(candidate(
            "android-cleartext-policy",
            "AndroidManifest.xml/application",
            "Cleartext is enabled by manifest. Minly excludes generic best-practice findings; only retain if a viable, demonstrated Minly exploit exists.",
            priority="low",
        ))
    if debuggable == "true":
        candidates.append(candidate(
            "android-debuggable-build",
            "AndroidManifest.xml/application",
            "Debuggable build signal. This is candidate context only and requires direct exploitability against Minly to be reportable.",
            priority="low",
        ))

    urls = set()
    for dex in apk.get_all_dex():
        for match in URL_RE.findall(dex):
            try:
                urls.add(redact_url(match.decode("utf-8", "ignore")))
            except Exception:
                pass
            if len(urls) >= 300:
                break
        if len(urls) >= 300:
            break

    native_libs = sorted(n for n in apk.get_files() if n.startswith("lib/") and n.endswith(".so"))
    return {
        "platform": "android",
        "identity": {
            "package": apk.get_package(),
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
        },
        "manifest": {
            "debuggable": debuggable,
            "allow_backup": allow_backup,
            "uses_cleartext_traffic": cleartext,
            "permissions": sorted(apk.get_permissions()),
            "components": components,
            "deep_links": deep_links,
        },
        "observed_urls_redacted": sorted(urls),
        "native_libraries": native_libs,
        "candidates": candidates,
    }


def inspect_ios(path: Path) -> dict:
    candidates = []
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        plist_names = [n for n in names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n)]
        if len(plist_names) != 1:
            raise SystemExit(f"expected exactly one app Info.plist; found {len(plist_names)}")
        plist_name = plist_names[0]
        info = plistlib.loads(zf.read(plist_name))
        app_root = plist_name.rsplit("/", 1)[0] + "/"

        schemes = []
        for block in info.get("CFBundleURLTypes", []) or []:
            schemes.extend(block.get("CFBundleURLSchemes", []) or [])
        for scheme in sorted(set(map(str, schemes))):
            candidates.append(candidate(
                "ios-custom-url-scheme",
                f"{scheme}://",
                "Custom URL scheme surface. Manually verify authentication, ownership, and sensitive-action confirmation; scheme presence alone is not a finding.",
                priority="high",
            ))

        ats = info.get("NSAppTransportSecurity") or {}
        if ats.get("NSAllowsArbitraryLoads") is True or ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
            candidates.append(candidate(
                "ios-ats-exception",
                "Info.plist/NSAppTransportSecurity",
                "ATS exception observed. Minly excludes best-practice-only issues; retain only if a viable, demonstrated Minly exploit exists.",
                priority="low",
            ))

        executable = info.get("CFBundleExecutable")
        executable_member = f"{app_root}{executable}" if executable else None
        frameworks = sorted(n for n in names if n.startswith(app_root + "Frameworks/") and (n.endswith(".framework/") or n.endswith(".dylib")))
        plugins = sorted(n for n in names if n.startswith(app_root + "PlugIns/") and n.endswith(".appex/Info.plist"))

        urls = set()
        if executable_member in names:
            blob = zf.read(executable_member)
            for match in URL_RE.findall(blob):
                urls.add(redact_url(match.decode("utf-8", "ignore")))
                if len(urls) >= 300:
                    break

    return {
        "platform": "ios",
        "identity": {
            "bundle_id": info.get("CFBundleIdentifier"),
            "version": info.get("CFBundleShortVersionString"),
            "build": info.get("CFBundleVersion"),
            "minimum_os": info.get("MinimumOSVersion"),
            "executable": executable,
        },
        "plist": {
            "url_schemes": sorted(set(map(str, schemes))),
            "queried_url_schemes": sorted(set(map(str, info.get("LSApplicationQueriesSchemes", []) or []))),
            "ats": ats,
            "background_modes": info.get("UIBackgroundModes", []) or [],
        },
        "observed_urls_redacted": sorted(urls),
        "framework_entries": frameworks,
        "extension_entries": plugins,
        "app_root": app_root,
        "executable_member": executable_member,
        "candidates": candidates,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--platform", choices=["android", "ios"], required=True)
    ap.add_argument("--artifact", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    if not args.artifact.is_file():
        raise SystemExit(f"artifact not found: {args.artifact}")
    if not zipfile.is_zipfile(args.artifact):
        raise SystemExit("artifact is not a ZIP-based APK/IPA container")

    result = inspect_android(args.artifact) if args.platform == "android" else inspect_ios(args.artifact)
    result.update({
        "artifact_sha256": sha256_file(args.artifact),
        "verification_status": "Unverified",
        "artifact_analysis_only": True,
        "manual_proof_required_for_submission": True,
        "reporting_note": "Tool output is research evidence only. Do not compile a vulnerability unless a human reproduces concrete impact within Minly's current VDP scope.",
    })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
