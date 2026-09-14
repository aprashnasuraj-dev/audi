# Minly Mobile Audit Toolchain

This document defines the mobile-analysis layer for the two explicitly in-scope Minly applications:

- **Android:** package `com.minly.users`
- **iOS:** App Store ID `1528802350`

The mobile pipeline is intentionally **artifact-first and offline**. It does not enumerate Minly infrastructure, brute-force endpoints, bypass platform DRM, or treat scanner output as a vulnerability. Every automated result is a research candidate until a human safely reproduces concrete impact with researcher-controlled accounts/devices.

## Artifact intake

Use only a lawfully obtained copy of the official store build installed or downloaded through an account/device you control. Do not commit APK/IPA binaries to this public repository.

The GitHub workflow accepts the binary through repository secrets containing a short-lived HTTPS download URL and expected SHA-256:

- Android: `MINLY_ANDROID_APK_URL`, `MINLY_ANDROID_APK_SHA256`
- iOS: `MINLY_IOS_IPA_URL`, `MINLY_IOS_IPA_SHA256`

The artifact is downloaded only during the manual job, verified against the supplied SHA-256, analyzed in the runner's temporary workspace, and deleted before artifact upload. The APK/IPA itself is never uploaded by the workflow.

## Android toolchain

The Android path uses a Linux runner and combines independent views of the APK:

- **Androguard** — package identity, manifest, permissions, components, SDK metadata, DEX-level inspection.
- **apktool** — manifest/resources/smali decoding for human review.
- **Semgrep** — offline pattern analysis of any decoded textual material supported by its parsers.
- **detect-secrets** — candidate secret-pattern detection; results remain unverified until validated without exposing real credentials.
- **LIEF / binutils** — native `.so` inventory and binary metadata/hardening context.
- **apksigner / keytool when present** — signing/certificate metadata.
- **Trivy filesystem scan** — dependency/secret/misconfiguration context only. Dependency CVEs are not reportable by themselves under Minly's rules.
- **Custom Minly mobile inspector** — exported-component/deep-link/API-surface research queue with explicit `Unverified` status.

### Android manual follow-up priorities

1. Deep links / app links that reach sensitive state.
2. Exported activities/services/receivers/providers that can cross a Minly authorization boundary.
3. WebView/native bridge behavior with Minly-controlled content.
4. Backend object authorization observed from normal app use, using only researcher-controlled Account A / Account B.
5. Client-controlled role/object/state fields that the backend trusts incorrectly.

A component being exported, cleartext being allowed, missing pinning, an old library, or lack of obfuscation is **not** a report by itself.

## iOS toolchain

The iOS path uses a macOS runner because Apple's native binary and signing utilities provide the most reliable offline view of an IPA:

- **plistlib / plutil** — bundle identity, versions, URL schemes, ATS, background modes, app metadata.
- **codesign** — signed entitlements and code-signing metadata.
- **otool** — linked frameworks/dylibs and Mach-O metadata.
- **nm / strings** — symbols and redacted route/URL candidates from the main executable.
- **LIEF** — additional Mach-O structural metadata.
- **Semgrep / detect-secrets** — offline textual resource/source-like candidate analysis where applicable.
- **Custom Minly mobile inspector** — URL-scheme/ATS/framework/extension research queue with explicit `Unverified` status.

### iOS manual follow-up priorities

1. Custom URL schemes / universal links that reach sensitive actions.
2. Authentication and authorization transitions across app screens and observed backend calls.
3. WebView-to-native trust boundaries.
4. Extension/share-sheet/clipboard/backup flows only where a realistic normal-device path exposes Minly data.
5. Backend object authorization using only researcher-controlled identities.

ATS exceptions, lack of certificate pinning, library versions, generic jailbreak/root observations, and sandboxed data that requires a compromised device remain out of scope unless a direct Minly exploit is demonstrated.

## Dynamic/manual testing boundary

GitHub Actions does **not** pretend to perform authenticated mobile dynamic testing. That requires a real researcher-controlled device/emulator and account state. The workflow therefore outputs a manual verification brief rather than replaying sensitive endpoints automatically.

For every candidate:

- reproduce through a normal app workflow first;
- keep tests reversible and low volume;
- use only your own accounts and data;
- stop immediately if unexpected non-public data belonging to another user appears;
- do not enumerate IDs/users/orders/creators at scale;
- map the final claim to a concrete PoC before compiling it into a report.

## Final-report integration

Only a human-reviewed candidate with concrete impact can be promoted into `SUBMISSION_TEMPLATE.md` / `FINAL_REPORT_FORMAT.md`.

For mobile findings the compiled report should additionally record:

- app platform and official target identity;
- app version/build;
- device model or emulator profile used for manual reproduction;
- OS version;
- authentication state and researcher-controlled account role(s);
- exact app screen, deep link, component, or backend endpoint;
- screenshots/video or redacted HTTP evidence that proves the security-relevant behavior.

Tool output that has not been manually reproduced must remain labeled **Unverified** and must not be presented as impact.
