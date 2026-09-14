# Raw Candidate Capture Trigger — Safe Full Audit

Date: 2026-09-14T12:05:00Z
Branch: `run/minly-final-audit-20260914`

## Intent

Trigger a fresh full Minly detailed audit run with maximum allowed bounded coverage and detailed candidate capture.

## Capture mode

This run should preserve all suspected vulnerability candidates in the generated private artifact bundle with:

- candidate title and category;
- affected in-scope surface;
- observed URL, path, manifest item, static-analysis rule, dependency context, or mobile component;
- source tool/family;
- severity/confidence estimate;
- sanitized evidence excerpts;
- hashes/fingerprints where useful;
- safe PoC/reproduction steps;
- what an attacker might do if the candidate is confirmed;
- recommended remediation;
- verification gaps and required Account A/B or manual checks.

## Safety boundary

Do not store unredacted credentials, tokens, raw HARs, third-party private data, unrelated user data, destructive payloads, brute-force logs, blind ID enumeration output, or uncontrolled scanner output in the public repository.

Raw evidence may be captured only when it is safe-for-analysis and redacted-for-submission. Sensitive proof should remain private and controlled by the researcher.

## Scope retained

- Web: `https://minly.com/`, exact host `minly.com` only.
- Android: `com.minly.users` public/provenance-checked static analysis.
- iOS: App Store ID `1528802350` public metadata/AASA analysis.
- No subdomain expansion, port sweep, credential attack, destructive testing, or third-party testing.

This file intentionally touches `programs/minly-vdp/**` to trigger the full detailed audit workflow.