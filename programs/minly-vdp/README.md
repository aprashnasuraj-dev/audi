# Minly VDP Participation Blueprint

This directory is the working blueprint for participating in the Minly Vulnerability Disclosure Program (VDP). It is intentionally designed around the program's safe-harbor, scope, privacy, and reporting rules.

## Authorized assets

Only the following assets are treated as in scope:

- Website: `https://minly.com/`
- iOS application: App Store ID `1528802350`
- Android application: package `com.minly.users`

Anything else is out of scope unless Minly updates the program in writing.

## Non-negotiable guardrails

- Use only accounts created and controlled by the researcher.
- Never access, retain, copy, or transfer another user's non-public data.
- If non-public data is exposed unexpectedly, stop immediately and report.
- No DoS/DDoS, traffic flooding, stress testing, social engineering, physical attacks, or disruptive automation.
- No high-volume automated scanning.
- No testing of third-party services merely because Minly links to or embeds them.
- No public disclosure before Minly agrees remediation/disclosure terms.
- Do not submit scanner-only output. Every report must include a manual proof of impact.
- Do not submit missing headers, weak TLS, version disclosure, self-XSS, low-impact login/logout CSRF, non-sensitive clickjacking, password-policy issues, email-authentication configuration, or non-critical rate-limit findings unless the program is updated to include them.
- Mobile reports must demonstrate direct exploitability against Minly; generic platform, rooted-device, pinning-only, obfuscation-only, or third-party-library-only observations are not enough.

## Working sequence

1. Confirm the current program page and scope before each test session.
2. Record the date/time of the scope check in `WORKLOG_TEMPLATE.md`.
3. Select one exact in-scope asset.
4. Use the checklists in `WEB_TEST_MATRIX.md` or `MOBILE_TEST_MATRIX.md`.
5. Keep traffic low and actions reversible.
6. Stop immediately if a test crosses an account boundary or exposes non-public third-party data.
7. Run the finding through `FINDING_ELIGIBILITY_GATE.md` before spending time on a report.
8. Capture only the minimum evidence required by `EVIDENCE_CHECKLIST.md`.
9. Draft with `SUBMISSION_TEMPLATE.md`.
10. Submit through Minly's disclosure portal and track acknowledgement/triage dates in the worklog.

## Repository structure

- `scope.yml` — machine-readable scope and exclusions.
- `FINDING_ELIGIBILITY_GATE.md` — go/no-go gate before reporting.
- `WEB_TEST_MATRIX.md` — prioritized website testing plan.
- `MOBILE_TEST_MATRIX.md` — Android/iOS testing plan.
- `EVIDENCE_CHECKLIST.md` — evidence and redaction requirements.
- `SUBMISSION_TEMPLATE.md` — human-readable disclosure template.
- `WORKLOG_TEMPLATE.md` — session and submission record.

## Success criteria

A submission is ready only when it is:

- on an explicitly in-scope Minly asset;
- reproducible using the researcher's own account(s);
- manually verified;
- non-destructive;
- supported by a clear security impact rather than a best-practice claim;
- documented with minimal, privacy-preserving evidence;
- free of secrets, unrelated user data, and internal tooling noise.
