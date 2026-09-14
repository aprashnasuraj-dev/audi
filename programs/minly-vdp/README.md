# Minly VDP Participation Blueprint

This directory is the working blueprint for participating in the Minly Vulnerability Disclosure Program (VDP). It is intentionally designed around the program's safe-harbor, scope, privacy, and reporting rules.

## Authorized assets

Only the following assets are treated as in scope:

- Website: `https://minly.com/`
- iOS application: App Store ID `1528802350`
- Android application: package `com.minly.users`

Anything else is out of scope unless Minly updates the program in writing.

## Adaptive audit model

The audit tracks more than already-exploitable bugs, but it keeps evidence classes separate:

1. **Confirmed exploitable issue** — manually reproduced with demonstrated impact; may become a submission.
2. **Security weakness** — concrete weakness that still needs proof of abuse.
3. **Latent vulnerability** — current safety depends on a fragile assumption or control.
4. **Attack-path precursor** — weakness likely to matter only when combined with another condition.
5. **Security enhancement** — defensive improvement without demonstrated exploitability.

Only the first class is directly reportable. This prevents future-risk analysis from being mislabeled as a vulnerability while still letting the audit surface conditions that could become dangerous as Minly evolves.

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
2. Record the date/time of the scope check privately.
3. Use the existing researcher-controlled account for normal-use workflow mapping.
4. Create a second ordinary researcher-controlled account only when a two-account authorization test is actually required.
5. Run `scripts/minly_policy_gate.py` before any automated live mapping.
6. Generate the latent-risk queue with `scripts/minly_hypothesis_matrix.py`.
7. Use the `Minly Adaptive Audit` workflow in `blueprint`, `public-map`, or `offline-toolchain` mode as appropriate.
8. Confirm current product paths against `WORKFLOW_MAP.md` and follow `RESEARCH_PLAN.md`.
9. Use `AUTHORIZATION_TEST_PLAN.md` and `PHASE1_SESSION_CHECKLIST.md` for controlled account-isolation tests.
10. Use `WEB_TEST_MATRIX.md` or `MOBILE_TEST_MATRIX.md` for broader manual coverage.
11. Keep traffic low and actions reversible.
12. Stop immediately if a test crosses an uncontrolled account boundary or exposes non-public third-party data.
13. Run candidates through `FINDING_ELIGIBILITY_GATE.md` and `SUBMISSION_SCORECARD.md`.
14. Capture only the minimum evidence required by `EVIDENCE_CHECKLIST.md`.
15. Draft confirmed issues with `SUBMISSION_TEMPLATE.md` and submit through Minly's portal.

## Repository structure

- `scope.yml` — original machine-readable scope and exclusions.
- `adaptive-audit-profile.yml` — v2 execution limits, risk classes, stop conditions, and priority lenses.
- `advanced-tool-versions.yml` — pinned advanced toolchain and policy-disabled capabilities.
- `ADVANCED_TOOLCHAIN.md` — live-safe/manual/offline/disabled execution model.
- `AI_REVIEW_PROTOCOL.md` — evidence labels and AI-assisted trust-boundary/future-risk review.
- `ACCOUNT_SETUP.md` — researcher-controlled account setup and privacy rules.
- `WORKFLOW_MAP.md` — normal public/authenticated product workflow map and object inventory.
- `AUTHORIZATION_TEST_PLAN.md` — manual A/B authorization-isolation methodology using only researcher-owned objects.
- `PHASE1_SESSION_CHECKLIST.md` — first-session execution checklist and stop conditions.
- `RESEARCH_PLAN.md` — staged adaptive research roadmap and time allocation.
- `FINDING_ELIGIBILITY_GATE.md` — go/no-go gate before reporting.
- `SUBMISSION_SCORECARD.md` — candidate prioritization rubric.
- `WEB_TEST_MATRIX.md` — prioritized website testing plan.
- `MOBILE_TEST_MATRIX.md` — Android/iOS testing plan.
- `EVIDENCE_CHECKLIST.md` — evidence and redaction requirements.
- `SUBMISSION_TEMPLATE.md` — human-readable disclosure template.
- `WORKLOG_TEMPLATE.md` — private-worklog structure; do not commit live findings here.
- `CONFIDENTIALITY.md` — public-repo data-handling rules.

## Automation

### `Minly VDP Blueprint Readiness`

Zero-live-traffic validation of exact scope, exclusions, privacy controls, and required blueprint files.

### `Minly Adaptive Audit`

Three explicit modes:

- `blueprint` — policy validation plus a 15+ lens latent-risk hypothesis matrix; no live target traffic.
- `public-map` — exact-host, GET-only, maximum 12-page map of `https://minly.com/`, at least 2.5 seconds between requests, no form submission, no cross-host redirect following.
- `offline-toolchain` — installs and inventories advanced analysis tools without contacting Minly.

Bulk template scanners, directory brute-forcers, broad GraphQL generation, active ZAP scanning, and brute-force wordlists are intentionally disabled by policy.

## Success criteria

A submission is ready only when it is:

- on an explicitly in-scope Minly asset;
- reproducible using the researcher's own account(s);
- manually verified;
- non-destructive;
- supported by a clear security impact rather than a best-practice claim;
- documented with minimal, privacy-preserving evidence;
- free of secrets, unrelated user data, and internal tooling noise.

The broader audit can still be successful even if it produces zero submissions: latent weaknesses and enhancement opportunities are valuable assurance outputs, but they remain clearly separated from vulnerability claims.
