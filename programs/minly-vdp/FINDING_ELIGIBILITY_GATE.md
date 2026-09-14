# Finding Eligibility Gate

Use this gate before drafting or submitting any Minly finding. A single `NO` in Sections A-C means stop and do not submit until the issue is clarified.

## A. Scope gate

- [ ] The affected asset is exactly `minly.com`, the official Minly iOS application, or Android package `com.minly.users`.
- [ ] The vulnerable behavior occurs in Minly-controlled functionality, not only in a third-party service.
- [ ] Testing used only researcher-controlled accounts and data.
- [ ] No prohibited action was required to reproduce the issue.

## B. Validity gate

- [ ] The behavior was reproduced manually.
- [ ] The report does not rely only on automated-scanner output.
- [ ] There is a concrete security consequence, not merely a hardening recommendation.
- [ ] The proof of concept is minimal and non-destructive.
- [ ] The issue is still reproducible in a clean session or second researcher-controlled account where applicable.

## C. Program-exclusion gate

Confirm the finding is **not merely** one of the following:

- [ ] Missing security headers or weak TLS without demonstrated exploitability.
- [ ] Self-XSS.
- [ ] Low-impact login/logout CSRF.
- [ ] Clickjacking on a page with no sensitive state-changing action.
- [ ] Software/version disclosure.
- [ ] Descriptive errors or stack traces without exploitability.
- [ ] Password-policy concerns.
- [ ] SPF/DKIM/DMARC configuration.
- [ ] Non-critical rate limiting/brute-force behavior.
- [ ] Expected continued JWT validity after logout in a stateless-token design.
- [ ] Mobile OS vulnerability, unlocked-device physical attack, pinning-only observation, rooted/jailbroken-only storage access, library-only issue, obfuscation-only issue, or app-only crash without backend impact.

## D. Impact-quality gate

At least one should be clear and evidenced:

- [ ] Unauthorized access to the researcher's second account or resource.
- [ ] Unauthorized state change on the researcher's second account or resource.
- [ ] Authentication or account-recovery bypass.
- [ ] Privilege boundary failure demonstrated without touching real third-party data.
- [ ] Sensitive data exposure belonging only to the researcher's controlled test accounts.
- [ ] Stored/reflected client-side injection with a meaningful Minly security consequence.
- [ ] Server-side request/control behavior with safe, non-destructive proof.
- [ ] Payment/business-logic abuse demonstrated with reversible or non-monetary proof.
- [ ] Mobile behavior that directly compromises Minly data, sessions, authorization, or backend security without relying on root/jailbreak or OS flaws.

## E. Evidence gate

- [ ] Exact affected location is documented.
- [ ] Preconditions are documented.
- [ ] Steps are deterministic and numbered.
- [ ] Expected vs actual result is explicit.
- [ ] Impact is separated from speculation.
- [ ] Secrets/tokens are redacted.
- [ ] No unrelated user data is captured.
- [ ] A retest criterion is included.

## Decision

- **READY TO REPORT** — A-C all pass, at least one D item is demonstrated, and E is complete.
- **KEEP TESTING SAFELY** — plausible issue but impact is not yet proven.
- **DO NOT SUBMIT** — out of scope, best-practice only, scanner-only, duplicate-quality evidence, or requires prohibited behavior.
