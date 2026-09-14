# Minly Vulnerability Submission Template

> Keep this report confidential until Minly confirms disclosure is permitted.

## Title

`[Impact] in [feature] allows [unauthorized result]`

## In-scope asset

- Asset: `minly.com` / Minly iOS / Minly Android
- Exact location: `<URL, screen, deep link, or API operation>`
- App version (if mobile): `<version>`
- Platform/OS/browser: `<details>`

## Summary

A concise description of the security boundary that fails and the resulting impact.

## Preconditions

- Researcher-controlled account(s): `<Account A / Account B roles>`
- Required feature/state: `<state>`
- No third-party user data was accessed: `Yes`

## Steps to reproduce

1. `<step>`
2. `<step>`
3. `<step>`
4. `<minimal proof step>`

## Expected result

Describe the authorization/security decision that should occur.

## Actual result

Describe only the behavior actually observed.

## Security impact

Explain the concrete consequence. Keep demonstrated impact separate from hypothetical escalation.

## Proof of concept / evidence

Include only the minimum necessary evidence. Redact passwords, cookies, tokens, API keys, OAuth parameters, and unrelated personal data.

```text
<minimal redacted request/response or reproduction evidence>
```

## Why this is in scope

- Affected asset is explicitly listed by the Minly VDP.
- Testing used only researcher-controlled account(s)/data.
- The report demonstrates manual impact and does not rely on scanner output alone.
- The issue is not merely a missing best-practice control or other listed exclusion.

## Suggested remediation

Describe the security invariant that should be enforced, preferably server-side where applicable. Avoid prescribing unnecessary implementation details.

## Retest criteria

The issue is fixed when:

1. `<unauthorized action is rejected>`
2. `<authorized action continues to work>`
3. `<alternate route/API/mobile path enforces the same boundary>`

## Research safety statement

Testing was limited to Minly's explicitly in-scope assets and researcher-controlled accounts. Testing stopped once sufficient proof was obtained. No denial-of-service, high-volume scanning, social engineering, physical testing, or intentional access to another user's non-public data was performed.
