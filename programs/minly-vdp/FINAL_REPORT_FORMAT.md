# Minly Final Report Compilation Rules

This file defines how a human-reviewed candidate is converted into a submission-ready report.

## Canonical source

`SUBMISSION_TEMPLATE.md` is the canonical report structure. A compiled final report must preserve its section order and meaning.

## Finding integrity

1. Never create a vulnerability from a scanner/tool hypothesis alone.
2. A finding marked `Verified` may be compiled as a submission candidate only when its security-relevant behavior is demonstrated by evidence.
3. `Partially verified` and `Unverified` material must retain that label everywhere it appears. It must not be rewritten as confirmed impact.
4. Every material claim must have a concrete proof reference: raw request/response, screenshot, video, or deterministic reproduction result.
5. Do not infer another user's exposure. Horizontal authorization testing must use researcher-controlled Account A / Account B evidence only.
6. Android/iOS artifact-analysis output is discovery evidence only. Exported components, URL schemes, ATS/cleartext settings, library versions, missing pinning, obfuscation state, or static secret-pattern hits are not vulnerabilities unless a safe manual PoC demonstrates direct Minly impact.

## Required section order

1. `# Submission title`
2. `# Target`
3. `# Technical severity`
4. `# VRT Category`
5. `# URL / Location of vulnerability`
6. `# Description`
   - `## Summary`
   - `## Vulnerability details`
   - `## Steps to reproduce`
   - `## Proof of concept`
   - `## Impact`
   - `## Suggested remediation`
7. `# Attachments`

## Required impact language

The Impact section must contain the literal lead-in:

**As an attacker, I could...**

The text following it must describe the demonstrated action and consequence, not a theoretical maximum.

## Description limit

The complete content under `# Description` and before `# Attachments` must remain under 25,000 characters.

## Reproduction quality

- Steps must be numbered.
- Preconditions must be included in the vulnerability details or first reproduction steps.
- The minimum safe proof is preferred over repeated exploitation.
- Any intentionally untested escalation path must be labeled `Unverified`.
- Mobile reproduction must identify the tested app version/build and device/OS context where applicable.

## Evidence handling

Where applicable, include minimal redacted HTTP evidence and/or screenshots. Strip:

- cookies and session tokens;
- authorization headers;
- passwords and API keys;
- OAuth secrets/codes;
- payment details;
- unrelated personal data.

Attachment entries must state exactly what each file proves.

For Android/iOS submissions, evidence should also identify the affected screen, deep link, app component, WebView/native boundary, extension, or backend endpoint observed from the app. Sanitized static-analysis output may be attached only as supporting context; the manual PoC remains the proof of vulnerability.

## Mobile target identity

Use the exact target names in the report:

- `Minly Android App` — package `com.minly.users`
- `Minly iOS App` — App Store ID `1528802350`

For `# URL / Location of vulnerability`, mobile reports may use an exact app screen, deep-link URI, exported component name, WebView route, extension path, or backend endpoint reached by the official app. Do not use a generic App Store/Play Store URL as the vulnerability location unless the issue is actually located there.

## Mobile manual-verification fields

Before a mobile candidate is marked `Verified`, capture when applicable:

- app version/build;
- device model or emulator/simulator profile;
- Android/iOS version;
- authentication state and researcher-controlled account role(s);
- exact affected mobile surface;
- minimal manual reproduction steps;
- screenshot/video or redacted HTTP evidence proving the behavior;
- explicit confirmation that the automated/static signal alone was not treated as the finding.

If the behavior cannot be manually reproduced, keep it `Unverified` and do not state concrete attacker impact.

## Severity and VRT

Severity and VRT classification must be based on the behavior actually demonstrated. Do not inflate severity using an unverified escalation path.

## Out-of-scope suppression

The final compiler must not promote Minly-listed exclusions into findings merely because they were observed. Examples include scanner-only output, missing headers without demonstrated vulnerability, version disclosure, self-XSS, low-impact login/logout CSRF, non-sensitive clickjacking, password-policy issues, missing certificate pinning by itself, third-party library versions without direct Minly exploitation, sandboxed mobile data requiring root/jailbreak, lack of obfuscation/root detection, and local app crashes without backend impact.

## Submission-ready definition

A final report is submission-ready only when:

- the affected asset is currently in scope;
- the PoC is reproducible;
- evidence supports every material claim;
- impact is concrete and uses the required attacker statement;
- verification status is explicit;
- the Description section is below 25,000 characters;
- evidence is privacy-safe and redacted;
- no out-of-scope-only issue is being submitted;
- mobile findings include app/device/OS/surface context where applicable;
- a human has reviewed the final wording and evidence mapping.
