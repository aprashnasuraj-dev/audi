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

## Evidence handling

Where applicable, include minimal redacted HTTP evidence and/or screenshots. Strip:

- cookies and session tokens;
- authorization headers;
- passwords and API keys;
- OAuth secrets/codes;
- payment details;
- unrelated personal data.

Attachment entries must state exactly what each file proves.

## Severity and VRT

Severity and VRT classification must be based on the behavior actually demonstrated. Do not inflate severity using an unverified escalation path.

## Out-of-scope suppression

The final compiler must not promote Minly-listed exclusions into findings merely because they were observed. Examples include scanner-only output, missing headers without demonstrated vulnerability, version disclosure, self-XSS, low-impact login/logout CSRF, non-sensitive clickjacking, password-policy issues, and other program-listed exclusions.

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
- a human has reviewed the final wording and evidence mapping.
