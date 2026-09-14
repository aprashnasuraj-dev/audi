# Minly Submission-Ready Vulnerability Report Template

> Keep this report confidential until Minly confirms disclosure is permitted.
>
> **Human-review rules:**
> - Do not invent findings. If something is unverified, label it **Unverified** and do not present it as a confirmed vulnerability.
> - Map every security claim to a concrete proof of concept or directly observed evidence.
> - For impact, explicitly answer **"As an attacker, I could..."** and describe real-world consequences such as unauthorized data exposure, account takeover, financial loss, unauthorized state changes, or other demonstrated harm.
> - Keep the complete `# Description` section under **25,000 characters**.
> - Use clear, numbered reproduction steps.
> - Include minimal raw HTTP requests/responses, screenshots, or video evidence where they materially prove the issue.
> - Redact passwords, cookies, session tokens, authorization headers, API keys, OAuth material, payment details, and unrelated personal data.
> - Do not submit Minly-listed out-of-scope issues such as missing security headers without demonstrated vulnerability, version disclosure, self-XSS, low-impact login/logout CSRF, non-sensitive clickjacking, password-policy issues, or scanner-only output.
> - Testing evidence must involve only researcher-controlled accounts/data. If unexpected non-public data belonging to another user is exposed, stop testing and report immediately.
> - Mobile artifact/tool output is a **candidate only** until the behavior is manually reproduced on a researcher-controlled device/account and tied to concrete Minly impact.

# Submission title

`[Vulnerability type] in [component] allows [specific unauthorized result]`

# Target

`[Minly Website / iOS App / Android App]`

# Technical severity

`[Critical / High / Medium / Low / Informational — based on VRT and demonstrated impact]`

# VRT Category

`[Exact VRT category, for example: Cross-Site Scripting (XSS) > Stored]`

# URL / Location of vulnerability

`[Full URL, API endpoint, app screen, deep link, component, or file path]`

# Description

## Summary

`[In 1–2 sentences: what is the vulnerability, where does it occur, and what security boundary fails?]`

## Vulnerability details

`[Explain the root cause or security-control failure, affected parameter/function/object, preconditions, authentication state, and why the behavior is exploitable. Clearly distinguish directly observed behavior from hypotheses.]`

For mobile findings, also record when applicable:

- **App version/build:** `[version / build number]`
- **Device / emulator profile:** `[model/profile]`
- **OS version:** `[Android/iOS version]`
- **Researcher-controlled account role/state:** `[Account A / Account B / logged out / creator / user, etc.]`
- **Affected mobile surface:** `[screen / deep link / exported component / WebView / extension / backend endpoint observed from app]`

## Steps to reproduce

1. `[Create/use researcher-controlled account and establish the required state.]`
2. `[Navigate to the affected feature or send the minimum required request.]`
3. `[Change only the parameter/state necessary to demonstrate the issue.]`
4. `[Observe the unauthorized or security-relevant result.]`
5. `[Optional minimal confirmation step, only if needed to prove impact.]`

## Proof of concept

`[Include the minimum evidence required to prove the finding. Every material claim above should be traceable to evidence here.]`

### Request

```http
[Minimal redacted raw HTTP request, when applicable]
```

### Response

```http
[Minimal redacted raw HTTP response showing the security-relevant result, when applicable]
```

### Visual evidence

`[Screenshot/video filename and exactly what it demonstrates, when applicable.]`

### Mobile artifact evidence

`[If relevant, reference only the sanitized artifact-analysis output that led to manual testing. State explicitly that the tool signal itself was not treated as the vulnerability.]`

### Verification status

`[Verified / Partially verified / Unverified]`

`[If not fully verified, explain exactly what remains unverified. Never infer or manufacture the missing result.]`

## Impact

**As an attacker, I could...**

`[Complete the sentence with the concrete action demonstrated by the PoC and its real-world consequence. Example pattern: "As an attacker, I could access an object belonging to another account by replacing an object identifier with one from my second researcher-controlled account, exposing data that should be isolated between users."]`

Then document:

- **Who is affected:** `[users / creators / account owners / specific role]`
- **Data or systems affected:** `[specific data, objects, actions, balances, bookings, messages, media, etc.]`
- **Worst demonstrated case:** `[maximum impact actually proven without exceeding the VDP]`
- **Authentication required:** `[Yes/No; role/state]`
- **User interaction required:** `[Yes/No; explain]`
- **Scope of impact:** `[single object/account / cross-account / broader, only if demonstrated]`
- **Limitations of proof:** `[anything deliberately not tested because of safety/scope]`

Do not convert hypothetical escalation into demonstrated impact. If an escalation path was not safely verified, label it **Unverified**.

## Suggested remediation

`[Give a specific fix tied to the failed security invariant. For authorization issues, prefer server-side object/role ownership enforcement on every affected operation. For input-handling issues, describe the required contextual validation/encoding or other concrete control.]`

Where useful, include retest expectations:

1. `[Unauthorized request/action is rejected.]`
2. `[The same authorized request/action still succeeds for the owner.]`
3. `[Equivalent web/mobile/API paths enforce the same security boundary.]`

# Attachments

- `[filename]` — `[what it proves]`
- `[filename]` — `[what it proves]`

## Final human-review gate

Before submission, confirm all of the following:

- [ ] The affected asset is explicitly in Minly's current scope.
- [ ] The finding is manually verified or clearly labeled **Unverified**.
- [ ] No finding or impact claim was invented or inferred beyond the evidence.
- [ ] Every material claim maps to the PoC/evidence section.
- [ ] Reproduction steps are numbered, minimal, and reproducible.
- [ ] The impact section literally contains **"As an attacker, I could..."** followed by a concrete consequence.
- [ ] Severity and VRT category reflect demonstrated impact rather than theoretical maximum impact.
- [ ] The `# Description` section is under 25,000 characters.
- [ ] Raw requests/responses and screenshots are included where useful and fully redacted.
- [ ] No Minly-listed out-of-scope issue is being submitted without a demonstrated in-scope vulnerability.
- [ ] Only researcher-controlled accounts/data were intentionally used.
- [ ] For mobile findings, app version/build, device/OS, affected screen/component/deep link/API, and manual reproduction context are recorded where applicable.
- [ ] Mobile scanner/static-analysis output was not promoted to a confirmed finding without a concrete manual PoC.
- [ ] No secrets, session material, payment data, or unrelated personal data remain in attachments.
