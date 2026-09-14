# Minly Adaptive Audit Toolchain

This toolchain is intentionally policy-aware. Power is not the goal by itself; useful evidence is. Every capability is assigned an execution class so the workflow cannot silently cross Minly's rules.

## Execution classes

- **LIVE-SAFE** — low-volume observation against an explicitly in-scope asset.
- **MANUAL-ONLY** — use only while a researcher is controlling the exact action and object.
- **OFFLINE-ONLY** — analyze researcher-provided artifacts without contacting Minly.
- **DISABLED-BY-POLICY** — technically possible but not appropriate for this VDP.

## Web and API layer

| Capability | Tool / approach | Class | Purpose |
| --- | --- | --- | --- |
| Normal browser journey capture | Playwright | LIVE-SAFE | Map user-visible workflows, requests, redirects, forms, API calls, WebSockets and state transitions. |
| Exact-host HTTP baseline | httpx/Python | LIVE-SAFE | Record status, redirects, cache/security metadata and protocol behavior as context only. |
| TLS metadata | Python `ssl` | LIVE-SAFE | Capture protocol/certificate context; never submit weak-TLS-only observations without impact. |
| HAR/trace analysis | custom parser | OFFLINE-ONLY | Build endpoint, method, object-id, state-change and trust-boundary inventory from redacted captures. |
| Request replay | HALO/manual replay | MANUAL-ONLY | Reproduce only observed operations and owned objects. No ID enumeration. |
| API contract comparison | OpenAPI parser | OFFLINE-ONLY / MANUAL-ONLY | Compare observed methods/fields with a supplied or legitimately exposed contract. |
| GraphQL schema analysis | schema parser | OFFLINE-ONLY | Analyze a supplied/introspected-in-normal-use schema without query spraying. |
| Dynamic wordlist/dir brute forcing | ffuf/dirsearch/gobuster | DISABLED-BY-POLICY | High-volume enumeration conflicts with program rules. |
| Broad template scanning | nuclei-style bulk scanning | DISABLED-BY-POLICY | Scanner-only/high-volume findings are not the objective of this VDP. |
| Active ZAP spider/attack mode | OWASP ZAP active scan | DISABLED-BY-POLICY | Too broad for this program unless Minly explicitly authorizes it. |

## Authorization and business-logic layer

The highest-value tool is a controlled two-account differential matrix, not a generic scanner.

For each observed object/action, record:

1. owner identity and role;
2. object identifier source;
3. read/write/delete/transition operations;
4. server-controlled fields;
5. expected authorization predicate;
6. one minimal cross-account test using only Account A and Account B objects;
7. response/body/state differences;
8. whether the proof already demonstrates impact.

No guessing sequential IDs, no unrelated-user probing, no enumeration.

## Mobile layer

| Capability | Tool / approach | Class | Purpose |
| --- | --- | --- | --- |
| APK structure/resources | JADX, apktool, aapt/apksigner | OFFLINE-ONLY | Inspect manifest, exported components, deep links, WebViews, hard-coded endpoints and client trust assumptions. |
| Mobile static rules | Semgrep custom rules | OFFLINE-ONLY | Flag risky WebView/native bridge, exported-component, intent, storage and crypto patterns for manual validation. |
| Dependency/SBOM context | Trivy filesystem/SBOM | OFFLINE-ONLY | Prioritize components only when they can be tied to Minly exploitability. |
| Mobile runtime capture | researcher device + proxy | MANUAL-ONLY | Observe normal own-account traffic and backend authorization parity. |
| Certificate-pinning bypass solely to claim missing pinning | n/a | DISABLED-BY-POLICY | Pinning-only findings are explicitly out of scope without a viable Minly impact chain. |
| Root/jailbreak-only data access | n/a | DISABLED-BY-POLICY | Explicitly out of scope unless direct non-rooted Minly impact exists. |

## Artifact and code analysis layer

When legitimate artifacts become available, the workflow can use:

- Semgrep for code/static patterns;
- Bandit for Python artifacts;
- Trivy for filesystem, package, SBOM and IaC context;
- CycloneDX SBOM generation;
- custom secret-pattern review with immediate redaction, never publication;
- manifest/permission/deep-link extraction for mobile packages;
- source-map inspection only when served directly by an in-scope Minly asset during normal use.

Static signals are hypotheses, not findings.

## AI-assisted reasoning layer

ChatGPT/AI review is used for **coverage expansion and hypothesis generation**, never to invent evidence. For every observation it should ask:

- What trust decision is the server making?
- Which field is assumed to be truthful because the client supplied it?
- Which control keeps this safe today, and what change would invalidate that assumption?
- Could a stale cache, asynchronous worker, retry, webhook, background job, mobile client, or feature flag bypass the primary control?
- Is the authorization predicate checked at every state transition or only in the UI?
- Does web/mobile enforce the same ownership and role rules?
- What is the smallest reversible own-account experiment that can falsify the safety assumption?

AI output must label each statement as **Observed**, **Inferred**, **Hypothesis**, or **Confirmed**.

## High-impact hypothesis families

Priority is given to conditions that could produce P1-P3 impact if confirmed:

- account takeover through recovery/session state confusion;
- horizontal or vertical authorization failure;
- payment/order/booking ownership or state-machine bypass;
- unauthorized creator/customer action crossing;
- high-impact server-side action controlled by client fields;
- reusable or transferable sensitive action token;
- backend/mobile authorization inconsistency;
- insecure callback/deep-link flow causing account or transaction confusion;
- unauthorized file/media access or modification;
- privilege/entitlement persistence after downgrade/revocation;
- stale authorization in async processing;
- cache key/auth-context mismatch exposing personalized content;
- cross-account message/content operation using only researcher-owned accounts;
- unsafe WebView/native bridge reaching privileged Minly functionality;
- business invariant bypass with reversible, non-loss PoC.

These are research hypotheses, not claims. Severity is assigned only after manual proof.
