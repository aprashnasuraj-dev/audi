# Minly Scope Verification — Final Audit Trigger

Date: 2026-09-14T11:30:00Z
Branch: `run/minly-final-audit-20260914`
Purpose: verify all current Minly audit targets before triggering the final bounded audit/scanning workflow.

## Verified in-scope assets

| Surface | Verified target | Evidence basis | Audit action |
| --- | --- | --- | --- |
| Web | `https://minly.com/` exact host `minly.com` | Repo VDP scope file plus Minly-owned public web/app platform references | Bounded exact-host web audit families only |
| Android | Google Play package `com.minly.users` | Repo VDP scope file and public Google Play listing for Minly | Public/provenance-checked static mobile audit only |
| iOS / iPhone | App Store ID `1528802350` | Repo VDP scope file and public Apple App Store listing for Minly by Minly Ltd. | Official App Store/AASA public metadata audit only |

## Scope decision

The final audit is allowed to run controlled scoped scanning and analysis. The interpretation is:

- Controlled scanning is allowed when exact-host, low-rate, bounded, non-destructive, and sanitized.
- Own-account-only testing means authenticated work must use researcher-controlled Account A/B identities and objects only; it does not mean no authenticated testing.
- Scanner output is candidate material until manual reproduction proves concrete Minly impact.
- Public repository material must not contain raw HARs, tokens, screenshots, live exploit evidence, private findings, or unrelated user data.

## Boundaries retained

- Do not expand web scope to `*.minly.com` or sibling hosts unless Minly explicitly authorizes them.
- Do not run subdomain/port sweeps, stress testing, credential attacks, blind object/user/order/account ID enumeration, destructive tests, or third-party-provider testing.
- Stop immediately if a test exposes non-public data from anyone other than controlled test accounts.

## Trigger statement

This verification file intentionally changes `programs/minly-vdp/**`, which is included in the corrected final audit workflow path filters. The push should trigger `Minly Corrected Final Audit Once` for a fresh final web/Android/iOS audit bundle.

## Public source notes used before trigger

- Repo scope: `programs/minly-vdp/scope.yml` declares Minly Website `https://minly.com/`, iOS App Store ID `1528802350`, and Android package `com.minly.users`.
- Repo web target: `programs/minly-vdp/halo-targets.yml` restricts live web audit to exact host `minly.com`, denies `*.minly.com`, and enforces low-rate controls.
- Public Google Play result confirms Minly Android listing at package ID `com.minly.users`.
- Public Apple App Store result confirms Minly listing at App Store ID `1528802350`, provider Minly Ltd.
- Minly public terms/privacy pages describe Minly-owned website and application platform.

No vulnerability details, secrets, raw evidence, HARs, or exploit payloads are included in this file.
