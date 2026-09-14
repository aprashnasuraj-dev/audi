# Authenticated Capture Workaround

This path exists for cases where a GitHub-hosted runner is challenged or blocked by Minly's edge/CDN before the normal authenticated application surface is reached.

It is **not** a CloudFront/WAF bypass. The researcher uses the normal Minly website from their own browser and own authorized account, exports the requests that their browser naturally made, and the repository analyzes that capture offline. The offline workflow generates no Minly target traffic.

## What the workflow accepts

The workflow `Minly VDP Authenticated HAR Audit` expects two GitHub Actions secrets:

- `MINLY_AUTHENTICATED_HAR_URL` — an HTTPS URL to a temporary/private HAR file captured from the researcher's own normal Minly session. A short-lived signed HTTPS URL is acceptable.
- `MINLY_AUTHENTICATED_HAR_SHA256` — the exact SHA-256 of that HAR file.

Do not commit the HAR to this public repository. HAR files can contain cookies, authorization material, PII, and account data.

## Capture procedure

1. Sign into the researcher's own Minly account in Chrome/Edge using the normal site.
2. Open Developer Tools -> Network.
3. Turn on `Preserve log` only if needed to capture a multi-page normal workflow.
4. Clear the Network panel before the test session.
5. Exercise ordinary in-scope workflows using only researcher-owned data. Useful coverage includes account/profile, creator browsing, booking/order flows, payments/wallet screens that can be safely viewed, messages, uploads/media, session/recovery flows, and other services exposed through normal UI.
6. Do not access another user's private objects, brute-force identifiers, submit disruptive actions, or intentionally create high request volume.
7. Export the capture as HAR **with content** if the browser offers that option. The offline mapper will persist only sanitized metadata; response/request bodies and credential/header values are not copied into the published audit artifact.
8. Store the HAR somewhere private with a temporary HTTPS download link.
9. Compute its SHA-256 locally and set the two GitHub secrets above.
10. Run Actions -> `Minly VDP Authenticated HAR Audit`, re-confirming current program scope.

## What is retained

The sanitized output keeps only information useful for human review:

- exact `minly.com` methods and normalized paths,
- parameter names but not parameter values,
- status codes,
- request/response header **names** but not values,
- top-level JSON field names where available,
- candidate type and source HAR entry index,
- hashed metadata for same-origin JavaScript analyzed ephemerally.

Third-party HAR entries are ignored for testing and counted only as out-of-scope observations.

## Candidate policy

Every generated item is labeled `Unverified`. A candidate becomes submission-ready only after a human demonstrates a reproducible vulnerability and concrete impact using authorized researcher-controlled data. The final submission must include the exact VRT category, location, numbered reproduction, PoC evidence, and the statement `As an attacker, I could...` backed by the demonstrated result.

Missing headers, version disclosure, self-XSS, scanner-only issues, and other Minly-listed exclusions must not be promoted merely because automated tooling sees them.
