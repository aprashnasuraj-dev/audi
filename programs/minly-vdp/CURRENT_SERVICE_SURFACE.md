# Current Minly Service Surface and Scope Boundaries

Snapshot date: 2026-09-14

This map is derived from normal public product presentation and the supplied VDP scope. It is a research-planning artifact, not a finding list.

## In-scope web surface

The explicitly listed website asset is `https://minly.com/`. Treat paths under that exact host as the website surface. Do not infer that sibling subdomains are authorized.

### Publicly visible service families

1. **Celebrity discovery and booking**
   - celebrity/category browsing;
   - creator profiles;
   - booking/request entry points;
   - personalized video/request experiences where offered.

2. **Private fan/creator engagement**
   - public product material references private messaging / direct engagement;
   - treat message/thread IDs, attachments, voice content, and conversation state as high-value authorization objects once observed on a researcher-owned account.

3. **Online events and on-demand content**
   - live/online event listings;
   - sold-out/past-event state;
   - on-demand event content;
   - entitlement, ticket, replay, stream and purchase objects are high-value state-machine targets if legitimately present on the researcher account.

4. **Business/brand engagement**
   - Minly Business entry point;
   - brand-to-celebrity collaboration or inquiry flows;
   - ordinary-user testing must not assume business/creator privileges; if elevated privileges are required, follow the program's report-first rule.

5. **Creator/talent enrollment**
   - public enrollment/join entry point;
   - examine only researcher-owned application state;
   - prioritize status/role transition boundaries rather than attempting to obtain elevated privileges.

6. **Public gifted/shared media pages**
   - publicly accessible media/share pages may expose stable object references;
   - public accessibility by itself is not an authorization issue;
   - record how public/private state, download capability, revocation and ownership are represented for researcher-owned content.

7. **Mobile application entry points**
   - Android package `com.minly.users`;
   - iOS App Store ID `1528802350`;
   - compare mobile/backend authorization with equivalent web actions when the same own-account object is visible on both clients.

## Observed boundary that is not automatically in scope

Normal product navigation/search results may reveal sibling hosts such as `merch.minly.com`. The supplied VDP scope lists the website as `minly.com` and states that services/domains not explicitly listed are out of scope. Therefore:

- do not crawl, scan, fuzz, authenticate to, or test `merch.minly.com` under this blueprint;
- record the handoff only as a **scope boundary observation**;
- do not treat a Minly brand name or shared parent domain as authorization to test a sibling host;
- if Minly later adds the sibling host explicitly, create a new dated scope snapshot before testing.

## High-value object/state inventory

For every object actually observed through normal use, capture only the class and ownership model in the public repo; keep live identifiers private.

| Surface | Candidate object/state | Primary security invariant |
| --- | --- | --- |
| Account | profile, settings, session, recovery state | only the account owner may read/change sensitive state |
| Booking/request | request, draft, status, recipient, instructions | request ownership and state transitions are server enforced |
| Messaging | thread, message, voice/media attachment | participants and ownership are enforced server-side |
| Events | ticket, entitlement, replay/on-demand access | access is bound to valid current entitlement |
| Media | personalized video, public/private flag, download | visibility/download state cannot cross ownership/privacy rules |
| Payment/order | order, amount, currency, discount, refund state | value and state transitions are server controlled |
| Creator enrollment | application, status, role transition | ordinary users cannot self-promote or alter privileged state |
| Business inquiry | request, contact, status | data/role boundaries remain isolated |
| Notifications | event/order/message notification | notification objects remain account-bound |
| Mobile links | deep link/app link parameters | untrusted links cannot bind privileged state or bypass auth |
| Async processing | delayed fulfillment, media generation, notification, refund | worker rechecks current authorization/state before acting |
| Cache/CDN | personalized/public content variant | cache key includes the authorization/privacy context required |

## Border-scope review questions

These are allowed as **reasoning questions** even when the adjacent system is out of scope:

- Does an in-scope Minly page expose a callback URL that later leaves scope?
- Does the in-scope application trust data returned from an external processor?
- Does an in-scope page leak sensitive state into a redirect, URL, referrer, or client-visible token before handoff?
- Does the in-scope backend enforce authorization before delegating to an external service?
- Does returning from an external flow allow stale/forged state to be accepted by the in-scope asset?

Test only the Minly side of the boundary. Do not probe the external service.

## Scope discipline

A service can be interesting without being testable. The audit should map every boundary, but active testing remains limited to assets explicitly authorized by the VDP.
