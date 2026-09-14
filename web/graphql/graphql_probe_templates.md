# GraphQL Manual Probe Templates

These are templates for a private, researcher-owned session only. They are not run in CI.

## Safe first checks

- Confirm whether a GraphQL endpoint is naturally observed in browser/mobile traffic.
- Do not brute-force paths.
- Do not query third-party GraphQL services.

## Introspection caution

Run introspection only when the endpoint is in exact Minly scope, observed through normal use, and allowed by program rules. Treat schema visibility alone as informational unless a real authorization or data exposure impact is proven.

## Authorization review questions

- Does Account B receive Account A private object fields?
- Can Account B mutate Account A object state?
- Are admin/creator fields reachable from an ordinary user?
- Are object IDs accepted without ownership verification?

Every proof must use only Account A / Account B controlled data.
