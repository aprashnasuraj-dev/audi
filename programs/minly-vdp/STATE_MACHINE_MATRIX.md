# Minly State-Machine Audit Matrix

Use this matrix to reason about transitions that can become vulnerable even when each individual endpoint appears correct. Fill only with researcher-owned observations.

## Transition review method

For each workflow:

1. identify the current state;
2. identify the actor/role allowed to request the transition;
3. identify server-side predicates that must be true;
4. identify fields the client can influence;
5. identify delayed/background work triggered by the transition;
6. identify whether authorization is rechecked at execution time;
7. test only one reversible transition needed to validate the hypothesis.

## Account/session lifecycle

| From | To | Expected invariant | Latent-risk questions |
| --- | --- | --- | --- |
| anonymous | authenticated | server verifies account ownership/authentication | can stale client state or alternate client type skip part of the transition? |
| authenticated | logged out | protected actions require a valid current session | do background/API clients remain usable unexpectedly? |
| authenticated | password/recovery changed | old sensitive artifacts should lose power as appropriate | are old recovery/session artifacts still accepted where impact exists? |
| active account | deletion requested | deletion is bound to owner and protected from replay | can another client/session cancel/alter deletion state incorrectly? |

## Booking/request lifecycle

| From | To | Expected invariant | Latent-risk questions |
| --- | --- | --- | --- |
| draft/new | submitted | owner, service, price and recipient state are server validated | can client-controlled fields change server-derived values? |
| submitted | accepted/in progress | only intended privileged actor/system changes status | is status authorization enforced beyond UI? |
| submitted | cancelled | only authorized owner/system can cancel | can stale request IDs or alternate client routes cross ownership? |
| completed | downloadable/viewable | media visibility matches request privacy/ownership | does public/private state persist consistently across cache/mobile/web? |

## Messaging lifecycle

| From | To | Expected invariant | Latent-risk questions |
| --- | --- | --- | --- |
| no thread | thread created | only intended participants are bound to thread | can client choose participants outside server policy? |
| thread active | message/voice sent | sender is authorized participant | does attachment/media access inherit thread authorization? |
| thread hidden/closed | reopened/continued | server enforces current relationship/state | can old client state or stale token restore access? |

## Event/entitlement lifecycle

| From | To | Expected invariant | Latent-risk questions |
| --- | --- | --- | --- |
| no entitlement | purchased/granted | entitlement derives from valid server-side transaction/state | can client claim purchase/status without server proof? |
| entitled | event/replay access | authorization checked for each protected resource | is a media URL transferable or cached without entitlement context? |
| entitled | revoked/refunded/expired | access ceases according to product policy | do CDN/cache/mobile clients continue serving content after revocation? |

## Creator/business enrollment lifecycle

| From | To | Expected invariant | Latent-risk questions |
| --- | --- | --- | --- |
| ordinary user | application submitted | user controls only own application data | can role/status fields be client-controlled? |
| application submitted | approved/rejected | privileged decision only | are approval/status endpoints protected server-side? |
| ordinary user | creator/business capability | elevation occurs only after authorized approval | can feature flags or hidden UI actions expose privileged operations early? |

## Payment/order lifecycle

| From | To | Expected invariant | Latent-risk questions |
| --- | --- | --- | --- |
| quote/cart | pending | price/currency/discount derived or validated server-side | can amount/discount/currency be overridden by client fields? |
| pending | paid | payment proof is bound to exact order/account/value | can callback state be replayed or mismatched? |
| paid | fulfilled | fulfillment matches paid order and owner | can async worker act on stale or changed ownership/state? |
| paid | refunded | refund eligibility/value/state is server controlled | can one transition be repeated or raced without financial harm? |

## Deep-link/callback lifecycle

| From | To | Expected invariant | Latent-risk questions |
| --- | --- | --- | --- |
| external/untrusted link | app/web route | privileged state requires server-side authorization | can link parameters select account/order/redirect state directly? |
| external provider return | Minly callback accepted | anti-forgery/state binding and transaction/account match | can stale/forged callback state be accepted by Minly? |
| mobile link | native action | route cannot bypass normal auth/ownership checks | does mobile client expose actions hidden on web without backend enforcement? |

## Async/background lifecycle

Review any delayed action such as media processing, notification, fulfillment, entitlement grant, refund, or queued message.

Key invariant: **authorization and relevant business state should be valid when the worker acts, not only when work was queued.**

Potential latent failure patterns:

- account loses entitlement after work is queued but worker still publishes privileged output;
- object ownership changes but queued task uses stale owner information;
- cancellation occurs but worker completes the original action anyway;
- privacy/public flag changes but cached/generated media keeps old visibility;
- retry executes a state transition twice;
- callback arrives after order/account state changed and is accepted without revalidation.

These are hypotheses until demonstrated with a safe researcher-owned proof.
