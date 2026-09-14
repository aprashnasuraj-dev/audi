# High-Impact Research Queue

Purpose: prioritize hypotheses capable of producing meaningful P1-P3 impact **if confirmed**, while staying within Minly's VDP rules. None of these entries is a vulnerability claim.

Use only researcher-controlled accounts and objects. Stop after the minimum proof. Never enumerate unrelated identifiers.

| Priority | Hypothesis family | Why it could matter if confirmed | Minimum safe validation |
| --- | --- | --- | --- |
| 1 | Cross-account request/booking ownership | unauthorized read/write/cancel could affect another user's transaction or private request | create benign object in Account A; use Account B only against that known A object; stop on first definitive result |
| 2 | Private message/thread isolation | unauthorized access to private communications can have high confidentiality impact | use only A/B researcher accounts and a benign thread; compare read/send authorization |
| 3 | Session invalidation after credential/recovery change | stale sessions may enable account takeover persistence | change researcher-owned account credential/recovery state and test one previously valid session |
| 4 | Recovery artifact replay/state confusion | reusable recovery artifacts can enable account takeover | use only own account and a single stale/replayed artifact after legitimate state change |
| 5 | Event/on-demand entitlement isolation | entitlement bypass can expose paid/private content | use only researcher-owned entitlement and anonymous/second research account comparison |
| 6 | Public/private media transition consistency | private personalized media exposed after privacy-state changes can leak sensitive content | create/observe own media; change privacy state once and compare owned/anonymous visibility |
| 7 | Creator/business role transition enforcement | client-controlled approval/status could lead to privilege escalation | inspect own enrollment/application state; alter only a benign status/role field if observed and reversible |
| 8 | Mobile/web backend authorization parity | one client may rely on UI checks while backend accepts unauthorized operations | compare the same researcher-owned object/action across web and mobile clients |
| 9 | Client-controlled price/amount/currency fields | server trusting client value can create material financial/business impact | on a reversible/non-final own flow, change one value field and verify server correction/rejection |
| 10 | Coupon/discount/order invariant enforcement | state-machine weakness may alter economic outcome | use own account and a non-loss test; modify one observed discount/invariant field and stop before real loss |
| 11 | Payment/callback account binding | mismatched callback/order/account state can mis-credit entitlements | test only Minly-side state using researcher-owned transaction context; never probe payment provider |
| 12 | Async worker stale authorization | queued action may execute after authorization/ownership is revoked | queue one reversible own action, change current state, observe whether worker rechecks authority |
| 13 | Refund/cancel idempotency/state replay | repeated state transition could duplicate value or inconsistent entitlement | one safe duplicate/replay attempt using own reversible object only |
| 14 | Cache/CDN authorization-context mismatch | personalized/private content may be served across sessions | compare own authenticated vs anonymous response variants; never target another user |
| 15 | Download/media URL transferability | bearer-style media URLs may bypass current ownership/entitlement | test only researcher-owned media URL between own sessions/accounts |
| 16 | Deep-link privileged object binding | crafted app links may open/act on objects without normal auth checks | use researcher-owned object ID in a benign deep link and verify backend enforcement |
| 17 | WebView/native bridge trust | untrusted web content may invoke privileged native actions | on researcher device/account, test only benign bridge invocation and stop before external-user impact |
| 18 | Hidden UI action without backend authorization | backend may expose privileged action that UI merely hides | only test an action directly observed in normal product traffic; no endpoint guessing |
| 19 | Notification/history object ownership | notifications can reveal private order/message metadata | compare one known researcher-owned notification/history object across A/B accounts |
| 20 | Account-switch stale object/session state | client may retain A context after switching to B | perform normal account switch and test one previously visible A-owned object from B session |
| 21 | Attachment/media authorization inheritance | message/thread authorization may not protect attachment URL | create benign own attachment and compare authorized vs unauthorized own-account context |
| 22 | Creator/customer boundary confusion | actions intended for one actor class may cross roles | use researcher-owned ordinary accounts only; do not seek elevated privileges without report-first approval |
| 23 | Feature-flag/rollout authorization | hidden feature may be callable before intended entitlement | test only if an operation is naturally observed; verify backend checks independent of UI flag |
| 24 | Cancellation vs fulfillment race/state mismatch | background fulfillment may ignore current cancellation state | one reversible own object only; avoid timing floods or concurrency stress |

## Promotion criteria

A queue item becomes a **confirmed exploitable issue** only after:

- the current product actually exposes the relevant workflow;
- manual reproduction succeeds;
- impact is current and demonstrated, not hypothetical;
- all data/objects are researcher controlled;
- the result passes `FINDING_ELIGIBILITY_GATE.md`;
- evidence is minimal and privacy-safe.

## Severity discipline

A hypothesis that *could* be P1/P2/P3 is not assigned that severity until present impact is proven. The queue is ordered by upside for research effort, not by pre-judged severity.
