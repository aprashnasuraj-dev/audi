# AI-Assisted Review Protocol

AI is used to widen coverage, challenge assumptions, correlate evidence, and prioritize manual validation. It must not invent evidence, silently infer exploitability, or turn a defensive recommendation into a vulnerability claim.

## Evidence labels

Every AI-generated statement must use one of these labels:

- **Observed** — directly present in sanitized evidence from an in-scope asset or researcher-owned account.
- **Inferred** — strongly supported by observed evidence but not directly tested.
- **Hypothesis** — plausible security question requiring validation.
- **Confirmed** — manually reproduced with demonstrated security impact.

Only **Confirmed** issues may enter the submission pipeline.

## Review passes

### Pass 1 — Trust-boundary reconstruction

For each normal product workflow, identify:

- actor / role;
- object owner;
- server-side state;
- client-controlled fields;
- security-sensitive transitions;
- async/background processing;
- callback/redirect/deep-link edges;
- web/mobile parity assumptions;
- cached/personalized response boundaries.

### Pass 2 — Assumption challenge

Ask what keeps the operation safe today:

- UI hiding?
- server authorization?
- unguessable identifier?
- feature flag?
- single-use token?
- current cache behavior?
- client type?
- sequence/order of steps?
- background worker timing?
- current entitlement state?

If safety depends on anything other than a durable server-side invariant, create a latent-risk hypothesis.

### Pass 3 — Future-change analysis

For each latent hypothesis, ask whether a realistic product change could make it exploitable:

- new mobile/web client;
- API reuse;
- feature flag rollout;
- caching/CDN optimization;
- async worker/retry behavior;
- new creator/customer role;
- new payment/booking state;
- deep-link expansion;
- new media type;
- token/session lifecycle change;
- new integration/callback.

Future-risk analysis is for prioritization and remediation advice. It is not reportable until a present, demonstrable security impact exists.

### Pass 4 — Minimal falsification experiment

Generate the smallest safe experiment that could disprove the safety assumption. It must:

- use only researcher-controlled accounts/data;
- avoid enumeration;
- avoid high-volume automation;
- be reversible;
- stop after sufficient proof;
- never require destructive action;
- remain on an explicitly in-scope Minly asset.

### Pass 5 — Severity discipline

Do not assign P1/P2/P3 based on potential alone. Severity requires confirmed impact. High-impact hypotheses should be prioritized first, but a hypothesis remains unconfirmed until manually demonstrated.

## AI review output schema

Each reviewed candidate should include:

- `evidence_label`
- `asset`
- `workflow`
- `actor_role`
- `owned_object`
- `trust_assumption`
- `observed_evidence`
- `plausible_failure_mode`
- `future_change_that_increases_risk`
- `minimum_safe_validation`
- `stop_condition`
- `expected_secure_behavior`
- `actual_behavior`
- `impact_if_confirmed`
- `current_classification`
- `submission_ready`

## Non-negotiable rule

A strong audit is allowed to produce many valuable latent-risk items and zero submission-ready vulnerabilities. The audit is successful when it increases assurance without manufacturing severity.
