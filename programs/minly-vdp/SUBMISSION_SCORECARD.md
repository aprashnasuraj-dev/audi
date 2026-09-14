# Submission Candidate Scorecard

Use this after the eligibility gate. This is an internal prioritization aid, not Minly's official severity system.

Score each dimension from 0-3.

## 1. Scope certainty

- 0 — third-party or unclear ownership.
- 1 — related to Minly but asset ownership is uncertain.
- 2 — clearly on an in-scope asset.
- 3 — clearly on an in-scope asset and directly tied to a documented Minly feature.

## 2. Manual reproducibility

- 0 — scanner-only or intermittent.
- 1 — observed once, not reliably reproduced.
- 2 — reproduced manually twice.
- 3 — clean, deterministic reproduction with minimal steps.

## 3. Security impact

- 0 — best practice/configuration only.
- 1 — weak or speculative impact.
- 2 — concrete confidentiality/integrity/authorization consequence on researcher-controlled data.
- 3 — strong account/privilege/business-impact boundary failure demonstrated safely.

## 4. Program fit

- 0 — explicitly excluded.
- 1 — adjacent to an exclusion and difficult to distinguish.
- 2 — not excluded and impact is clear.
- 3 — high-confidence fit with program rules and safe-harbor conditions.

## 5. Evidence quality

- 0 — incomplete or contains sensitive/unrelated data.
- 1 — basic screenshots only.
- 2 — clear steps plus redacted request/response or mobile evidence.
- 3 — concise, independently reproducible evidence with expected-vs-actual behavior and retest criteria.

## 6. Duplicate risk

- 0 — common best-practice issue or obvious generic finding.
- 1 — common bug class in a generic surface.
- 2 — product-specific logic or less obvious boundary.
- 3 — unique chain/invariant tied to Minly behavior.

## Decision thresholds

- **15-18 — submit now:** strong candidate; finalize human review and report.
- **11-14 — strengthen proof:** likely worthwhile, but improve impact/evidence first.
- **7-10 — low priority:** keep notes privately; do not rush submission.
- **0-6 — do not submit:** likely excluded, weak, or scanner/best-practice-only.

## Mandatory overrides

Regardless of score, do not submit if:

- it required accessing another user's data;
- it required prohibited/high-volume testing;
- it is only an excluded best-practice issue;
- the evidence cannot be safely shared;
- the affected asset is not explicitly in scope.
