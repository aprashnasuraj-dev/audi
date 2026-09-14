# Latent Risk Register Template

Do not commit live identifiers, tokens, screenshots, or unpublished vulnerability details to the public repository. Use this structure privately or with sanitized placeholders.

| Field | Value |
| --- | --- |
| Candidate ID | `MINLY-RISK-XX` |
| Evidence label | Observed / Inferred / Hypothesis / Confirmed |
| Current classification | confirmed_exploitable / security_weakness / latent_vulnerability / attack_path_precursor / security_enhancement |
| In-scope asset | `https://minly.com/` / Android / iOS |
| Workflow | |
| Actor / role | |
| Researcher-owned object class | |
| Trust assumption | |
| Current control that keeps it safe | |
| Evidence observed | |
| Plausible failure mode | |
| Product/deployment change that could increase risk | |
| Minimum safe validation | |
| Stop condition | |
| Expected secure behavior | |
| Actual behavior | |
| Present security impact | |
| Potential impact if assumption fails | |
| Reproduction status | Not tested / rejected / partially supported / confirmed |
| Submission ready? | No / Yes |
| Why / why not | |

## Promotion rules

### Hypothesis -> security weakness

Requires direct evidence that a security invariant is weak, inconsistent, client-dependent, stale, or incompletely enforced.

### Security weakness -> confirmed exploitable

Requires:

- manual reproduction;
- current, not hypothetical, impact;
- an in-scope Minly asset;
- own-account / researcher-owned data proof;
- no destructive or high-volume behavior;
- evidence sufficient for Minly to reproduce.

### Confirmed exploitable -> submission

Still requires the normal finding eligibility gate. A confirmed issue may remain unsubmitted if it is explicitly out of scope or duplicate/known.

## Close reasons

Use an explicit close reason instead of deleting failed hypotheses:

- secure server-side enforcement confirmed;
- UI-only difference with no backend impact;
- third-party-only boundary;
- requires prohibited testing;
- best-practice-only;
- scanner/static signal not reproducible;
- product feature not present;
- insufficient current impact;
- duplicate of another candidate;
- stopped due to privacy/non-public-data condition.
