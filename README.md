# HALO Audit

A clean-room security-audit pipeline centered on authenticated application testing, browser discovery, cross-identity replay, explicit coverage states, and reproduction-gated reporting.

## Architecture

### Phase 1 — Foundation

- **Identity vault**: `config/identities.yml` resolves secrets from environment variables and guarantees an `anonymous` identity. Network-facing adapters are required to inherit the vault-bound adapter contract.
- **Browser discovery**: Playwright executes JavaScript, crawls same-scope pages, captures XHR/fetch traffic, and records discovered URLs separately for each identity.
- **Replay transport**: captured GET/HEAD requests are replayed under identity pairs and response fingerprints are compared. Authorization headers/cookies from the captured request are stripped and replaced by the selected identity.
- **Input gates**: OpenAPI, GraphQL, container, and IaC families emit explicit `SKIPPED` reasons when required input is absent. Input-present families without an executor are `FAILED`, never silently treated as clean.
- **Seeded target**: the built-in mock SPA intentionally lets a normal `user` read `/api/admin/secret`. CI must detect this before any scaling work is trusted.

### Phase 2 — Verification gate

The seeded acceptance test requires all of the following:

1. authenticated findings > 0,
2. browser discovery reaches API URLs beyond the SPA shell,
3. cross-identity replay detects at least one response difference,
4. the planted non-admin/admin-surface weakness is detected.

### Phase 3 — Hypothesis layer

Optional enrichment runs only after the foundation is usable:

- threat-model enrichment,
- chain composition (chains remain hypotheses),
- reproduction verification before candidates are admitted to the final report.

Unknown finding types fail closed at the reproduction boundary until a dedicated verifier exists.

### Phase 4 — Combined run and report

`scripts/run-audit.py` can run one or all targets from `config/targets.yml`. Every family reports one of:

`RAN | SKIPPED | FAILED | TIMEOUT`

The combined output includes:

- `report.json`
- `report.md`
- `report.html`
- `report.pdf`
- `findings.sarif`
- `sbom.cdx.json`
- `vex.openvex.json`

## Safety boundary

- network targets are restricted by an explicit host allowlist,
- replay permits **GET/HEAD only**,
- redirects are not automatically followed by replay,
- captured authorization/cookie headers are never blindly reused,
- browser discovery observes application traffic but replay remains method-bounded,
- missing coverage is never reported as a clean pass.

## Quick verification

```bash
python -m pip install -e '.[all]'
python -m playwright install chromium
python -m pytest tests/test_foundation.py tests/test_hypothesis_reporting.py tests/test_adapter_contract.py
python -m pytest tests/test_mock_pipeline.py
```

For the integrated mock run:

```bash
export HALO_USER_TOKEN=user-token
export HALO_ADMIN_TOKEN=admin-token
python scripts/serve-mock.py &
python scripts/run-audit.py --target mock-local --hypothesis --phase2-gate --output artifacts/local
```

## Current limitation

The clean foundation intentionally does **not** pretend every optional family is implemented. `api-contract`, `graphql-schema`, `container`, and `iac` are gated today; if required input exists but an executor does not, the family is reported as `FAILED`. That is deliberate: unimplemented coverage must never look like a clean security result.
