# HALO Audit

A clean-room security-audit pipeline centered on authenticated application testing, browser discovery, cross-identity replay, explicit coverage states, and reproduction-gated reporting.

## Architecture

### Phase 1 — Foundation

- **Identity vault**: `config/identities.yml` resolves secrets from environment variables and guarantees an `anonymous` identity. Every network-facing DAST/API adapter must inherit the vault-bound adapter contract.
- **Browser discovery**: Playwright executes JavaScript, crawls same-scope pages, captures XHR/fetch traffic, and records discovered URLs separately for each identity. Out-of-scope HTTP(S) browser requests are blocked before transmission.
- **Replay transport**: captured GET/HEAD requests are replayed under identity pairs and response fingerprints are compared. Authorization headers/cookies from the captured request are stripped and replaced by the selected identity.
- **Shared request budget**: browser discovery, replay, and network reproduction consume the same per-target request budget. Exhaustion is a failure, not partial success.
- **Input gates**: OpenAPI, GraphQL, container, and IaC families emit explicit `SKIPPED` reasons when required input is absent.
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

Replay findings are re-requested, contract findings are re-checked against the declared contract plus a safe GET/HEAD replay, and Trivy findings are confirmed by a cached repeat scan. Unsupported finding types fail the reproduction family explicitly rather than disappearing silently.

### Phase 4 — Combined run and report

`scripts/run-audit.py` can run one or all targets from `config/targets.yml`. Every family reports one of:

`RAN | SKIPPED | FAILED | TIMEOUT`

Implemented gated families:

- `browser-discovery` — Playwright, per identity
- `runtime-verification` — cross-identity GET/HEAD replay
- `api-contract` — observed API surface versus OpenAPI
- `graphql-schema` — observed GET GraphQL operations versus declared schema
- `container` — Trivy image vulnerabilities
- `iac` — Trivy configuration/misconfiguration scanning
- `reproduction-verification` — Phase-3 final admission gate

The combined output includes:

- `report.json`
- `report.md`
- `report.html`
- `report.pdf`
- `findings.sarif`
- `sbom.cdx.json`
- `vex.openvex.json`

## Tool integrity

`config/tool-versions.yml` pins Trivy. `scripts/install-trivy.sh` first verifies the publisher's checksum manifest against a pinned SHA-256, then verifies the release tarball against that verified manifest before installation. CI actions are pinned to immutable commit SHAs.

## Safety boundary

- network targets are restricted by an explicit host allowlist,
- Playwright blocks out-of-scope HTTP(S) traffic before it leaves the browser,
- replay permits **GET/HEAD only**,
- redirects are not automatically followed by replay,
- captured authorization/cookie headers are never blindly reused,
- the target request budget is shared across browser discovery, replay, and reproduction,
- missing input is `SKIPPED`; execution/tool failures are `FAILED`; timeouts are `TIMEOUT`,
- missing coverage is never reported as a clean pass.

## Quick verification

```bash
python -m pip install -e '.[all]'
python -m playwright install chromium
python -m pytest \
  tests/test_foundation.py \
  tests/test_hypothesis_reporting.py \
  tests/test_adapter_contract.py \
  tests/test_optional_families.py
python -m pytest tests/test_mock_pipeline.py
```

For the integrated mock run:

```bash
export HALO_USER_TOKEN=user-token
export HALO_ADMIN_TOKEN=admin-token
python scripts/serve-mock.py &
python scripts/run-audit.py --target mock-local --hypothesis --phase2-gate --output artifacts/local
```

For IaC/container families, install the pinned Trivy build first:

```bash
bash scripts/install-trivy.sh
export PATH="$HOME/.local/bin:$PATH"
```

## Interpretation

A response differential is a **signal**, not automatically a vulnerability. The high-severity mock rule is deliberately narrower: it requires a non-admin identity to receive a successful response from an obvious `/admin` surface. Contract drift also does not imply exploitability. Final reporting keeps the evidence grade/confidence and requires the Phase-3 reproduction gate when `--hypothesis` is enabled.
