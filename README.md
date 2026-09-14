# HALO Audit

HALO is a bounded, evidence-first application audit runner for explicitly authorized targets. It combines browser-executed discovery, authenticated session validation, conservative cross-identity replay, passive contract telemetry, hardening checks, explicit coverage accounting, reproduction gates, and privacy-preserving reporting.

The repository is designed to fail closed: missing authorization context, stale scope, incomplete required coverage, invalid authentication, exhausted request budgets, rate-limit signals, or unsupported reproduction paths prevent a run from being treated as a clean result.

## Architecture

### 1. Scope and live-safety boundary

Each target is defined in `config/targets.yml` with an exact seed host. Live targets use:

- exact `allow_hosts` for seed authorization,
- optional navigation-derived authenticated-flow suffixes rather than wildcard enumeration,
- explicit denied hosts,
- a dated scope snapshot and maximum age,
- a shared request budget,
- per-host request pacing,
- stop-on-429 behavior,
- required-family and minimum-coverage publication gates.

`src/halo/live_safety.py` and the browser/replay layers enforce these rules. A discovered host is not automatically trusted merely because it shares a parent domain; transition evidence must be captured and accepted by the configured policy.

### 2. Identity and authenticated browser sessions

`config/identities.yml` supports anonymous, header/cookie, bearer-token, and Playwright storage-state identities. Live browser identities are isolated per target/brand.

For storage-state identities HALO also requires an authentication proof check (`auth_check_url` plus an expected marker). An expired or unusable session therefore fails preflight/coverage instead of silently degrading to anonymous testing.

Secrets and storage-state JSON files are never committed. The GitHub workflow materializes storage state into an ephemeral runner directory from repository secrets and removes that operational dependency from source control.

### 3. Browser discovery and passive telemetry

Playwright executes the rendered application under each selected identity while enforcing scope and request limits before network transmission. Discovery records privacy-sanitized evidence including:

- rendered page/navigation flow,
- XHR/fetch requests,
- observed API paths and methods,
- passive GraphQL operation metadata, including observed POST metadata without actively issuing unsafe methods,
- WebSocket endpoint metadata,
- scope-transition provenance,
- edge/response metadata needed by downstream checks.

Third-party resource handling is policy controlled. Out-of-scope target navigation is blocked even when passive third-party resources are allowed.

### 4. Runtime verification

Runtime verification replays only safe `GET`/`HEAD` observations and compares semantic response fingerprints across identities. Captured authorization/cookie material is not blindly reused; the selected vault identity supplies its own state.

A response difference is a signal, not automatically a vulnerability. Higher-confidence authorization findings require narrower evidence, and all network reproduction consumes the same target request budget.

### 5. Implemented families

Every family emits an explicit `RAN`, `SKIPPED`, `FAILED`, or `TIMEOUT` coverage record.

- `browser-discovery` — JavaScript-aware discovery per identity
- `runtime-verification` — safe cross-identity replay and semantic comparison
- `web-hardening` — conservative response-policy observations such as HSTS/CSP
- `api-contract` — observed API paths/methods versus a declared OpenAPI contract
- `graphql-schema` — passively observed GraphQL operations versus a declared schema
- `container` — Trivy image vulnerability execution when configured
- `iac` — Trivy configuration/misconfiguration execution when configured
- `reproduction-verification` — final evidence admission gate when hypothesis mode is enabled

Optional families are never treated as successful merely because input is absent. Required families must actually run for publication to pass.

### 6. Integrity, canonicalization, and contextual triage

HALO keeps raw/normalized/excluded accounting so adapter result loss cannot silently become a zero-finding result. Canonicalization merges semantically equivalent observations while retaining the supporting tool evidence instead of inflating the issue count.

Technology applicability and contextual triage prevent irrelevant technology-specific checks from becoming canonical findings. Optional known-issue fingerprints can classify novelty conservatively without suppressing the underlying evidence.

### 7. Reproduction and hypothesis layer

When `--hypothesis` is enabled, findings are enriched and then re-verified before final admission. Replay findings are re-requested safely, contract findings are re-checked against their declared inputs and passive observations, and supported local-tool findings can be confirmed by repeat execution. Unsupported reproduction types fail closed rather than disappearing silently.

### 8. Privacy-preserving reporting

Persisted reports are sanitized before publication. Sensitive headers, cookies, OAuth/session query values, and other credential-like values are redacted while preserving enough route and evidence context for review.

The combined bundle can include:

- `report.json`
- `report.md`
- `report.html`
- `report.pdf`
- `findings.sarif`
- `sbom.cdx.json`
- `vex.openvex.json`
- per-target run evidence and coverage metadata

## Preflight

`python scripts/preflight.py` performs a zero-target-traffic readiness check. For live targets it validates the configured scope, scope freshness, identity availability, operational authentication material, required settings, and local family inputs before a browser is launched.

Examples:

```bash
python scripts/preflight.py --target web-app
python scripts/preflight.py --live-only
```

A live run should not be considered ready until preflight succeeds with the intended authenticated identity/session material present.

## Local verification

Install the package and browser dependencies:

```bash
python -m pip install -e '.[all]'
python -m playwright install chromium
python -m pytest
python -m compileall -q src tests scripts
```

Run the seeded mock target:

```bash
export HALO_MOCK_USER_TOKEN=user-token
export HALO_MOCK_ADMIN_TOKEN=admin-token
python scripts/serve-mock.py &
python scripts/run-audit.py \
  --target mock-local \
  --hypothesis \
  --phase2-gate \
  --output artifacts/local
```

The seeded acceptance gate proves authenticated discovery, API discovery beyond the SPA shell, cross-identity replay, and detection of the planted non-admin/admin-surface weakness.

## Live GitHub Actions workflow

`.github/workflows/audit.yml` is manually dispatched. Select exactly one authorized target or `all-live`, confirm the configured authorization scope, and optionally enable hypothesis/reproduction mode.

For each live browser identity configure the matching GitHub Actions secrets. For example the `web-app` identity uses:

```text
HALO_WEB_USER_STORAGE_STATE_B64
HALO_WEB_USER_AUTH_CHECK_URL
HALO_WEB_USER_AUTH_CHECK_CONTAINS
```

The storage-state secret is the base64 encoding of a Playwright storage-state JSON file. Equivalent target-specific variables exist for NetworkSolutions, Bluehost, and HostGator. The workflow materializes these only inside the runner temporary directory, runs zero-traffic preflight, installs the pinned toolchain, executes the selected target, and uploads the report bundle.

## Tool integrity

`config/tool-versions.yml` pins Trivy. `scripts/install-trivy.sh` verifies the publisher checksum manifest against its pinned digest and then verifies the downloaded release artifact before installation. GitHub Actions are pinned to immutable commit SHAs.

## Interpretation rules

- A zero-finding family is meaningful only when its coverage record shows successful execution.
- `SKIPPED` is not equivalent to `RAN`.
- A response differential is evidence, not automatically an exploitable defect.
- Contract drift and missing hardening headers are observations whose practical impact depends on context.
- Canonical issue counts are deduplicated issue counts, while corroborating observations remain attached as evidence.
- Live results are publishable only when scope, authentication, required-family coverage, integrity accounting, and configured publication gates pass.

Use HALO only against targets for which you have current authorization and keep `config/targets.yml` synchronized with that authorization boundary.
