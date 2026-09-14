# Minly Advanced Audit Architecture

This blueprint extends the Minly VDP participation plan with a deeper, low-impact workflow that stays inside the exact program boundaries supplied by the researcher.

## Design goal

Go deeper without turning the program into a high-volume scanner exercise. The workflow is candidate-discovery oriented: it maps the public surface, extracts same-origin client-side signals, performs offline static analysis, and produces a manual verification queue. Nothing is submission-ready until a human reproduces impact using a researcher-controlled account and confirms the issue is in scope.

## Exact boundary

- Web seed: `https://minly.com/`
- Exact web host allowed for automated requests: `minly.com`
- No subdomain enumeration.
- No requests to third-party services for security testing.
- No password spraying, credential stuffing, brute force, fuzzing, path wordlists, destructive actions, or service-stress testing.
- No attempts to access another user's account or non-public data.
- Stop once a minimal proof is sufficient.

A browser may observe references to other hosts, but the research workflow records only the hostname as an external dependency and does not actively probe it.

## Deep workflow layers

### 1. Exact-scope public surface map

A throttled browser performs normal GET navigation from the exact seed only. It records:

- same-origin navigable pages;
- forms and their declared methods/actions without submitting them;
- same-origin JavaScript bundles;
- same-origin XHR/fetch/WebSocket endpoints already observed during ordinary page rendering;
- query-parameter names with values removed;
- redirect destinations;
- external dependency hostnames without probing them.

The crawler has hard page/request ceilings and an inter-request delay. State-changing form submission is disabled.

### 2. Client-side route and API candidate extraction

Same-origin JavaScript already retrieved by the browser is analyzed locally for candidate strings such as:

- REST-style paths and versioned API paths;
- GraphQL references;
- WebSocket endpoints;
- route names containing account, profile, order, payment, booking, creator, admin, role, permission, wallet, message, upload, or media concepts;
- object identifiers and parameter names that may be relevant to authorization testing.

These are candidates only. No extracted endpoint is automatically replayed.

### 3. Offline browser-code analysis

Downloaded same-origin scripts are analyzed locally for security-relevant client-side patterns:

- DOM injection sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`);
- dynamic code execution (`eval`, `Function`);
- `postMessage` receivers;
- local/session storage use;
- client-side authorization/role checks;
- redirect/navigation handling;
- token-like material with redacted output only.

Semgrep is used only on the temporary local copy of the JavaScript. Results are treated as hypotheses requiring manual validation.

### 4. Authorization-first manual queue

The generated manual queue prioritizes:

1. horizontal authorization between two researcher-controlled accounts;
2. vertical authorization boundaries visible to the user's own role;
3. object ownership checks for profile, booking/order, payment, creator, messaging, upload/media, and account resources;
4. state transition integrity and replay resistance;
5. business-logic consistency across website and mobile clients;
6. sensitive action confirmation and recovery flows.

A second researcher-controlled account is required before horizontal IDOR/BOLA conclusions are made. A single account can still be used for route mapping, vertical-access checks, workflow/state-machine testing, input handling, and business-logic review.

### 5. Submission gate

A candidate is reportable only after:

- exact in-scope asset confirmed on the day of testing;
- manual reproduction succeeds;
- impact is concrete, not a best-practice observation;
- only researcher-controlled accounts/data are used;
- minimal proof is captured and secrets are redacted;
- no prohibited testing method was needed.

## Toolchain roles

- Playwright: normal browser navigation and passive network observation.
- Semgrep: offline JavaScript candidate analysis only.
- Gitleaks: optional offline redacted candidate detection in same-origin public JavaScript; never print matched secret values.
- Python analyzer: scope enforcement, URL normalization, parameter redaction, route/API extraction, candidate scoring, and report generation.
- GitHub Actions: reproducible manual-dispatch runner with explicit authorization confirmation and artifact generation.

## What is deliberately excluded

The workflow does not include subdomain discovery, directory brute forcing, active ZAP scanning, Nuclei template sweeps, SQL injection automation, password attacks, mass fuzzing, vulnerability exploitation, or stress/load testing. Those would either conflict with the supplied Minly rules or create unacceptable volume/risk for this program.
