# MCP & AI Orchestration Layer

This directory wires the requested MCP/AI layer into the Minly audit repository as a scoped planning and guardrail layer.

## Correct policy interpretation

Scanning is not disabled. The gate separates:

1. **Controlled scoped scanning** — allowed when it is exact-host, low-rate, bounded, non-destructive, and sanitized.
2. **Own-account testing** — allowed for authenticated checks when both identities and objects are researcher-controlled.
3. **Uncontrolled scanning/reporting** — blocked when it is off-scope, high-volume, destructive, privacy-invasive, brute-force, blind ID enumeration, or scanner-only reporting.

## What is implemented

- `orchestrator.py` accepts a natural-language instruction and returns a scoped execution decision.
- `configs/mcp/minly-safe-orchestration.yml` defines exact-host scope, low-rate limits, controlled scanner policy, and CI behavior.
- External MCP servers are represented as example configs only; credentials and server URLs must not be committed.
- CI verifies that controlled scanner plans are accepted, while uncontrolled scanner behavior remains blocked.

## What is intentionally blocked

The orchestrator blocks WAF-bypass-as-a-goal, credential attacks, destructive testing, third-party target testing, blind object/user/order/account ID enumeration, and unbounded scanner execution. That does **not** mean no scanning and does **not** mean no testing.

## CI wiring

The corrected final audit workflow runs the orchestrator, bounded built-in audit families, static mobile analysis, candidate ranking, and report generation. Final reports still treat automated output as candidate material until manual reproduction proves concrete Minly impact.
