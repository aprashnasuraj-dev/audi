# MCP & AI Orchestration Layer

This directory wires the requested MCP/AI layer into the Minly audit repository as a **manual-gated planning layer**.

## What is implemented

- `orchestrator.py` accepts a natural-language instruction and returns a scoped execution plan.
- `configs/mcp/minly-safe-orchestration.yml` defines exact-host scope, low-rate limits, and module policy.
- External MCP servers are represented as example configs only; credentials and server URLs must not be committed.

## What is intentionally blocked

The orchestrator does not run live scanners, WAF evasion payload generators, brute-force tools, object-ID enumeration, or third-party target tests. Those categories either conflict with the Minly guardrails or require a private, human-controlled lab with explicit permission.

## CI wiring

The corrected final audit workflow runs the orchestrator in dry-run mode and executes guardrail tests before the audit phases. This proves the modules are present and safely gated without adding uncontrolled traffic.
