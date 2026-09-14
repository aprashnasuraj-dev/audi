# Minly Final Audit Module Wiring

This document records how the requested MCP, recon, web, mobile, and API modules are wired into the corrected one-shot Minly final audit.

## Wiring summary

- `configs/mcp/` stores safe MCP server configuration examples and the authoritative module policy.
- `ai/mcp-orchestrator/orchestrator.py` converts natural-language instructions into scoped dry-run plans.
- `recon/` contains local/offline recon helpers for JavaScript surface extraction and historical URL classification.
- `web/` contains manual business-logic/JWT/GraphQL/IDOR review helpers, plus a deliberately blocked WAF-evasion module.
- `mobile/` contains Android/iOS static and local secret-scanning workflow wrappers; dynamic bypass work is documented as private-lab only and not run in CI.
- `api/` contains local OpenAPI, BOLA/IDOR, mass-assignment, and low-impact rate-limit planning helpers.
- `tests/test_minly_module_gates.py` verifies the guardrails.
- `.github/workflows/minly-final-audit-corrected-once.yml` compiles the new scripts and runs the module guardrail tests before audit execution.

## Safety decisions

The requested tool families include capabilities that can become high-impact or out-of-scope if run blindly. Therefore this implementation emphasizes reproducibility and safe orchestration:

- no high-volume recon from CI;
- no subdomain expansion when scope is exact-host `minly.com`;
- no WAF-bypass payload generation;
- no blind object-ID enumeration;
- no live Frida/Objection bypass scripts in the public repository;
- no active API traffic generation from the helper modules;
- every candidate remains unverified until manually proven with researcher-controlled data.

## CI expectation

The corrected final audit workflow should fail early if:

- exact Minly scope changes unexpectedly;
- module policy no longer requires manual confirmation;
- an active dangerous command is accepted by the orchestrator;
- key module files disappear;
- Python helper scripts stop compiling.
