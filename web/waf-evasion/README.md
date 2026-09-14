# WAF Evasion Module Status

This module is deliberately **not wired to generate or run WAF bypass payloads**.

Reason: the Minly workflow is constrained to low-impact, exact-scope, privacy-preserving VDP testing. Context-aware WAF bypass payload generation can easily cross into prohibited active exploitation, high-volume probing, or disruptive testing.

Allowed replacement workflow:

1. Record the application behavior from a normal researcher-owned flow.
2. Identify whether input handling creates a concrete security boundary failure.
3. Use the smallest benign payload needed to prove impact.
4. Stop after minimum evidence.
5. Do not automate evasion or payload mutation in CI.

The CI gate verifies that this directory exists as a blocked/controlled module, not as an active payload generator.
