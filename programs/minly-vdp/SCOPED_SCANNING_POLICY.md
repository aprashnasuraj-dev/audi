# Scoped Scanning and Own-Account Testing Policy

This note fixes the audit interpretation used by the Minly workflow.

## Correct interpretation

- **No high-volume automated scanning** does not mean no scanning.
- **Own-account-only testing** does not mean no testing.
- **No scanner-only submissions** does not mean scanners are useless.
- **No public disclosure of live findings** does not mean the workflow cannot create a private/sanitized audit bundle.

## Allowed audit work

The audit may run controlled scanning and analysis when all of these are true:

1. The target is exactly in scope, currently `https://minly.com/` / host `minly.com`.
2. The action is low-rate, bounded, non-destructive, and stops on rate limiting.
3. Authenticated testing uses only researcher-controlled Account A and Account B.
4. Scanner output is treated as a candidate queue, not a final vulnerability.
5. Public repository output is sanitized and contains no live findings, raw HAR, tokens, screenshots, or unpublished report evidence.

## Blocked audit work

The workflow and orchestrator must block:

- off-scope hosts, subdomain/port sweeps, and third-party provider testing;
- destructive, availability-impacting, brute-force, or credential attacks;
- blind object/user/order/account ID enumeration;
- WAF bypass or payload evasion as an objective;
- scanner-only report promotion without manual reproduction and concrete Minly impact;
- committing private evidence or live findings to the public repository.

## Practical rule

Use scanners to create leads. Use owned-account manual reproduction to prove impact. Use sanitized reports for CI artifacts. Keep sensitive evidence private and remove transient artifacts after use.
