# HALO Audit

A clean security-audit pipeline rebuilt from first principles around four constraints:

1. identity-aware authenticated testing,
2. browser-executed discovery for modern SPAs,
3. safe cross-identity replay for authorization differentials,
4. explicit family coverage states so missing inputs never look like clean passes.

The implementation is staged. Phase 1 builds the foundation and a seeded mock target. Phase 2 proves the spine against that target. Phase 3 adds hypothesis enrichment only after the verification gates are green. Phase 4 runs every configured target and emits combined machine- and human-readable reports.

## Safety boundary

Network work is scope- and budget-bound. Browser discovery may observe application traffic, but the initial replay transport permits GET/HEAD only. Unsupported or missing inputs produce `SKIPPED` with a reason rather than `PASS`.

## Status

Clean-room rebuild started on 2026-09-14.
