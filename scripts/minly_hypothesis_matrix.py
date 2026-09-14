#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

VALIDATION_MAP = {
    "object_ownership_and_authorization": "Use only two researcher-controlled accounts. Create an object in A and attempt the minimum equivalent read/write from B without guessing unrelated identifiers.",
    "role_and_entitlement_transitions": "Observe a legitimate entitlement/role change on the researcher account and verify server-side revocation across web/mobile/state transitions.",
    "session_and_recovery_state_machine": "Use only the researcher account to test whether session/recovery artifacts remain usable after a legitimate state transition such as reset, logout, or credential change.",
    "business_logic_invariants": "Identify one documented or UI-implied invariant, change one client-controlled variable, and verify the server enforces the invariant without causing financial loss.",
    "payment_booking_and_order_state_integrity": "Use reversible or non-monetary own-account flows to verify state transitions, ownership, amount and entitlement are server-controlled.",
    "creator_customer_boundary": "With researcher-owned identities only, test whether actions/data cross creator/customer boundaries beyond intended permissions.",
    "callback_redirect_and_deep_link_trust": "Use benign researcher-controlled destinations and normal app links to verify callbacks/deep links cannot redirect or bind privileged state incorrectly.",
    "upload_media_and_content_trust": "Upload harmless files/content on the researcher account and verify authorization, serving context, metadata handling, and object ownership.",
    "webview_native_bridge_boundaries": "On a researcher device/account, verify untrusted web content cannot invoke privileged native actions or expose sensitive app state.",
    "mobile_backend_authorization_parity": "Compare equivalent own-account web/mobile operations and confirm backend authorization does not depend on client type or hidden UI controls.",
    "asynchronous_jobs_and_stale_authorization": "Trigger one reversible own-account async action, change authorization/ownership state, and verify delayed processing rechecks current authority.",
    "cache_and_cdn_authorization_consistency": "Compare researcher-controlled authenticated/anonymous responses for cache-key and personalization isolation without probing other users.",
    "feature_flags_and_hidden_capabilities": "Treat UI-hidden capabilities as hypotheses only; if an observed backend action exists, verify authorization using the researcher account without endpoint enumeration.",
    "server_controlled_vs_client_controlled_fields": "For an observed own-account request, identify fields that should be server-derived and change only one benign value to verify enforcement.",
    "privacy_and_data_minimization_boundaries": "Inspect only researcher-owned records and responses for unnecessary sensitive fields or cross-context exposure; stop on any third-party data.",
    "abuse_resistance_for_high_impact_actions": "For a high-impact own-account action, test a single reversible replay/state transition only where the program permits and the proof cannot cause service harm.",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Minly adaptive audit hypothesis matrix")
    parser.add_argument("--profile", default="programs/minly-vdp/adaptive-audit-profile.yml")
    parser.add_argument("--output", default="artifacts/minly-adaptive")
    args = parser.parse_args()

    profile = yaml.safe_load(Path(args.profile).read_text(encoding="utf-8"))
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    hypotheses = []
    for index, lens in enumerate(profile.get("priority_lenses") or [], start=1):
        hypotheses.append(
            {
                "id": f"MINLY-HYP-{index:02d}",
                "lens": lens,
                "classification": "latent_vulnerability",
                "status": "hypothesis",
                "observed_evidence": [],
                "assumption_to_falsify": f"The current implementation consistently enforces the security invariant represented by {lens.replace('_', ' ')}.",
                "minimum_safe_validation": VALIDATION_MAP.get(
                    lens,
                    "Use the smallest reversible researcher-owned experiment that can falsify the assumption without enumeration or third-party data access.",
                ),
                "promotion_rule": "Promote to security_weakness only with concrete evidence; promote to confirmed_exploitable only after manual reproduction and demonstrated impact.",
                "reportable_now": False,
            }
        )

    (out / "hypothesis-matrix.json").write_text(json.dumps(hypotheses, indent=2), encoding="utf-8")

    lines = [
        "# Minly Adaptive Audit Hypothesis Matrix",
        "",
        "This file is a research queue, not a vulnerability report. Every item starts as an unconfirmed hypothesis.",
        "",
        "| ID | Lens | Status | Minimum safe validation |",
        "| --- | --- | --- | --- |",
    ]
    for item in hypotheses:
        lines.append(
            f"| {item['id']} | `{item['lens']}` | {item['status']} | {item['minimum_safe_validation'].replace('|', '/')} |"
        )
    lines.extend(
        [
            "",
            "## Promotion rules",
            "",
            "- **Observed**: direct evidence from an in-scope asset or researcher-owned account.",
            "- **Inferred**: conclusion supported by observed evidence but not yet directly tested.",
            "- **Hypothesis**: plausible security question requiring safe validation.",
            "- **Confirmed**: manually reproduced with demonstrated security impact.",
            "",
            "Only **Confirmed** items may become submissions, and they must still pass the program eligibility gate.",
        ]
    )
    (out / "hypothesis-matrix.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"generated {len(hypotheses)} Minly research hypotheses")


if __name__ == "__main__":
    main()
