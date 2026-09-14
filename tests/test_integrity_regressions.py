from __future__ import annotations

from pathlib import Path

import yaml

from halo.applicability import TechnologyProfile
from halo.canonical import canonicalize_findings
from halo.contextual_triage import TriageDisposition, evaluate_contextual_signal
from halo.integrity import scanner_exit_completed
from halo.models import Finding, ResultAccounting


FIXTURES = Path(__file__).parent / "fixtures"


def test_previous_human_review_false_positives_remain_excluded_or_informational():
    data = yaml.safe_load((FIXTURES / "previous_run_false_positives.yml").read_text(encoding="utf-8"))
    for case in data["cases"]:
        profile = TechnologyProfile(set(case.get("technologies") or []), {})
        decision = evaluate_contextual_signal(case["signal"], profile)
        assert decision.disposition is TriageDisposition(case["expected"]), case["name"]


def test_previous_integrity_failures_are_machine_detectable():
    data = yaml.safe_load((FIXTURES / "previous_run_integrity.yml").read_text(encoding="utf-8"))
    for case in data["cases"]:
        if "accounting" in case:
            accounting = ResultAccounting(**case["accounting"])
            assert accounting.parity_ok is bool(case["parity_ok"]), case["name"]
        if "exit_code" in case:
            assert scanner_exit_completed(case["tool"], int(case["exit_code"]), mode=case["mode"]) is bool(case["completed"])


def test_semantic_dedup_merges_corroboration_without_losing_sources():
    findings = [
        Finding(
            tool="scanner-a",
            family="web-hardening",
            rule_id="halo.missing-hsts",
            title="Strict-Transport-Security was not observed",
            severity="low",
            url="https://example.test/account",
            identity="anonymous",
            evidence={"header": "Strict-Transport-Security"},
        ),
        Finding(
            tool="scanner-b",
            family="web-hardening",
            rule_id="strict-transport-security-missing",
            title="HSTS header missing",
            severity="medium",
            url="https://example.test/login",
            identity="user",
            evidence={"header": "Strict-Transport-Security"},
        ),
    ]
    issues = canonicalize_findings(findings, "fixture")
    assert len(issues) == 1
    issue = issues[0]
    assert issue.weakness == "web.missing-hsts"
    assert issue.severity == "medium"
    assert set(issue.tools) == {"scanner-a", "scanner-b"}
    assert len(issue.evidence_sources) == 2
