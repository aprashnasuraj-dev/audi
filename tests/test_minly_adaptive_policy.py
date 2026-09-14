from __future__ import annotations

from pathlib import Path

import yaml

from scripts.minly_hypothesis_matrix import VALIDATION_MAP
from scripts.minly_public_mapper import normalize


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "programs" / "minly-vdp" / "adaptive-audit-profile.yml"


def load_profile():
    return yaml.safe_load(PROFILE.read_text(encoding="utf-8"))


def test_minly_adaptive_profile_is_exact_scope_and_low_volume():
    data = load_profile()
    scope = data["scope"]
    assert scope["exact_web_origins"] == ["https://minly.com/"]
    assert scope["wildcard_hosts_allowed"] is False
    assert scope["third_party_testing_allowed"] is False

    modes = {mode["name"]: mode for mode in data["research_modes"]}
    public = modes["public_surface"]
    assert public["allowed_methods"] == ["GET", "HEAD"]
    assert public["max_requests"] <= 24
    assert public["max_requests_per_second"] <= 0.4
    assert public["follow_cross_host_redirects"] is False
    assert public["mutate_state"] is False

    owned = modes["own_account_manual"]
    assert owned["max_requests"] <= 40
    assert owned["max_requests_per_second"] <= 0.5
    assert owned["automation"] == "browser_assisted_only"

    differential = modes["two_account_differential"]
    assert differential["object_enumeration"] is False
    assert differential["mutate_only_owned_objects"] is True


def test_nonconfirmed_risk_classes_are_never_directly_reportable():
    classes = load_profile()["risk_classes"]
    assert classes["confirmed_exploitable"]["reportable"] is True
    for name in (
        "security_weakness",
        "latent_vulnerability",
        "attack_path_precursor",
        "security_enhancement",
    ):
        assert classes[name]["reportable"] is False


def test_public_mapper_never_expands_cross_host_or_state_changing_paths():
    assert normalize("/about", "https://minly.com/") == "https://minly.com/about"
    assert normalize("https://example.com/path", "https://minly.com/") is None
    assert normalize("http://minly.com/about", "https://minly.com/") is None
    assert normalize("/logout", "https://minly.com/") is None
    assert normalize("/checkout", "https://minly.com/") is None
    assert normalize("/profile?user=123", "https://minly.com/") == "https://minly.com/profile"


def test_hypothesis_model_has_broad_manual_validation_coverage():
    lenses = load_profile()["priority_lenses"]
    assert len(lenses) >= 15
    assert set(lenses) <= set(VALIDATION_MAP)
    assert "object_ownership_and_authorization" in lenses
    assert "session_and_recovery_state_machine" in lenses
    assert "asynchronous_jobs_and_stale_authorization" in lenses
    assert "mobile_backend_authorization_parity" in lenses
