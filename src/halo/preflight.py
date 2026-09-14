from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .identity import IdentityVault, authentication_mode
from .input_gate import evaluate_family_input
from .models import FamilyStatus
from .scope import ScopePolicy, ScopeState

_BASE_REQUIRED_WEB_FAMILIES = frozenset({"browser-discovery", "web-hardening"})
_OPTIONAL_INPUT_FAMILIES = frozenset({"api-contract", "graphql-schema", "container", "iac"})


@dataclass
class PreflightResult:
    target: str
    ready: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    identities: list[str] = field(default_factory=list)
    authenticated_identities: list[str] = field(default_factory=list)
    operational_identities: list[str] = field(default_factory=list)
    unavailable_identities: dict[str, str] = field(default_factory=dict)
    authentication_mode: str = "optional"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def preflight_target(
    target_name: str,
    target: dict[str, Any],
    vault: IdentityVault,
    *,
    repo_root: Path,
) -> PreflightResult:
    """Validate a target without contacting it.

    Live scope, pacing and publication prerequisites remain fail-closed. Authentication
    can be configured as optional: if a session is unavailable, the target may run its
    public surface with anonymous identity only, while authenticated-only capabilities
    remain dormant and are reported as unavailable rather than silently simulated.
    """
    errors: list[str] = []
    warnings: list[str] = []

    try:
        mode = authentication_mode(target)
        resolution = vault.resolve_for_target(target)
    except Exception as exc:
        return PreflightResult(
            target_name,
            False,
            [f"invalid identity/authentication configuration: {exc}"],
        )

    selected = list(resolution.requested)
    operational = resolution.operational_names
    authenticated = resolution.authenticated_names
    live = bool(target.get("live_target"))

    for identity_name, reason in resolution.unavailable.items():
        if identity_name == "anonymous" or mode == "required":
            errors.append(f"identity {identity_name!r} is not operational: {reason}")
        else:
            warnings.append(
                f"identity {identity_name!r} unavailable; continuing with public-surface capability only: {reason}"
            )

    if not operational:
        errors.append("no operational identity is available")
    if mode in {"optional", "anonymous-only"} and "anonymous" not in operational:
        errors.append("public-surface mode requires an operational anonymous identity")

    try:
        policy = ScopePolicy.from_target(target)
    except Exception as exc:
        return PreflightResult(
            target_name,
            False,
            errors + [f"invalid scope policy: {exc}"],
            warnings=warnings,
            identities=selected,
            authenticated_identities=authenticated,
            operational_identities=operational,
            unavailable_identities=dict(resolution.unavailable),
            authentication_mode=mode,
        )

    seed_host = urlsplit(str(target.get("url") or "")).hostname or ""
    if policy.state_for_host(seed_host) is not ScopeState.SEED_ALLOWED:
        errors.append("seed URL is not explicitly SEED_ALLOWED")

    if live:
        for host in target.get("allow_hosts") or []:
            if "*" in str(host):
                errors.append(f"live seed allow_hosts must be exact, not wildcard: {host}")
        for suffix in target.get("authenticated_flow_suffixes") or []:
            if "*" in str(suffix):
                errors.append(f"authenticated_flow_suffixes must use a bare suffix, not wildcard syntax: {suffix}")

        snapshot = target.get("scope_snapshot")
        if not snapshot:
            errors.append("live target requires scope_snapshot")
        else:
            try:
                snapshot_date = date.fromisoformat(str(snapshot))
            except ValueError:
                errors.append("scope_snapshot must be YYYY-MM-DD")
            else:
                age = (date.today() - snapshot_date).days
                maximum = int(target.get("scope_max_age_days", 60))
                if age < 0:
                    errors.append("scope_snapshot is in the future")
                elif age > maximum:
                    errors.append(f"scope snapshot is stale: age={age}d exceeds {maximum}d")

        limits = dict(target.get("limits") or {})
        rate = float(limits.get("max_requests_per_second", 3.0))
        budget = int(limits.get("request_budget", 250))
        if rate > 5.0:
            errors.append(f"live max_requests_per_second={rate:g} exceeds conservative ceiling 5")
        if budget > 1000:
            errors.append(f"live request_budget={budget} exceeds conservative ceiling 1000")
        if not bool(limits.get("stop_on_429", True)):
            errors.append("live target must stop on HTTP 429")
        if float(target.get("minimum_coverage_ratio", 1.0)) < 1.0:
            errors.append("live target minimum_coverage_ratio must be 1.0")

        required = {str(value) for value in target.get("required_families") or []}
        expected_core = set(_BASE_REQUIRED_WEB_FAMILIES)
        if mode == "required":
            expected_core.add("runtime-verification")
        missing_core = sorted(expected_core - required)
        if missing_core:
            errors.append(f"live target is missing required web families: {missing_core}")
        if target.get("browser", {}).get("allow_third_party_resources"):
            warnings.append("third-party static resources may load passively with auth headers stripped")

    for identity in resolution.operational:
        if identity.role == "anonymous":
            continue
        if not identity.auth_check_url:
            message = f"identity {identity.name!r} has no auth_check_url"
            (errors if mode == "required" else warnings).append(message)
        else:
            try:
                auth_host = urlsplit(identity.auth_check_url).hostname or ""
                if policy.state_for_host(auth_host) is not ScopeState.SEED_ALLOWED:
                    errors.append(
                        f"identity {identity.name!r} auth_check_url must stay on an exact seed host before flow scope is granted"
                    )
            except Exception as exc:
                errors.append(f"identity {identity.name!r} has invalid auth_check_url: {exc}")
        if not identity.auth_check_selector and not identity.auth_check_contains:
            message = f"identity {identity.name!r} needs auth_check_selector or auth_check_contains"
            (errors if mode == "required" else warnings).append(message)

    if mode == "required" and not authenticated:
        errors.append("target requires at least one operational non-anonymous identity")

    required_families = {str(value) for value in target.get("required_families") or []}
    for family in sorted(required_families & _OPTIONAL_INPUT_FAMILIES):
        gate = evaluate_family_input(family, target, repo_root)
        if gate.status is FamilyStatus.SKIPPED:
            errors.append(f"required family {family} has no usable input: {gate.reason}")

    flow_candidates = list(target.get("authenticated_flow_suffixes") or []) + list(
        target.get("authenticated_flow_hosts") or []
    )
    if flow_candidates and live and mode != "required" and not authenticated:
        warnings.append(
            "authenticated flow expansion is configured but dormant because no operational authenticated identity is available"
        )

    if live and mode == "optional" and not authenticated:
        warnings.append(
            "authenticated session material is unavailable; this run is limited to the public/anonymous surface"
        )
    if live and mode == "anonymous-only":
        warnings.append("authentication_mode=anonymous-only; authenticated coverage is intentionally disabled")

    return PreflightResult(
        target=target_name,
        ready=not errors,
        errors=errors,
        warnings=warnings,
        identities=selected,
        authenticated_identities=sorted(authenticated),
        operational_identities=operational,
        unavailable_identities=dict(resolution.unavailable),
        authentication_mode=mode,
    )
