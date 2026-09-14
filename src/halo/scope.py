from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from enum import StrEnum
from urllib.parse import urlsplit, urlunsplit

from .models import Identity


def _normalize_host(host: str) -> str:
    value = host.strip().rstrip(".").lower()
    if not value:
        raise ValueError("host is required")
    if "*" in value and not value.startswith("*."):
        raise ValueError("wildcard is permitted only as a single leading '*.'")
    if value.count("*") > 1:
        raise ValueError("multiple wildcards are not permitted")
    suffix = value[2:] if value.startswith("*.") else value
    try:
        ipaddress.ip_address(suffix)
    except ValueError:
        suffix = suffix.encode("idna").decode("ascii")
    else:
        if value.startswith("*."):
            raise ValueError("wildcard IP literals are not permitted")
    return f"*.{suffix}" if value.startswith("*.") else suffix


def _matches(pattern: str, host: str) -> bool:
    pattern = _normalize_host(pattern)
    candidate = _normalize_host(host)
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return candidate.endswith("." + suffix) and candidate != suffix
    return candidate == pattern


def canonicalize_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise ValueError("only http/https URLs are permitted")
    if parts.username or parts.password:
        raise ValueError("URL userinfo is not permitted")
    if not parts.hostname:
        raise ValueError("URL hostname is required")
    host = _normalize_host(parts.hostname)
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("malformed port") from exc
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


@dataclass(frozen=True)
class ScopeGuard:
    allow_hosts: tuple[str, ...]

    def __init__(self, allow_hosts: list[str] | tuple[str, ...]):
        normalized = tuple(_normalize_host(host) for host in allow_hosts)
        if not normalized:
            raise ValueError("scope allowlist cannot be empty")
        if "*" in normalized:
            raise ValueError("global wildcard is forbidden")
        object.__setattr__(self, "allow_hosts", normalized)

    def allows_host(self, host: str) -> bool:
        return any(_matches(pattern, host) for pattern in self.allow_hosts)

    def assert_url(self, url: str) -> str:
        canonical = canonicalize_url(url)
        host = urlsplit(canonical).hostname or ""
        if not self.allows_host(host):
            raise PermissionError(f"out-of-scope host: {host}")
        return canonical


class ScopeState(StrEnum):
    SEED_ALLOWED = "SEED_ALLOWED"
    FLOW_ALLOWED = "FLOW_ALLOWED"
    DENIED = "DENIED"
    THIRD_PARTY = "THIRD_PARTY"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class ScopeGrant:
    host: str
    source_url: str
    destination_url: str
    identity: str
    identity_role: str
    event: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class ScopePolicy:
    """Exact seed scope plus authenticated, provenance-carrying flow grants.

    Static wildcard authorization is deliberately not inferred from an
    authenticated-flow suffix. A new host is granted only after a top-level
    navigation from an already-authorized page under a non-anonymous identity.
    Explicit deny rules always win.
    """

    def __init__(
        self,
        allow_hosts: list[str] | tuple[str, ...],
        *,
        deny_hosts: list[str] | tuple[str, ...] = (),
        authenticated_flow_suffixes: list[str] | tuple[str, ...] = (),
        authenticated_flow_hosts: list[str] | tuple[str, ...] = (),
    ):
        self.seed_guard = ScopeGuard(allow_hosts)
        self.deny_hosts = tuple(_normalize_host(value) for value in deny_hosts)
        self.flow_suffixes = tuple(_normalize_host(value) for value in authenticated_flow_suffixes)
        self.flow_hosts = tuple(_normalize_host(value) for value in authenticated_flow_hosts)
        self._grants: dict[str, ScopeGrant] = {}

    @classmethod
    def from_target(cls, target: dict) -> "ScopePolicy":
        return cls(
            tuple(str(value) for value in target.get("allow_hosts") or ()),
            deny_hosts=tuple(str(value) for value in target.get("deny_hosts") or ()),
            authenticated_flow_suffixes=tuple(
                str(value) for value in target.get("authenticated_flow_suffixes") or ()
            ),
            authenticated_flow_hosts=tuple(
                str(value) for value in target.get("authenticated_flow_hosts") or ()
            ),
        )

    @property
    def grants(self) -> list[ScopeGrant]:
        return [self._grants[key] for key in sorted(self._grants)]

    def is_denied_host(self, host: str) -> bool:
        return any(_matches(pattern, host) for pattern in self.deny_hosts)

    def is_flow_candidate(self, host: str) -> bool:
        candidate = _normalize_host(host)
        if any(candidate == item for item in self.flow_hosts):
            return True
        return any(candidate == suffix or candidate.endswith("." + suffix) for suffix in self.flow_suffixes)

    def state_for_host(self, host: str) -> ScopeState:
        candidate = _normalize_host(host)
        if self.is_denied_host(candidate):
            return ScopeState.DENIED
        if self.seed_guard.allows_host(candidate):
            return ScopeState.SEED_ALLOWED
        if candidate in self._grants:
            return ScopeState.FLOW_ALLOWED
        if self.is_flow_candidate(candidate):
            return ScopeState.UNRESOLVED
        return ScopeState.THIRD_PARTY

    def allows_host(self, host: str) -> bool:
        return self.state_for_host(host) in {ScopeState.SEED_ALLOWED, ScopeState.FLOW_ALLOWED}

    def assert_url(self, url: str) -> str:
        canonical = canonicalize_url(url)
        host = urlsplit(canonical).hostname or ""
        state = self.state_for_host(host)
        if state not in {ScopeState.SEED_ALLOWED, ScopeState.FLOW_ALLOWED}:
            raise PermissionError(f"scope state {state.value} for host: {host}")
        return canonical

    def try_navigation_transition(
        self,
        destination_url: str,
        *,
        source_url: str,
        identity: Identity,
        top_level_navigation: bool,
        authentication_verified: bool,
        event: str = "browser-navigation",
    ) -> tuple[str, ScopeState]:
        destination = canonicalize_url(destination_url)
        host = urlsplit(destination).hostname or ""
        current = self.state_for_host(host)
        if current in {ScopeState.SEED_ALLOWED, ScopeState.FLOW_ALLOWED}:
            return destination, current
        if current is ScopeState.DENIED:
            raise PermissionError(f"explicitly denied host: {host}")
        if not top_level_navigation:
            raise PermissionError(f"non-navigation request cannot extend scope to {host}")
        if identity.role == "anonymous" or not authentication_verified:
            raise PermissionError(f"authenticated navigation proof required before extending scope to {host}")
        if not self.is_flow_candidate(host):
            raise PermissionError(f"destination host is not an eligible authenticated-flow host: {host}")

        source = canonicalize_url(source_url)
        source_host = urlsplit(source).hostname or ""
        if not self.allows_host(source_host):
            raise PermissionError(f"navigation source is not already authorized: {source_host}")

        grant = ScopeGrant(
            host=_normalize_host(host),
            source_url=source,
            destination_url=destination,
            identity=identity.name,
            identity_role=identity.role,
            event=event,
        )
        self._grants[grant.host] = grant
        return destination, ScopeState.FLOW_ALLOWED

    def provenance(self) -> list[dict[str, str]]:
        return [grant.to_dict() for grant in self.grants]
