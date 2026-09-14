from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


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
        candidate = _normalize_host(host)
        for pattern in self.allow_hosts:
            if pattern.startswith("*."):
                suffix = pattern[2:]
                if candidate.endswith("." + suffix) and candidate != suffix:
                    return True
            elif candidate == pattern:
                return True
        return False

    def assert_url(self, url: str) -> str:
        canonical = canonicalize_url(url)
        host = urlsplit(canonical).hostname or ""
        if not self.allows_host(host):
            raise PermissionError(f"out-of-scope host: {host}")
        return canonical
