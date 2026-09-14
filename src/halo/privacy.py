from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SENSITIVE_QUERY_KEYS = frozenset({
    "access_token",
    "auth",
    "authorization",
    "code",
    "credential",
    "id_token",
    "jwt",
    "key",
    "oauth_token",
    "password",
    "passwd",
    "refresh_token",
    "samlrequest",
    "samlresponse",
    "secret",
    "session",
    "sessionid",
    "sid",
    "sig",
    "signature",
    "state",
    "ticket",
    "token",
    "x-amz-credential",
    "x-amz-security-token",
    "x-amz-signature",
})
_SECRET_FIELD_KEYS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "access_token",
    "refresh_token",
    "id_token",
    "bearer_token",
    "client_secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "secret",
    "token",
})
_BEARER = re.compile(r"(?i)\bbearer\s+[^\s,;]+")


def _sensitive_query_key(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    if normalized in _SENSITIVE_QUERY_KEYS:
        return True
    return normalized.endswith(("_token", "_secret", "_password", "_signature"))


def redact_url_for_evidence(value: str) -> str:
    """Return a stable URL safe to persist in reports and provenance.

    Execution paths may need the original query string, so callers should use
    this only at evidence/report boundaries. Fragments and userinfo are removed;
    common OAuth/session/signature query values are replaced deterministically.
    """
    try:
        parts = urlsplit(value)
    except Exception:
        return value
    if parts.scheme.lower() not in {"http", "https", "ws", "wss"} or not parts.hostname:
        return _BEARER.sub("Bearer <redacted>", value)

    host = parts.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = host if port is None else f"{host}:{port}"

    pairs: list[tuple[str, str]] = []
    for key, item in parse_qsl(parts.query, keep_blank_values=True):
        pairs.append((key, "<redacted>" if _sensitive_query_key(key) else item))
    query = urlencode(pairs, doseq=True)
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", query, ""))


def sanitize_for_report(value: Any, *, key_hint: str | None = None) -> Any:
    """Recursively remove credentials and sensitive URL parameters from output."""
    if key_hint and key_hint.strip().lower() in _SECRET_FIELD_KEYS:
        return "<redacted>" if value not in (None, "") else value
    if isinstance(value, dict):
        return {
            str(key): sanitize_for_report(item, key_hint=str(key))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [sanitize_for_report(item) for item in value]
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.lower().startswith(("http://", "https://", "ws://", "wss://")):
            return redact_url_for_evidence(value)
        return _BEARER.sub("Bearer <redacted>", value)
    return value
