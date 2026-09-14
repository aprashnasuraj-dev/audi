from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import httpx

from .models import Identity
from .scope import ScopeGuard

SAFE_METHODS = frozenset({"GET", "HEAD"})


@dataclass(frozen=True)
class CapturedRequest:
    method: str
    url: str
    headers: dict[str, str]


@dataclass(frozen=True)
class ResponseFingerprint:
    status_code: int
    body_sha256: str
    body_length: int
    content_type: str
    json_shape: tuple[str, ...] | None


@dataclass(frozen=True)
class ReplayDiff:
    request: CapturedRequest
    identity_a: str
    identity_b: str
    a: ResponseFingerprint
    b: ResponseFingerprint

    @property
    def different(self) -> bool:
        return self.a != self.b


def _json_shape(response: httpx.Response) -> tuple[str, ...] | None:
    try:
        payload: Any = response.json()
    except Exception:
        return None
    if isinstance(payload, dict):
        return tuple(sorted(str(k) for k in payload.keys()))
    if isinstance(payload, list):
        return ("<list>",)
    return (type(payload).__name__,)


def _fingerprint(response: httpx.Response) -> ResponseFingerprint:
    body = response.content
    return ResponseFingerprint(
        status_code=response.status_code,
        body_sha256=hashlib.sha256(body).hexdigest(),
        body_length=len(body),
        content_type=response.headers.get("content-type", "").split(";", 1)[0].strip().lower(),
        json_shape=_json_shape(response),
    )


class ReplayTransport:
    """Replay one captured safe request under two identities and diff responses."""

    def __init__(self, scope: ScopeGuard, *, timeout: float = 10.0):
        self.scope = scope
        self.timeout = timeout

    async def _send(self, request: CapturedRequest, identity: Identity) -> ResponseFingerprint:
        method = request.method.upper()
        if method not in SAFE_METHODS:
            raise PermissionError(f"replay method {method} is outside safe boundary {sorted(SAFE_METHODS)}")
        url = self.scope.assert_url(request.url)
        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in {"authorization", "cookie", "host", "content-length"}
        }
        headers.update(identity.headers)
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=self.timeout,
            cookies=identity.cookies,
        ) as client:
            response = await client.request(method, url, headers=headers)
        return _fingerprint(response)

    async def compare(self, request: CapturedRequest, identity_a: Identity, identity_b: Identity) -> ReplayDiff:
        a = await self._send(request, identity_a)
        b = await self._send(request, identity_b)
        return ReplayDiff(request=request, identity_a=identity_a.name, identity_b=identity_b.name, a=a, b=b)
