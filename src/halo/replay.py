from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

import httpx

from .live_safety import LiveSafetyController
from .models import Identity

SAFE_METHODS = frozenset({"GET", "HEAD"})
_VOLATILE_KEY = re.compile(r"(?:csrf|nonce|request[_-]?id|trace[_-]?id|timestamp|^time$|session[_-]?id)$", re.I)
_SENSITIVE_KEY = re.compile(r"(?:email|account|balance|secret|role|permission|owner|phone|address|user)", re.I)


@dataclass(frozen=True)
class CapturedRequest:
    method: str
    url: str
    headers: dict[str, str]


@dataclass(frozen=True)
class ResponseFingerprint:
    status_code: int
    body_sha256: str
    semantic_sha256: str
    body_length: int
    content_type: str
    json_shape: tuple[str, ...] | None
    sensitive_value_hashes: tuple[str, ...] = ()


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

    @property
    def material(self) -> bool:
        """Higher-signal differential after common volatile values are removed."""
        return any((
            self.a.status_code != self.b.status_code,
            self.a.content_type != self.b.content_type,
            self.a.json_shape != self.b.json_shape,
            self.a.semantic_sha256 != self.b.semantic_sha256,
            self.a.sensitive_value_hashes != self.b.sensitive_value_hashes,
        ))


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


def _normalize_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _normalize_json(item)
            for key, item in sorted(value.items(), key=lambda kv: str(kv[0]))
            if not _VOLATILE_KEY.search(str(key))
        }
    if isinstance(value, list):
        return [_normalize_json(item) for item in value]
    return value


def _sensitive_hashes(value: Any, prefix: str = "") -> list[str]:
    output: list[str] = []
    if isinstance(value, dict):
        for key, item in sorted(value.items(), key=lambda kv: str(kv[0])):
            path = f"{prefix}.{key}" if prefix else str(key)
            if _SENSITIVE_KEY.search(str(key)) and not isinstance(item, (dict, list)):
                digest = hashlib.sha256(repr(item).encode("utf-8")).hexdigest()
                output.append(f"{path}:{digest}")
            output.extend(_sensitive_hashes(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            output.extend(_sensitive_hashes(item, f"{prefix}[{index}]"))
    return output


def _fingerprint(response: httpx.Response) -> ResponseFingerprint:
    body = response.content
    semantic_body = body
    sensitive: tuple[str, ...] = ()
    try:
        payload = response.json()
    except Exception:
        pass
    else:
        normalized = _normalize_json(payload)
        semantic_body = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sensitive = tuple(sorted(_sensitive_hashes(payload)))
    return ResponseFingerprint(
        status_code=response.status_code,
        body_sha256=hashlib.sha256(body).hexdigest(),
        semantic_sha256=hashlib.sha256(semantic_body).hexdigest(),
        body_length=len(body),
        content_type=response.headers.get("content-type", "").split(";", 1)[0].strip().lower(),
        json_shape=_json_shape(response),
        sensitive_value_hashes=sensitive,
    )


class ReplayTransport:
    """Replay one captured safe request under two identities and diff responses."""

    def __init__(self, scope, *, timeout: float = 10.0, safety: LiveSafetyController | None = None):
        self.scope = scope
        self.timeout = timeout
        self.safety = safety

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
        if self.safety is not None:
            await self.safety.before_request(url)
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=self.timeout,
            cookies=identity.cookies,
        ) as client:
            response = await client.request(method, url, headers=headers)
        if self.safety is not None:
            self.safety.observe_response(url, response.status_code, response.headers)
        return _fingerprint(response)

    async def compare(self, request: CapturedRequest, identity_a: Identity, identity_b: Identity) -> ReplayDiff:
        a = await self._send(request, identity_a)
        b = await self._send(request, identity_b)
        return ReplayDiff(request=request, identity_a=identity_a.name, identity_b=identity_b.name, a=a, b=b)
