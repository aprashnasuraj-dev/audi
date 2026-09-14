from __future__ import annotations

import asyncio
import email.utils
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit


class LiveSafetyStop(RuntimeError):
    """Raised when a live target signals that automated traffic should stop."""


@dataclass
class LiveSafetyController:
    """Shared per-target pacing and fail-closed rate-limit handling.

    The controller is intentionally conservative: it serializes pacing decisions
    per target, enforces a maximum request rate per host, and treats HTTP 429 as
    a stop signal rather than automatically retrying through a live rate limit.
    """

    max_requests_per_second: float = 3.0
    max_retry_after_seconds: float = 30.0
    stop_on_429: bool = True
    _last_request_by_host: dict[str, float] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @classmethod
    def from_target(cls, target: dict[str, Any]) -> "LiveSafetyController":
        limits = dict(target.get("limits") or {})
        rate = float(limits.get("max_requests_per_second", 3.0))
        retry_cap = float(limits.get("max_retry_after_seconds", 30.0))
        if not 0.1 <= rate <= 20.0:
            raise ValueError("max_requests_per_second must be within 0.1..20")
        if not 0.0 <= retry_cap <= 120.0:
            raise ValueError("max_retry_after_seconds must be within 0..120")
        return cls(
            max_requests_per_second=rate,
            max_retry_after_seconds=retry_cap,
            stop_on_429=bool(limits.get("stop_on_429", True)),
        )

    async def before_request(self, url: str) -> None:
        host = (urlsplit(url).hostname or "").lower()
        if not host:
            raise ValueError("live-safety request URL has no host")
        interval = 1.0 / self.max_requests_per_second
        async with self._lock:
            now = time.monotonic()
            previous = self._last_request_by_host.get(host)
            if previous is not None:
                wait = interval - (now - previous)
                if wait > 0:
                    await asyncio.sleep(wait)
            self._last_request_by_host[host] = time.monotonic()

    def observe_response(self, url: str, status_code: int, headers: Mapping[str, str]) -> None:
        if int(status_code) != 429 or not self.stop_on_429:
            return
        retry_after = _retry_after_seconds(headers.get("retry-after"))
        if retry_after is not None:
            retry_after = min(retry_after, self.max_retry_after_seconds)
            detail = f"; Retry-After={retry_after:.1f}s"
        else:
            detail = ""
        host = urlsplit(url).hostname or "unknown-host"
        raise LiveSafetyStop(f"target {host} returned HTTP 429; automated traffic stopped{detail}")


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    stripped = value.strip()
    try:
        return max(0.0, float(stripped))
    except ValueError:
        pass
    try:
        parsed = email.utils.parsedate_to_datetime(stripped)
    except Exception:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0.0, (parsed - datetime.now(timezone.utc)).total_seconds())


def live_safety(context: dict[str, Any], target: dict[str, Any]) -> LiveSafetyController:
    controller = context.get("_live_safety_controller")
    if controller is None:
        controller = LiveSafetyController.from_target(target)
        context["_live_safety_controller"] = controller
    if not isinstance(controller, LiveSafetyController):
        raise TypeError("context contains invalid live-safety controller")
    return controller
