from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from .live_safety import LiveSafetyController
from .scope import ScopePolicy, canonicalize_url


def load_targets(path: Path) -> dict[str, dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if raw.get("schema_version") != 1:
        raise ValueError("targets schema_version must be 1")
    output: dict[str, dict[str, Any]] = {}
    for item in raw.get("targets") or []:
        if not isinstance(item, dict):
            raise ValueError("each target must be a mapping")
        name = str(item.get("name", "")).strip()
        if not name or name in output:
            raise ValueError(f"target name missing or duplicate: {name!r}")
        url = canonicalize_url(str(item.get("url", "")))
        hosts = [str(x) for x in item.get("allow_hosts") or []]
        normalized = dict(item)
        normalized["url"] = url
        normalized["allow_hosts"] = hosts

        policy = ScopePolicy.from_target(normalized)
        if policy.state_for_host(urlsplit(url).hostname or "").value != "SEED_ALLOWED":
            raise PermissionError(f"seed URL for {name!r} is outside exact seed allow_hosts")

        limits = dict(item.get("limits") or {})
        max_pages = int(limits.get("max_pages", 25))
        request_budget = int(limits.get("request_budget", 250))
        timeout_seconds = float(limits.get("timeout_seconds", 10))
        if not 1 <= max_pages <= 200:
            raise ValueError(f"{name}: max_pages must be 1..200")
        if not 1 <= request_budget <= 5000:
            raise ValueError(f"{name}: request_budget must be 1..5000")
        if not 0.5 <= timeout_seconds <= 60:
            raise ValueError(f"{name}: timeout_seconds must be 0.5..60")
        normalized["limits"] = {
            **limits,
            "max_pages": max_pages,
            "request_budget": request_budget,
            "timeout_seconds": timeout_seconds,
        }
        LiveSafetyController.from_target(normalized)

        if normalized.get("live_target"):
            snapshot = normalized.get("scope_snapshot")
            if not snapshot:
                raise ValueError(f"{name}: live_target requires scope_snapshot")
            try:
                snapshot_date = date.fromisoformat(str(snapshot))
            except ValueError as exc:
                raise ValueError(f"{name}: scope_snapshot must be YYYY-MM-DD") from exc
            if snapshot_date > date.today():
                raise ValueError(f"{name}: scope_snapshot cannot be in the future")
            max_age = int(normalized.get("scope_max_age_days", 60))
            if not 1 <= max_age <= 365:
                raise ValueError(f"{name}: scope_max_age_days must be 1..365")
            normalized["scope_max_age_days"] = max_age

        identities = [str(value) for value in normalized.get("identities") or []]
        if normalized.get("require_authenticated_identity") and not identities:
            raise ValueError(f"{name}: authenticated audit requires explicit identities")

        output[name] = normalized
    if not output:
        raise ValueError("at least one target is required")
    return output
