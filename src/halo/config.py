from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from .scope import ScopeGuard, canonicalize_url


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
        guard = ScopeGuard(hosts)
        if not guard.allows_host(urlsplit(url).hostname or ""):
            raise PermissionError(f"seed URL for {name!r} is outside allow_hosts")
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
        normalized = dict(item)
        normalized["url"] = url
        normalized["allow_hosts"] = hosts
        normalized["limits"] = {
            **limits,
            "max_pages": max_pages,
            "request_budget": request_budget,
            "timeout_seconds": timeout_seconds,
        }
        output[name] = normalized
    if not output:
        raise ValueError("at least one target is required")
    return output
