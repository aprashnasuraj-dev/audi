from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from .models import Identity

_ENV = re.compile(r"^\$\{([A-Z0-9_]+)\}$")


def _resolve(value: Any) -> Any:
    if isinstance(value, str):
        match = _ENV.match(value)
        if match:
            name = match.group(1)
            if name not in os.environ:
                raise RuntimeError(f"required identity secret environment variable {name} is unset")
            return os.environ[name]
    if isinstance(value, dict):
        return {str(k): _resolve(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve(v) for v in value]
    return value


class IdentityVault:
    """Loads named identities without persisting resolved secrets back to disk."""

    def __init__(self, identities: dict[str, Identity]):
        if "anonymous" not in identities:
            identities = {"anonymous": Identity("anonymous"), **identities}
        self._identities = dict(identities)

    @classmethod
    def from_file(cls, path: Path) -> "IdentityVault":
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if raw.get("schema_version") != 1:
            raise ValueError("identity vault schema_version must be 1")
        identities: dict[str, Identity] = {}
        for name, cfg in (raw.get("identities") or {}).items():
            resolved = _resolve(cfg or {})
            headers = {str(k): str(v) for k, v in (resolved.get("headers") or {}).items()}
            cookies = {str(k): str(v) for k, v in (resolved.get("cookies") or {}).items()}
            bearer = resolved.get("bearer_token")
            if bearer:
                headers["Authorization"] = f"Bearer {bearer}"
            identities[str(name)] = Identity(str(name), headers=headers, cookies=cookies)
        return cls(identities)

    def names(self) -> list[str]:
        return list(self._identities)

    def get(self, name: str) -> Identity:
        try:
            return self._identities[name]
        except KeyError as exc:
            raise KeyError(f"unknown identity {name!r}; available={self.names()}") from exc

    def selected(self, names: list[str] | None = None) -> list[Identity]:
        return [self.get(name) for name in (names or self.names())]
