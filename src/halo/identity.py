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
    """Loads named identities and resolves secrets only when selected.

    Browser identities may use Playwright storage-state files in addition to
    headers/cookies. Authentication checks are carried with the identity so an
    authenticated run can prove that the session is actually logged in before
    navigation-derived scope can expand.
    """

    def __init__(
        self,
        identities: dict[str, Identity] | None = None,
        *,
        raw_configs: dict[str, dict[str, Any]] | None = None,
        base_dir: Path | None = None,
    ):
        self._identities = dict(identities or {})
        self._raw_configs = {str(k): dict(v or {}) for k, v in (raw_configs or {}).items()}
        self._base_dir = (base_dir or Path.cwd()).resolve()
        if "anonymous" not in self._identities and "anonymous" not in self._raw_configs:
            self._identities = {"anonymous": Identity("anonymous", role="anonymous"), **self._identities}

    @classmethod
    def from_file(cls, path: Path) -> "IdentityVault":
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if raw.get("schema_version") != 1:
            raise ValueError("identity vault schema_version must be 1")
        configs = raw.get("identities") or {}
        if not isinstance(configs, dict):
            raise ValueError("identity vault 'identities' must be a mapping")
        return cls(
            raw_configs={str(name): dict(cfg or {}) for name, cfg in configs.items()},
            base_dir=path.parent,
        )

    def names(self) -> list[str]:
        ordered = list(self._identities)
        ordered.extend(name for name in self._raw_configs if name not in self._identities)
        return ordered

    def get(self, name: str) -> Identity:
        if name in self._identities:
            return self._identities[name]
        if name not in self._raw_configs:
            raise KeyError(f"unknown identity {name!r}; available={self.names()}")

        resolved = _resolve(self._raw_configs[name])
        headers = {str(k): str(v) for k, v in (resolved.get("headers") or {}).items()}
        cookies = {str(k): str(v) for k, v in (resolved.get("cookies") or {}).items()}
        bearer = resolved.get("bearer_token")
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"

        storage_state = resolved.get("storage_state_path")
        storage_state_path: str | None = None
        if storage_state:
            candidate = Path(str(storage_state)).expanduser()
            if not candidate.is_absolute():
                candidate = self._base_dir / candidate
            candidate = candidate.resolve()
            if not candidate.is_file():
                raise RuntimeError(f"storage state for identity {name!r} does not exist: {candidate}")
            storage_state_path = str(candidate)

        identity = Identity(
            name,
            role=str(resolved.get("role") or ""),
            headers=headers,
            cookies=cookies,
            storage_state_path=storage_state_path,
            auth_check_url=(str(resolved["auth_check_url"]) if resolved.get("auth_check_url") else None),
            auth_check_contains=(
                str(resolved["auth_check_contains"]) if resolved.get("auth_check_contains") else None
            ),
            auth_check_selector=(
                str(resolved["auth_check_selector"]) if resolved.get("auth_check_selector") else None
            ),
        )
        self._identities[name] = identity
        return identity

    def selected(self, names: list[str] | None = None) -> list[Identity]:
        return [self.get(name) for name in (names or self.names())]
