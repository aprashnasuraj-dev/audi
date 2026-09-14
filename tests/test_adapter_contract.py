from __future__ import annotations

import inspect

from halo.adapters.base import VaultBoundAdapter
from halo.adapters.browser_discovery import BrowserDiscoveryAdapter
from halo.adapters.replay_runtime import ReplayRuntimeAdapter


def test_every_network_adapter_is_vault_bound():
    for cls in (BrowserDiscoveryAdapter, ReplayRuntimeAdapter):
        assert issubclass(cls, VaultBoundAdapter), cls.__name__
        signature = inspect.signature(cls.run_for_identities)
        assert "vault" in signature.parameters
        assert "identities" in signature.parameters
        assert "context" in signature.parameters


def test_adapter_names_are_unique():
    adapters = (BrowserDiscoveryAdapter, ReplayRuntimeAdapter)
    assert len({cls.name for cls in adapters}) == len(adapters)
