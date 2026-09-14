from __future__ import annotations

import inspect

from halo.adapters.base import VaultBoundAdapter
from halo.adapters.browser_discovery import BrowserDiscoveryAdapter
from halo.adapters.graphql_schema import GraphQLSchemaAdapter
from halo.adapters.openapi_contract import OpenAPIContractAdapter
from halo.adapters.replay_runtime import ReplayRuntimeAdapter


NETWORK_ADAPTERS = (
    BrowserDiscoveryAdapter,
    ReplayRuntimeAdapter,
    OpenAPIContractAdapter,
    GraphQLSchemaAdapter,
)


def test_every_network_adapter_is_vault_bound():
    for cls in NETWORK_ADAPTERS:
        assert issubclass(cls, VaultBoundAdapter), cls.__name__
        signature = inspect.signature(cls.run_for_identities)
        assert "vault" in signature.parameters
        assert "identities" in signature.parameters
        assert "context" in signature.parameters


def test_adapter_names_are_unique():
    assert len({cls.name for cls in NETWORK_ADAPTERS}) == len(NETWORK_ADAPTERS)
