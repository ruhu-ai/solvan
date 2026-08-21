from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest

from solvan.application.production_graph_types import (
    GraphEdge,
    GraphNode,
    GraphSourcePlanEntry,
    GraphSourceResult,
)
from solvan.domain import Scope
from solvan.platform.production_graph_source_errors import GraphSourceUnavailable
from solvan.platform.production_graph_source_normalization import (
    attribute_type,
    dedupe_edges,
    dedupe_nodes,
    digest,
    exact_fields,
    location_from_name,
    owner,
    project_from_uri,
    required_text,
    resource_node_key,
    text_mapping,
    text_sequence,
)
from solvan.platform.production_graph_sources import (
    AppHubGraphSource,
    AssetRelationshipGraphSource,
    GraphSourceConfigurationError,
    GraphSourceDenied,
    GraphSourceNotEntitled,
    GraphSourceRegistry,
    IamPolicyGraphSource,
    configured_graph_sources,
)


def _node(*, key: str = "service:a", owner_team: str | None = None) -> GraphNode:
    return GraphNode(
        node_key=key,
        node_kind="SERVICE",
        resource_ref="//run.googleapis.com/projects/acme-prod/locations/europe-west1/services/a",
        external_project_id="acme-prod",
        owner_team=owner_team,
        declared_environment=None,
        business_criticality=None,
        data_classification=None,
        authorization_boundary=None,
        verification_profile=None,
        region="europe-west1",
        instrumentation_state="UNKNOWN",
        source_key="app_hub",
        source_revision=1,
    )


def _edge(*, key: str = "edge:a", target: str = "database:a") -> GraphEdge:
    return GraphEdge(key, "service:a", target, "DEPENDS_ON_DECLARED", "asset", 1)


def test_normalization_extracts_only_typed_safe_provider_fields() -> None:
    assert project_from_uri(None) is None
    assert project_from_uri("//run/projects/acme-prod/services/api") == "acme-prod"
    assert project_from_uri("projects/INVALID/services/api") is None
    assert location_from_name("projects/p/locations/europe-west1/applications/a") == "europe-west1"
    assert location_from_name("projects/p/applications/a") is None
    assert location_from_name("projects/p/locations/") is None
    assert attribute_type([], "environment") is None
    assert attribute_type({"environment": []}, "environment") is None
    assert attribute_type({"environment": {"type": "TYPE_UNSPECIFIED"}}, "environment") is None
    assert attribute_type({"environment": {"type": "PRODUCTION"}}, "environment") == "PRODUCTION"
    assert owner([]) is None
    assert owner({"operatorOwners": {}}) is None
    assert owner({"operatorOwners": ["bad", {"displayName": "unsafe\nowner"}]}) is None
    assert owner({"operatorOwners": [{"displayName": "Payments SRE"}]}) == "Payments SRE"


@pytest.mark.parametrize(
    ("resource", "expected"),
    [
        ("//run.googleapis.com/projects/p/locations/europe-west1/services/a", "service:"),
        ("//sqladmin.googleapis.com/projects/p/instances/a", "database:"),
        ("//pubsub.googleapis.com/projects/p/topics/a", "queue:"),
        ("//pubsub.googleapis.com/projects/p/subscriptions/a", "queue:"),
        ("//storage.googleapis.com/projects/p/buckets/a", None),
    ],
)
def test_resource_node_key_is_a_closed_resource_classification(
    resource: str, expected: str | None
) -> None:
    result = resource_node_key(resource)
    assert (None if result is None else result.split(resource, 1)[0]) == expected


def test_deduplication_accepts_identical_material_and_refuses_conflicts() -> None:
    node = _node()
    edge = _edge()
    assert dedupe_nodes((node, node)) == (node,)
    assert dedupe_edges((edge, edge)) == (edge,)
    with pytest.raises(GraphSourceUnavailable, match="conflicting node"):
        dedupe_nodes((node, _node(owner_team="other")))
    with pytest.raises(GraphSourceUnavailable, match="conflicting edge"):
        dedupe_edges((edge, _edge(target="database:other")))
    assert digest({"b": 2, "a": 1}) == digest({"a": 1, "b": 2})


def test_configuration_normalizers_are_exact_and_fail_closed() -> None:
    exact_fields({"kind": "IAM"}, {"kind"})
    with pytest.raises(ValueError, match="fields are not exact"):
        exact_fields({"kind": "IAM", "secret": "x"}, {"kind"})
    assert required_text({"field": " value "}, "field") == " value "
    with pytest.raises(ValueError, match="requires field"):
        required_text({"field": " "}, "field")
    assert text_sequence({"items": ["a", "b"]}, "items") == ("a", "b")
    invalid_sequences: tuple[object, ...] = (None, [], [""], [1])
    for invalid in invalid_sequences:
        with pytest.raises(ValueError, match="non-empty items"):
            text_sequence({"items": invalid}, "items")
    assert text_mapping({"items": {"a": "b"}}, "items") == {"a": "b"}
    invalid_mappings: tuple[object, ...] = (
        None,
        [],
        {"": "b"},
        {"a": ""},
        {1: "b"},
    )
    for invalid in invalid_mappings:
        with pytest.raises(ValueError, match="text map"):
            text_mapping({"items": invalid}, "items")


def test_source_contract_validation_rejects_impossible_results() -> None:
    digest_value = "sha256:" + "a" * 64
    for kwargs in (
        {"source_key": "", "source_revision": 1, "tier": 1, "policy_hash": digest_value},
        {"source_key": "app", "source_revision": 0, "tier": 1, "policy_hash": digest_value},
        {"source_key": "app", "source_revision": 1, "tier": 5, "policy_hash": digest_value},
        {"source_key": "app", "source_revision": 1, "tier": 1, "policy_hash": "bad"},
    ):
        with pytest.raises(ValueError):
            GraphSourcePlanEntry(required_for_complete=True, **kwargs)

    common = ("app", 1, 1, True)
    invalid = (
        (*common, "UNKNOWN", False, (), (), 1),
        (*common, "COMPLETE", False, (), (), 1),
        (*common, "PARTIAL", True, (), (), 1),
        (*common, "UNAVAILABLE", False, (_node(),), (), 1),
        (*common, "UNAVAILABLE", False, (), (), -1),
        (*common, "COMPLETE", True, (), (), 0),
    )
    for source_key, revision, tier, required, outcome, complete, nodes, edges, pages in invalid:
        with pytest.raises(ValueError):
            GraphSourceResult(
                source_key,
                revision,
                tier,
                required,
                outcome,
                complete,
                nodes=nodes,
                edges=edges,
                page_count=pages,
            )


def test_deployment_source_envelope_is_scope_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = Scope(
        "org_00000000000000000000000000",
        "prj_00000000000000000000000000",
        "env_00000000000000000000000000",
    )
    monkeypatch.delenv("SOLVAN_PRODUCTION_GRAPH_SOURCES_JSON", raising=False)
    assert configured_graph_sources(scope) is None

    invalid_values: tuple[str, ...] = (
        "not-json",
        "[]",
        json.dumps({"schema_version": 1, "scope": scope.canonical_dict()}),
        json.dumps({"schema_version": 2, "scope": scope.canonical_dict(), "sources": {"a": {}}}),
        json.dumps(
            {
                "schema_version": 1,
                "scope": Scope(
                    "org_00000000000000000000000001",
                    "prj_00000000000000000000000000",
                    "env_00000000000000000000000000",
                ).canonical_dict(),
                "sources": {"a": {}},
            }
        ),
        json.dumps({"schema_version": 1, "scope": scope.canonical_dict(), "sources": {}}),
    )
    for value in invalid_values:
        monkeypatch.setenv("SOLVAN_PRODUCTION_GRAPH_SOURCES_JSON", value)
        with pytest.raises(GraphSourceConfigurationError):
            configured_graph_sources(scope)

    sources = {"app": {"kind": "APP_HUB"}}
    monkeypatch.setenv(
        "SOLVAN_PRODUCTION_GRAPH_SOURCES_JSON",
        json.dumps({"schema_version": 1, "scope": scope.canonical_dict(), "sources": sources}),
    )
    assert configured_graph_sources(scope) == sources


@dataclass
class _ProviderResponse:
    status_code: int
    payload: Any

    def json(self) -> Any:
        return self.payload


class _ProviderTransport:
    def __init__(self, response: _ProviderResponse | Exception) -> None:
        self.response = response

    def get(self, *_args: Any, **_kwargs: Any) -> _ProviderResponse:
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


@pytest.mark.parametrize(
    ("response", "error"),
    [
        (_ProviderResponse(402, {}), GraphSourceNotEntitled),
        (_ProviderResponse(401, {}), GraphSourceDenied),
        (_ProviderResponse(404, {}), GraphSourceUnavailable),
        (_ProviderResponse(500, {}), GraphSourceUnavailable),
        (_ProviderResponse(200, []), GraphSourceUnavailable),
        (RuntimeError("network"), GraphSourceUnavailable),
    ],
)
def test_provider_transport_failures_remain_distinct(
    response: _ProviderResponse | Exception, error: type[Exception]
) -> None:
    source = AssetRelationshipGraphSource(
        _ProviderTransport(response),
        search_scope="projects/acme-prod",
        relationship_types=("RUN_SERVICE_TO_SQL_INSTANCE",),
    )
    with pytest.raises(error):
        source.fetch(source_key="relationships", source_revision=1)


def test_source_constructors_and_registry_refuse_unsafe_configuration() -> None:
    transport = _ProviderTransport(_ProviderResponse(200, {}))
    with pytest.raises(ValueError, match="named adapters"):
        GraphSourceRegistry({})
    with pytest.raises(ValueError, match="named adapters"):
        GraphSourceRegistry({" ": object()})
    with pytest.raises(ValueError, match="project id"):
        AppHubGraphSource(transport, host_project="INVALID", location="europe-west1")
    with pytest.raises(ValueError, match="location"):
        AppHubGraphSource(transport, host_project="acme-prod", location="regions/eu")
    with pytest.raises(ValueError, match="scope"):
        AssetRelationshipGraphSource(
            transport, search_scope="global", relationship_types=("RELATIONSHIP",)
        )
    with pytest.raises(ValueError, match="allowlist"):
        AssetRelationshipGraphSource(
            transport, search_scope="projects/acme-prod", relationship_types=("bad",)
        )
    with pytest.raises(ValueError, match="scope"):
        IamPolicyGraphSource(
            transport,
            search_scope="global",
            principal_nodes={},
            resource_nodes={},
        )
