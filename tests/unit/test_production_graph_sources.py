from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from solvan.application.production_graph_types import GraphSourceResult
from solvan.platform.production_graph_sources import (
    AppHubGraphSource,
    AssetRelationshipGraphSource,
    GraphSourceDenied,
    GraphSourceRegistry,
    GraphSourceUnavailable,
    IamPolicyGraphSource,
    graph_source_registry_from_config,
)


@dataclass
class _Response:
    payload: dict[str, Any]
    status_code: int = 200

    def json(self) -> dict[str, Any]:
        return self.payload


class _Transport:
    def __init__(self, responses: list[_Response]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: Any) -> _Response:
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


def test_app_hub_projects_only_safe_governed_attributes() -> None:
    transport = _Transport(
        [
            _Response(
                {
                    "applications": [
                        {"name": "projects/host-proj/locations/europe-west1/applications/payments"}
                    ]
                }
            ),
            _Response(
                {
                    "services": [
                        {
                            "state": "ACTIVE",
                            "serviceReference": {
                                "uri": "//run.googleapis.com/projects/customer-prod/"
                                "locations/europe-west1/services/payments"
                            },
                            "attributes": {
                                "criticality": {"type": "MISSION_CRITICAL"},
                                "environment": {"type": "PRODUCTION"},
                                "operatorOwners": [
                                    {"displayName": "Payments SRE", "email": "private@example.com"}
                                ],
                            },
                            "description": "untrusted instructions",
                        }
                    ]
                }
            ),
            _Response({"workloads": []}),
        ]
    )

    result = AppHubGraphSource(transport, host_project="host-proj", location="europe-west1").fetch(
        source_key="app_hub", source_revision=1
    )

    assert result.outcome == "COMPLETE"
    assert result.page_count == 3
    assert len(result.nodes) == 1
    node = result.nodes[0]
    assert node.external_project_id == "customer-prod"
    assert node.owner_team == "Payments SRE"
    assert node.business_criticality == "MISSION_CRITICAL"
    assert node.declared_environment == "PRODUCTION"
    assert "private@example.com" not in repr(node)
    assert "untrusted instructions" not in repr(node)


def test_app_hub_unreachable_child_page_makes_result_partial() -> None:
    transport = _Transport(
        [
            _Response(
                {
                    "applications": [
                        {"name": "projects/host-proj/locations/europe-west1/applications/payments"}
                    ]
                }
            ),
            _Response({"services": [], "unreachable": ["europe-west2"]}),
            _Response({"workloads": []}),
        ]
    )

    result = AppHubGraphSource(transport, host_project="host-proj", location="europe-west1").fetch(
        source_key="app_hub", source_revision=1
    )

    assert result.outcome == "PARTIAL"
    assert not result.pagination_complete


def test_asset_relationship_source_emits_declared_edges_only() -> None:
    source = "//run.googleapis.com/projects/customer-prod/locations/europe-west1/services/payments"
    target = "//sqladmin.googleapis.com/projects/customer-data/instances/payments"
    transport = _Transport(
        [
            _Response(
                {
                    "results": [
                        {
                            "name": source,
                            "relationships": {
                                "RUN_SERVICE_TO_SQL_INSTANCE": {
                                    "relatedResources": [
                                        {
                                            "assetType": "sqladmin.googleapis.com/Instance",
                                            "fullResourceName": target,
                                        }
                                    ]
                                }
                            },
                        }
                    ]
                }
            )
        ]
    )

    result = AssetRelationshipGraphSource(
        transport,
        search_scope="projects/customer-prod",
        relationship_types=("RUN_SERVICE_TO_SQL_INSTANCE",),
    ).fetch(source_key="asset_relationships", source_revision=3)

    assert result.outcome == "COMPLETE"
    assert len(result.edges) == 1
    assert result.edges[0].edge_kind == "DEPENDS_ON_DECLARED"
    assert result.edges[0].from_node_key == f"service:{source}"
    assert result.edges[0].to_node_key == f"database:{target}"


def test_iam_source_never_invents_principal_or_resource_resolution() -> None:
    transport = _Transport(
        [
            _Response(
                {
                    "results": [
                        {
                            "resource": "//sqladmin.googleapis.com/projects/customer-data/"
                            "instances/payments",
                            "policy": {
                                "bindings": [
                                    {
                                        "role": "roles/cloudsql.client",
                                        "members": [
                                            "serviceAccount:payments@customer-prod.iam.gserviceaccount.com",
                                            "serviceAccount:unknown@customer-prod.iam.gserviceaccount.com",
                                        ],
                                    }
                                ]
                            },
                        }
                    ]
                }
            )
        ]
    )
    service = "service://payments"
    database = "database://payments"

    result = IamPolicyGraphSource(
        transport,
        search_scope="projects/customer-prod",
        principal_nodes={"serviceAccount:payments@customer-prod.iam.gserviceaccount.com": service},
        resource_nodes={
            "//sqladmin.googleapis.com/projects/customer-data/instances/payments": database
        },
    ).fetch(source_key="cloud_iam", source_revision=2)

    assert len(result.edges) == 1
    assert result.edges[0].from_node_key == service
    assert result.edges[0].to_node_key == database
    assert result.edges[0].edge_kind == "ALLOWED_TO_CALL"


def test_registry_refuses_unregistered_or_substituted_sources() -> None:
    class Adapter:
        def fetch(self, *, source_key: str, source_revision: int) -> GraphSourceResult:
            return GraphSourceResult(
                "substituted",
                source_revision,
                1,
                True,
                "COMPLETE",
                True,
                response_digest="sha256:" + "a" * 64,
            )

    registry = GraphSourceRegistry({"app_hub": Adapter()})
    with pytest.raises(GraphSourceUnavailable, match="not registered"):
        registry.fetch(source_key="from-model", source_revision=1)
    with pytest.raises(GraphSourceUnavailable, match="substituted"):
        registry.fetch(source_key="app_hub", source_revision=1)


def test_provider_denial_is_distinct_from_empty_source() -> None:
    transport = _Transport([_Response({}, status_code=403)])
    source = AssetRelationshipGraphSource(
        transport,
        search_scope="projects/customer-prod",
        relationship_types=("RUN_SERVICE_TO_SQL_INSTANCE",),
    )
    with pytest.raises(GraphSourceDenied):
        source.fetch(source_key="asset_relationships", source_revision=1)


def test_deployment_registry_is_closed_and_rejects_extra_or_unknown_configuration() -> None:
    registry = graph_source_registry_from_config(
        _Transport([]),
        config={
            "app_hub": {
                "kind": "APP_HUB",
                "host_project": "host-proj",
                "location": "europe-west1",
            },
            "asset_inventory": {
                "kind": "ASSET_INVENTORY",
                "search_scope": "folders/123456",
            },
            "asset_relationships": {
                "kind": "ASSET_RELATIONSHIPS",
                "search_scope": "folders/123456",
                "relationship_types": ["RUN_SERVICE_TO_SQL_INSTANCE"],
            },
            "cloud_iam": {
                "kind": "IAM",
                "search_scope": "folders/123456",
                "principal_nodes": {},
                "resource_nodes": {},
            },
        },
    )
    assert registry.source_keys == (
        "app_hub",
        "asset_inventory",
        "asset_relationships",
        "cloud_iam",
    )

    with pytest.raises(ValueError, match="fields are not exact"):
        graph_source_registry_from_config(
            _Transport([]),
            config={
                "app_hub": {
                    "kind": "APP_HUB",
                    "host_project": "host-proj",
                    "location": "europe-west1",
                    "credential": "must-never-be-accepted",
                }
            },
        )
    with pytest.raises(ValueError, match="unsupported kind"):
        graph_source_registry_from_config(
            _Transport([]), config={"arbitrary": {"kind": "FROM_MODEL"}}
        )
