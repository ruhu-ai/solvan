"""Governed Google Cloud sources for Production Graph reconciliation.

Provider payloads are projected immediately into typed graph facts.  Raw
responses, IAM conditions, contact email addresses, descriptions, and labels
never leave this boundary.  A registry dispatches only exact, pre-registered
source keys; source names returned by a model or request cannot select an
arbitrary connector.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from typing import Any

from solvan.application.production_graph_types import (
    GraphEdge,
    GraphNode,
    GraphSourceAdapter,
    GraphSourceResult,
)
from solvan.domain import Scope
from solvan.platform.asset_inventory_source import (
    AssetInventoryDenied,
    AssetInventoryGraphSource,
    AssetInventoryUnavailable,
)
from solvan.platform.production_graph_source_errors import (
    GraphSourceDenied,
    GraphSourceNotEntitled,
    GraphSourceUnavailable,
)
from solvan.platform.production_graph_source_normalization import (
    attribute_type as _attribute_type,
)
from solvan.platform.production_graph_source_normalization import (
    dedupe_edges as _dedupe_edges,
)
from solvan.platform.production_graph_source_normalization import (
    dedupe_nodes as _dedupe_nodes,
)
from solvan.platform.production_graph_source_normalization import (
    digest as _digest,
)
from solvan.platform.production_graph_source_normalization import (
    exact_fields as _exact_fields,
)
from solvan.platform.production_graph_source_normalization import (
    location_from_name as _location_from_name,
)
from solvan.platform.production_graph_source_normalization import (
    owner as _owner,
)
from solvan.platform.production_graph_source_normalization import (
    project_from_uri as _project_from_uri,
)
from solvan.platform.production_graph_source_normalization import (
    required_text as _required_text,
)
from solvan.platform.production_graph_source_normalization import (
    resource_node_key as _resource_node_key,
)
from solvan.platform.production_graph_source_normalization import (
    text_mapping as _text_mapping,
)
from solvan.platform.production_graph_source_normalization import (
    text_sequence as _text_sequence,
)

_PAGE_SIZE = 500
_MAX_PAGES = 20


class GraphSourceConfigurationError(RuntimeError):
    """Deployment-owned graph source configuration is absent or unsafe."""


class GraphSourceRegistry(GraphSourceAdapter):
    """Exact source-key registry used by the coordinator-owned graph worker."""

    def __init__(self, adapters: Mapping[str, GraphSourceAdapter]) -> None:
        if not adapters or any(not key.strip() for key in adapters):
            raise ValueError("graph source registry requires named adapters")
        self._adapters = dict(adapters)

    @property
    def source_keys(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters))

    def fetch(self, *, source_key: str, source_revision: int) -> GraphSourceResult:
        adapter = self._adapters.get(source_key)
        if adapter is None:
            raise GraphSourceUnavailable(f"graph source {source_key} is not registered")
        result = adapter.fetch(source_key=source_key, source_revision=source_revision)
        if (result.source_key, result.source_revision) != (source_key, source_revision):
            raise GraphSourceUnavailable("graph source returned a substituted policy identity")
        return result


def configured_graph_sources(scope: Scope) -> dict[str, Any] | None:
    """Resolve the exact deployment-owned source registry for one scope.

    The closed, versioned envelope prevents a shared process or copied
    environment variable from reading one customer's estate while recording
    the observation under another customer's database scope. Request bodies,
    model output, and provider responses never contribute to this value.
    """

    raw = os.environ.get("SOLVAN_PRODUCTION_GRAPH_SOURCES_JSON")
    if raw is None:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise GraphSourceConfigurationError(
            "SOLVAN_PRODUCTION_GRAPH_SOURCES_JSON is invalid"
        ) from error
    if not isinstance(value, dict):
        raise GraphSourceConfigurationError(
            "Production Graph source configuration must be an object"
        )
    if set(value) != {"schema_version", "scope", "sources"}:
        raise GraphSourceConfigurationError(
            "Production Graph source configuration has unknown or missing fields"
        )
    if value["schema_version"] != 1:
        raise GraphSourceConfigurationError(
            "Production Graph source configuration schema_version is unsupported"
        )
    if value["scope"] != scope.canonical_dict():
        raise GraphSourceConfigurationError(
            "Production Graph source configuration does not match the active scope"
        )
    sources = value["sources"]
    if not isinstance(sources, dict) or not sources:
        raise GraphSourceConfigurationError(
            "Production Graph source registry must be a non-empty object"
        )
    return sources


def graph_source_registry_from_config(
    transport: Any,
    *,
    config: Mapping[str, Any],
) -> GraphSourceRegistry:
    """Build the exact deployment-owned source registry.

    Configuration selects endpoints and authored IAM/resource mappings only.
    It carries no credential values and is never accepted from an HTTP request,
    model output, or provider payload. Unknown fields and source kinds refuse so
    a typo cannot silently weaken the graph.
    """

    adapters: dict[str, GraphSourceAdapter] = {}
    for source_key, raw in config.items():
        if not isinstance(source_key, str) or not source_key or not isinstance(raw, dict):
            raise ValueError("graph source configuration must be a named object")
        kind = raw.get("kind")
        if kind == "APP_HUB":
            _exact_fields(raw, {"kind", "host_project", "location"})
            adapters[source_key] = AppHubGraphSource(
                transport,
                host_project=_required_text(raw, "host_project"),
                location=_required_text(raw, "location"),
            )
        elif kind == "ASSET_INVENTORY":
            _exact_fields(raw, {"kind", "search_scope"})
            adapters[source_key] = AssetInventoryGraphSource(
                transport,
                search_scope=_required_text(raw, "search_scope"),
            )
        elif kind == "ASSET_RELATIONSHIPS":
            _exact_fields(raw, {"kind", "search_scope", "relationship_types"})
            relationship_types = _text_sequence(raw, "relationship_types")
            adapters[source_key] = AssetRelationshipGraphSource(
                transport,
                search_scope=_required_text(raw, "search_scope"),
                relationship_types=relationship_types,
            )
        elif kind == "IAM":
            _exact_fields(
                raw,
                {"kind", "search_scope", "principal_nodes", "resource_nodes"},
            )
            adapters[source_key] = IamPolicyGraphSource(
                transport,
                search_scope=_required_text(raw, "search_scope"),
                principal_nodes=_text_mapping(raw, "principal_nodes"),
                resource_nodes=_text_mapping(raw, "resource_nodes"),
            )
        else:
            raise ValueError(f"graph source {source_key} has an unsupported kind")
    return GraphSourceRegistry(adapters)


class AppHubGraphSource:
    """Read App Hub v1 applications and their registered services/workloads."""

    def __init__(self, transport: Any, *, host_project: str, location: str) -> None:
        if _project_from_uri(f"projects/{host_project}") != host_project:
            raise ValueError("App Hub host project must be a Google Cloud project id")
        if not location.strip() or "/" in location:
            raise ValueError("App Hub location must be one location id")
        self._transport = transport
        self._project = host_project
        self._location = location

    def fetch(self, *, source_key: str, source_revision: int) -> GraphSourceResult:
        applications, pages, complete = self._list(
            f"projects/{self._project}/locations/{self._location}/applications",
            "applications",
        )
        nodes: list[GraphNode] = []
        for application in applications:
            name = application.get("name")
            if not isinstance(name, str) or not name:
                continue
            for collection, reference, kind in (
                ("services", "serviceReference", "SERVICE"),
                ("workloads", "workloadReference", "DEPLOYMENT"),
            ):
                members, child_pages, child_complete = self._list(
                    f"{name}/{collection}", collection
                )
                pages += child_pages
                complete = complete and child_complete
                for item in members:
                    if item.get("state") not in (None, "ACTIVE"):
                        continue
                    reference_value = item.get(reference)
                    uri = reference_value.get("uri") if isinstance(reference_value, dict) else None
                    project = _project_from_uri(uri)
                    if not isinstance(uri, str) or project is None:
                        continue
                    attributes = item.get("attributes")
                    nodes.append(
                        GraphNode(
                            node_key=f"{kind.lower()}:{uri}",
                            node_kind=kind,
                            resource_ref=uri[:1_000],
                            external_project_id=project,
                            owner_team=_owner(attributes),
                            declared_environment=_attribute_type(attributes, "environment"),
                            business_criticality=_attribute_type(attributes, "criticality"),
                            data_classification=None,
                            authorization_boundary=None,
                            verification_profile=None,
                            region=_location_from_name(name) or self._location,
                            instrumentation_state="UNKNOWN",
                            source_key=source_key,
                            source_revision=source_revision,
                        )
                    )
        normalized = tuple(sorted(_dedupe_nodes(nodes), key=lambda item: item.node_key))
        return GraphSourceResult(
            source_key=source_key,
            source_revision=source_revision,
            tier=1,
            required_for_complete=True,
            outcome="COMPLETE" if complete else "PARTIAL",
            pagination_complete=complete,
            nodes=normalized,
            response_digest=_digest(
                [
                    {
                        "node_key": node.node_key,
                        "resource_ref": node.resource_ref,
                        "owner_team": node.owner_team,
                        "environment": node.declared_environment,
                        "criticality": node.business_criticality,
                    }
                    for node in normalized
                ]
            ),
            page_count=pages,
        )

    def _list(self, resource: str, collection: str) -> tuple[list[dict[str, Any]], int, bool]:
        values: list[dict[str, Any]] = []
        token: str | None = None
        for page in range(1, _MAX_PAGES + 1):
            params: dict[str, Any] = {"pageSize": _PAGE_SIZE, "orderBy": "name"}
            if token:
                params["pageToken"] = token
            payload = _get_json(
                self._transport,
                f"https://apphub.googleapis.com/v1/{resource}",
                params=params,
            )
            raw = payload.get(collection, [])
            if not isinstance(raw, list):
                raise GraphSourceUnavailable(f"App Hub {collection} response is malformed")
            values.extend(item for item in raw if isinstance(item, dict))
            unreachable = payload.get("unreachable", [])
            if isinstance(unreachable, list) and unreachable:
                return values, page, False
            next_token = payload.get("nextPageToken")
            token = next_token if isinstance(next_token, str) and next_token else None
            if token is None:
                return values, page, True
        return values, _MAX_PAGES, False


class AssetRelationshipGraphSource:
    """Read only explicitly allowed declared relationship types from CAI."""

    def __init__(
        self,
        transport: Any,
        *,
        search_scope: str,
        relationship_types: Sequence[str],
    ) -> None:
        if not search_scope.startswith(("projects/", "folders/", "organizations/")):
            raise ValueError("asset relationship scope is invalid")
        if not relationship_types or any(
            re.fullmatch(r"[A-Z0-9_]{3,160}", value) is None for value in relationship_types
        ):
            raise ValueError("relationship source requires an explicit closed type allowlist")
        self._transport = transport
        self._scope = search_scope
        self._types = tuple(sorted(set(relationship_types)))

    def fetch(self, *, source_key: str, source_revision: int) -> GraphSourceResult:
        edges: list[GraphEdge] = []
        token: str | None = None
        pages = 0
        complete = True
        for page_number in range(1, _MAX_PAGES + 1):
            pages = page_number
            params: dict[str, Any] = {
                "query": " OR ".join(f"relationships:{item}" for item in self._types),
                "pageSize": _PAGE_SIZE,
                "orderBy": "name",
                "readMask": "name,relationships",
            }
            if token:
                params["pageToken"] = token
            payload = _get_json(
                self._transport,
                f"https://cloudasset.googleapis.com/v1/{self._scope}:searchAllResources",
                params=params,
                entitlement_statuses=frozenset({402}),
            )
            raw = payload.get("results", [])
            if not isinstance(raw, list):
                raise GraphSourceUnavailable("Cloud Asset relationship response is malformed")
            edges.extend(self._edges(raw, source_key=source_key, source_revision=source_revision))
            next_token = payload.get("nextPageToken")
            token = next_token if isinstance(next_token, str) and next_token else None
            if token is None:
                break
        else:
            complete = False
        normalized = tuple(sorted(_dedupe_edges(edges), key=lambda item: item.edge_key))
        return GraphSourceResult(
            source_key=source_key,
            source_revision=source_revision,
            tier=3,
            required_for_complete=True,
            outcome="COMPLETE" if complete else "PARTIAL",
            pagination_complete=complete,
            edges=normalized,
            response_digest=_digest(
                [
                    {
                        "edge_key": edge.edge_key,
                        "from": edge.from_node_key,
                        "to": edge.to_node_key,
                    }
                    for edge in normalized
                ]
            ),
            page_count=pages,
        )

    def _edges(
        self, values: Sequence[Any], *, source_key: str, source_revision: int
    ) -> list[GraphEdge]:
        edges: list[GraphEdge] = []
        for value in values:
            if not isinstance(value, dict) or not isinstance(value.get("name"), str):
                continue
            source = value["name"]
            relationships = value.get("relationships")
            if not isinstance(relationships, dict):
                continue
            for relationship_type in self._types:
                group = relationships.get(relationship_type)
                related = group.get("relatedResources") if isinstance(group, dict) else None
                if not isinstance(related, list):
                    continue
                for item in related:
                    target = item.get("fullResourceName") if isinstance(item, dict) else None
                    if not isinstance(target, str) or not target:
                        continue
                    from_key = _resource_node_key(source)
                    to_key = _resource_node_key(target)
                    if from_key is None or to_key is None or from_key == to_key:
                        continue
                    edges.append(
                        GraphEdge(
                            edge_key=f"declared:{relationship_type}:{source}->{target}",
                            from_node_key=from_key,
                            to_node_key=to_key,
                            edge_kind="DEPENDS_ON_DECLARED",
                            source_key=source_key,
                            source_revision=source_revision,
                        )
                    )
        return edges


class IamPolicyGraphSource:
    """Read IAM policy pages and emit only explicitly resolved call grants.

    IAM membership does not by itself say which runtime service a service
    account represents.  The authored ``principal_nodes`` and
    ``resource_nodes`` maps are therefore required inputs to an edge; an
    unresolved binding is observed for the response digest but emits no edge.
    """

    def __init__(
        self,
        transport: Any,
        *,
        search_scope: str,
        principal_nodes: Mapping[str, str],
        resource_nodes: Mapping[str, str],
    ) -> None:
        if not search_scope.startswith(("projects/", "folders/", "organizations/")):
            raise ValueError("IAM policy scope is invalid")
        self._transport = transport
        self._scope = search_scope
        self._principals = dict(principal_nodes)
        self._resources = dict(resource_nodes)

    def fetch(self, *, source_key: str, source_revision: int) -> GraphSourceResult:
        token: str | None = None
        pages = 0
        complete = True
        edges: list[GraphEdge] = []
        observed: list[dict[str, str]] = []
        for page_number in range(1, _MAX_PAGES + 1):
            pages = page_number
            params: dict[str, Any] = {"pageSize": _PAGE_SIZE, "orderBy": "resource"}
            if token:
                params["pageToken"] = token
            payload = _get_json(
                self._transport,
                f"https://cloudasset.googleapis.com/v1/{self._scope}:searchAllIamPolicies",
                params=params,
            )
            raw = payload.get("results", [])
            if not isinstance(raw, list):
                raise GraphSourceUnavailable("Cloud IAM policy response is malformed")
            for item in raw:
                if not isinstance(item, dict) or not isinstance(item.get("resource"), str):
                    continue
                target = self._resources.get(item["resource"])
                policy = item.get("policy")
                bindings = policy.get("bindings") if isinstance(policy, dict) else None
                if not isinstance(bindings, list):
                    continue
                for binding in bindings:
                    if not isinstance(binding, dict) or binding.get("condition"):
                        continue
                    role = binding.get("role")
                    members = binding.get("members")
                    if not isinstance(role, str) or not isinstance(members, list):
                        continue
                    for member in members:
                        if not isinstance(member, str):
                            continue
                        observed.append(
                            {"resource": item["resource"], "role": role, "member": member}
                        )
                        source = self._principals.get(member)
                        if source is None or target is None or source == target:
                            continue
                        edges.append(
                            GraphEdge(
                                edge_key=f"iam:{member}:{role}:{item['resource']}",
                                from_node_key=source,
                                to_node_key=target,
                                edge_kind="ALLOWED_TO_CALL",
                                source_key=source_key,
                                source_revision=source_revision,
                            )
                        )
            next_token = payload.get("nextPageToken")
            token = next_token if isinstance(next_token, str) and next_token else None
            if token is None:
                break
        else:
            complete = False
        normalized = tuple(sorted(_dedupe_edges(edges), key=lambda item: item.edge_key))
        return GraphSourceResult(
            source_key=source_key,
            source_revision=source_revision,
            tier=2,
            required_for_complete=True,
            outcome="COMPLETE" if complete else "PARTIAL",
            pagination_complete=complete,
            edges=normalized,
            response_digest=_digest(sorted(observed, key=lambda item: tuple(item.values()))),
            page_count=pages,
        )


def _get_json(
    transport: Any,
    url: str,
    *,
    params: Mapping[str, Any],
    entitlement_statuses: frozenset[int] = frozenset(),
) -> dict[str, Any]:
    try:
        response = transport.get(url, params=dict(params), timeout=30)
    except Exception as error:
        raise GraphSourceUnavailable("Google graph source could not be reached") from error
    status_code = int(getattr(response, "status_code", 0))
    if status_code in entitlement_statuses:
        raise GraphSourceNotEntitled("the graph source requires a customer entitlement")
    if status_code in {401, 403}:
        raise GraphSourceDenied("verified identity was denied the graph source read")
    if status_code == 404:
        raise GraphSourceUnavailable("the required graph source API is not enabled")
    if not 200 <= status_code < 300:
        raise GraphSourceUnavailable(f"Google graph source returned status {status_code}")
    payload = response.json()
    if not isinstance(payload, dict):
        raise GraphSourceUnavailable("Google graph source response is not an object")
    return payload


__all__ = [
    "AppHubGraphSource",
    "AssetInventoryDenied",
    "AssetInventoryUnavailable",
    "AssetRelationshipGraphSource",
    "GraphSourceConfigurationError",
    "GraphSourceDenied",
    "GraphSourceNotEntitled",
    "GraphSourceRegistry",
    "GraphSourceUnavailable",
    "IamPolicyGraphSource",
    "configured_graph_sources",
    "graph_source_registry_from_config",
]
