"""Cloud Asset Inventory as a bounded, tier-1 catalog source for the graph.

Specification 20 §2. This is the source that makes onboarding possible: it
establishes which resources exist in a customer estate, so a stranger can point
Solvan at their own project instead of hand-authoring a graph.

It originates **nodes only**. Cloud Asset Inventory can also return declared
relationships, but that is a separately entitled Security Command Centre
Premium or Enterprise feature; a snapshot built from this source alone is
honestly `INCOMPLETE` for dependency authority rather than silently
edgeless-and-complete.

Everything the provider returns is untrusted data. Display names come from a
customer's estate and never reach an authority field — no owner, environment,
criticality, classification, or boundary is inferred from them.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from solvan.application.production_graph_types import GraphNode, GraphSourceResult

#: Asset types this source is permitted to originate, and the node kind each
#: becomes. A type absent here is ignored rather than guessed at: an unknown
#: asset with an invented node kind would be a fabricated production fact.
ASSET_TYPE_NODE_KINDS: dict[str, str] = {
    "run.googleapis.com/Service": "SERVICE",
    "sqladmin.googleapis.com/Instance": "DATABASE",
    "pubsub.googleapis.com/Topic": "QUEUE",
    "pubsub.googleapis.com/Subscription": "QUEUE",
}

#: One page is bounded, and so is the number of pages. An estate larger than
#: this is not silently truncated: `pagination_complete` goes false and the
#: snapshot cannot be `COMPLETE`.
_PAGE_SIZE = 500
_MAXIMUM_PAGES = 20
_MAXIMUM_NODES = _PAGE_SIZE * _MAXIMUM_PAGES

_PROJECT_IN_NAME = re.compile(r"//[a-z0-9.-]+/projects/([a-z][a-z0-9-]{4,61})/")
_PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,61}$")
_SAFE_LABEL = re.compile(r"^[\w .:/@-]{1,200}$")


class AssetInventoryUnavailable(RuntimeError):
    """The catalog could not be read conclusively.

    Distinct from an empty estate. A refused or unreachable search proves
    nothing about what exists, and recording it as "no resources found" would
    let a snapshot claim a customer runs nothing.
    """


class AssetInventoryDenied(RuntimeError):
    """Verified identity reached the API and was refused the catalog read."""


class SearchTransport(Protocol):
    def get(self, url: str, **kwargs: Any) -> Any: ...


@dataclass(frozen=True, slots=True)
class DiscoveredResource:
    """One sanitized Cloud Asset Inventory result.

    Only fields Solvan will actually use survive the projection. The raw
    provider payload never leaves this module.
    """

    asset_type: str
    resource_name: str
    external_project_id: str
    location: str
    display_name: str

    @property
    def node_kind(self) -> str:
        return ASSET_TYPE_NODE_KINDS[self.asset_type]

    @property
    def node_key(self) -> str:
        """Stable across runs, derived from identity rather than order.

        Keyed on the full resource name so two resources that share a display
        name in different projects remain two nodes.
        """
        return f"{self.node_kind.lower()}:{self.resource_name}"


class AssetInventoryGraphSource:
    """Bounded catalog reads over one external resource scope.

    The scope is a Cloud Asset Inventory search scope — `projects/…`,
    `folders/…`, or `organizations/…` — which is why one folder-level grant can
    enumerate every project beneath it (specification 13 §4.1).
    """

    def __init__(
        self,
        transport: SearchTransport,
        *,
        search_scope: str,
        asset_types: Sequence[str] | None = None,
    ) -> None:
        if not search_scope.startswith(("projects/", "folders/", "organizations/")):
            raise ValueError("asset search scope must be a project, folder, or organization")
        selected = tuple(asset_types or ASSET_TYPE_NODE_KINDS)
        unknown = [item for item in selected if item not in ASSET_TYPE_NODE_KINDS]
        if unknown:
            raise ValueError(f"asset types are outside the permitted catalog: {sorted(unknown)}")
        self._transport = transport
        self._scope = search_scope
        self._asset_types = selected

    def fetch(self, *, source_key: str, source_revision: int) -> GraphSourceResult:
        if not source_key.strip() or source_revision < 1:
            raise ValueError("asset inventory source identity is required")
        resources, pagination_complete, page_count = self._search()
        nodes = tuple(
            GraphNode(
                node_key=item.node_key,
                node_kind=item.node_kind,
                resource_ref=item.resource_name,
                external_project_id=item.external_project_id,
                # A catalog establishes existence and location. Ownership,
                # environment, criticality, classification, boundary, and
                # verification profile are governed attributes that an
                # authored decision or a higher-authority source sets; this
                # source leaves them absent rather than guessing.
                owner_team=None,
                declared_environment=None,
                business_criticality=None,
                data_classification=None,
                authorization_boundary=None,
                verification_profile=None,
                region=item.location,
                instrumentation_state="UNKNOWN",
                source_key=source_key,
                source_revision=source_revision,
            )
            for item in resources
        )
        return GraphSourceResult(
            source_key=source_key,
            source_revision=source_revision,
            tier=1,
            required_for_complete=True,
            outcome="COMPLETE" if pagination_complete else "PARTIAL",
            pagination_complete=pagination_complete,
            nodes=nodes,
            edges=(),
            response_digest=_digest(resources),
            page_count=page_count,
        )

    def _search(self) -> tuple[tuple[DiscoveredResource, ...], bool, int]:
        collected: list[DiscoveredResource] = []
        page_token: str | None = None
        for _page in range(_MAXIMUM_PAGES):
            payload = self._page(page_token)
            raw = payload.get("results", [])
            if not isinstance(raw, list):
                raise AssetInventoryUnavailable("Cloud Asset Inventory results are not a list")
            collected.extend(_projected(raw))
            token = payload.get("nextPageToken")
            page_token = token if isinstance(token, str) and token else None
            if page_token is None:
                # Ordering is by resource name so the digest is stable across
                # runs that return the same estate in a different order.
                return _deduplicated(collected), True, _page + 1
            if len(collected) >= _MAXIMUM_NODES:
                break
        return _deduplicated(collected), False, _MAXIMUM_PAGES

    def _page(self, page_token: str | None) -> dict[str, Any]:
        parameters: dict[str, Any] = {
            "assetTypes": list(self._asset_types),
            "pageSize": _PAGE_SIZE,
            "orderBy": "name",
            "readMask": "name,assetType,displayName,location",
        }
        if page_token:
            parameters["pageToken"] = page_token
        try:
            response = self._transport.get(
                f"https://cloudasset.googleapis.com/v1/{self._scope}:searchAllResources",
                params=parameters,
                timeout=30,
            )
        except Exception as error:
            raise AssetInventoryUnavailable(
                "Cloud Asset Inventory could not be reached conclusively"
            ) from error
        status_code = int(getattr(response, "status_code", 0))
        if status_code in (401, 403):
            raise AssetInventoryDenied("roles/cloudasset.viewer was refused on this search scope")
        if status_code == 404:
            raise AssetInventoryUnavailable(
                "the Cloud Asset API is not enabled on this search scope"
            )
        if not 200 <= status_code < 300:
            raise AssetInventoryUnavailable(f"Cloud Asset Inventory returned status {status_code}")
        payload = response.json()
        if not isinstance(payload, dict):
            raise AssetInventoryUnavailable("Cloud Asset Inventory response is not an object")
        return payload


def _projected(raw: Iterable[Any]) -> list[DiscoveredResource]:
    projected: list[DiscoveredResource] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        asset_type = item.get("assetType")
        name = item.get("name")
        if not isinstance(asset_type, str) or asset_type not in ASSET_TYPE_NODE_KINDS:
            continue
        if not isinstance(name, str) or not name:
            continue
        project = _PROJECT_IN_NAME.search(name)
        if project is None or not _PROJECT_ID.fullmatch(project.group(1)):
            # A resource whose project cannot be established has no address, and
            # §13 §4.2 forbids inventing one. Skipping it keeps the node out of
            # the graph rather than putting an unaddressable node in it.
            continue
        location = item.get("location")
        projected.append(
            DiscoveredResource(
                asset_type=asset_type,
                resource_name=name[:1_000],
                external_project_id=project.group(1),
                location=location if isinstance(location, str) and location else "global",
                display_name=_safe_label(item.get("displayName")),
            )
        )
    return projected


def _safe_label(value: Any) -> str:
    """Display names are customer-authored text and are treated as such.

    Bounded, control characters rejected, and used only as a label. Nothing
    downstream may derive authority from it.
    """
    if not isinstance(value, str):
        return ""
    candidate = value.strip()[:200]
    return candidate if _SAFE_LABEL.fullmatch(candidate) else ""


def _deduplicated(items: Sequence[DiscoveredResource]) -> tuple[DiscoveredResource, ...]:
    unique = {item.resource_name: item for item in items}
    return tuple(unique[name] for name in sorted(unique))


def _digest(resources: Sequence[DiscoveredResource]) -> str:
    material = [
        {
            "name": item.resource_name,
            "type": item.asset_type,
            "project": item.external_project_id,
            "location": item.location,
        }
        for item in resources
    ]
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
