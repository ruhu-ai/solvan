"""Typed source contracts shared by graph adapters and the graph repository."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

_SOURCE_OUTCOMES = frozenset(
    {
        "COMPLETE",
        "PARTIAL",
        "UNAVAILABLE",
        "NOT_ENTITLED",
        "REFUSED_REGION",
        "REFUSED_CLASSIFICATION",
    }
)


@dataclass(frozen=True, slots=True)
class GraphSourcePlanEntry:
    """One exact immutable source-policy revision frozen into a graph run."""

    source_key: str
    source_revision: int
    tier: int
    required_for_complete: bool
    policy_hash: str

    def __post_init__(self) -> None:
        if not self.source_key.strip() or self.source_revision < 1:
            raise ValueError("graph source plan requires an exact source revision")
        if self.tier not in {1, 2, 3, 4}:
            raise ValueError("graph source tier is closed to 1..4")
        if not self.policy_hash.startswith("sha256:") or len(self.policy_hash) != 71:
            raise ValueError("graph source policy hash must be a sha256 digest")


@dataclass(frozen=True, slots=True)
class GraphNode:
    node_key: str
    node_kind: str
    resource_ref: str
    external_project_id: str | None
    owner_team: str | None
    declared_environment: str | None
    business_criticality: str | None
    data_classification: str | None
    authorization_boundary: str | None
    verification_profile: str | None
    region: str
    instrumentation_state: str
    source_key: str
    source_revision: int


@dataclass(frozen=True, slots=True)
class GraphEdge:
    edge_key: str
    from_node_key: str
    to_node_key: str
    edge_kind: str
    source_key: str
    source_revision: int


@dataclass(frozen=True, slots=True)
class GraphSourceResult:
    source_key: str
    source_revision: int
    tier: int
    required_for_complete: bool
    outcome: str
    pagination_complete: bool
    nodes: tuple[GraphNode, ...] = ()
    edges: tuple[GraphEdge, ...] = ()
    response_digest: str = ""
    page_count: int = 1

    def __post_init__(self) -> None:
        if self.outcome not in _SOURCE_OUTCOMES:
            raise ValueError("graph source outcome is closed")
        if self.outcome == "COMPLETE" and not self.pagination_complete:
            raise ValueError("complete graph source results require exhausted pagination")
        if self.outcome == "PARTIAL" and self.pagination_complete:
            raise ValueError("partial graph source results cannot claim exhausted pagination")
        if self.outcome not in {"COMPLETE", "PARTIAL"} and (self.nodes or self.edges):
            raise ValueError("failed or refused graph source results cannot carry elements")
        if self.page_count < 0:
            raise ValueError("graph source page count cannot be negative")
        if self.outcome in {"COMPLETE", "PARTIAL"} and self.page_count < 1:
            raise ValueError("completed graph source results require at least one page")


class GraphSourceAdapter(Protocol):
    """One coordinator-selected, read-only Production Graph source."""

    def fetch(self, *, source_key: str, source_revision: int) -> GraphSourceResult: ...
