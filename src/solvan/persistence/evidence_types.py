"""Value objects for the governed evidence-tool transaction boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from solvan.domain import Scope


@dataclass(frozen=True, slots=True)
class EvidenceToolReservation:
    call_id: str
    scope: Scope
    run_id: str
    incident_id: str | None
    alert_episode_id: str | None
    service_id: str
    service_key: str
    platform_kind: str
    platform_resource: str
    graph_snapshot_id: str
    #: Specification 13 §4.2. The project the incident's primary service runs
    #: in, read from its frozen graph node. A read about another node uses that
    #: node's project, never this one.
    service_project_id: str
    tool_name: str
    tool_version: str
    profile_key: str
    profile_version: str
    binding_kind: str
    capability_key: str | None
    connection_id: str | None
    connection_epoch: int | None
    identity_ref: str
    gateway_policy_ref: str
    input_bytes: int
    otel_span_id: str
    arguments_hash: str
    max_output_bytes: int
    maximum_aggregate_evidence_bytes: int
    existing_evidence_id: str | None = None


@dataclass(frozen=True, slots=True)
class EvidenceWrite:
    source_kind: str
    source_resource: str
    query_spec: dict[str, Any]
    window_start: datetime
    window_end: datetime
    observed_at: datetime
    content_ref: str
    content_hash: str
    classification: str
    residency: str
    redaction_manifest_ref: str
    provenance: dict[str, Any]
    freshness_expires_at: datetime


@dataclass(frozen=True, slots=True)
class StoredEvidence:
    evidence_id: str
    content_ref: str
    content_hash: str
    classification: str


@dataclass(frozen=True, slots=True)
class GraphNodeResource:
    node_id: str
    node_key: str
    node_kind: str
    resource_ref: str
    #: Specification 13 §4.2. The project this node's resource lives in. A read
    #: addresses the project of the node it is reading about, never the project
    #: of the incident's primary service.
    external_project_id: str


@dataclass(frozen=True, slots=True)
class ProductionGraphSlice:
    nodes: tuple[dict[str, Any], ...]
    edges: tuple[dict[str, Any], ...]
