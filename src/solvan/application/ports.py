"""Application-facing ports and durable workflow transfer objects."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from solvan.domain import Scope


class IncidentDisposition(StrEnum):
    ATTACHED = "ATTACHED"
    CREATED = "CREATED"


@dataclass(frozen=True, slots=True)
class ClaimedEvent:
    event_id: str
    event_type: str
    claim_token: UUID
    claim_expires_at: datetime


@dataclass(frozen=True, slots=True)
class OutboxEnvelope:
    event_id: str
    aggregate_type: str
    aggregate_id: str
    aggregate_version: int
    topic: str
    event_type: str
    payload: dict[str, object]
    idempotency_key: str


@dataclass(frozen=True, slots=True)
class IncidentOpenRequest:
    state_machine_version: str
    severity: str
    incident_class: str
    primary_service_id: str
    production_graph_snapshot_id: str
    detected_at: datetime
    detection_rule_id: str | None
    detection_rule_version: int | None
    deduplication_key: str
    action_budget: int
    repeated_action_limit: int
    trigger_policy_key: str | None = None
    trigger_policy_version: str | None = None

    def __post_init__(self) -> None:
        detection = self.detection_rule_id is not None and self.detection_rule_version is not None
        trigger = self.trigger_policy_key is not None and self.trigger_policy_version is not None
        if detection == trigger:
            raise ValueError("an incident requires exactly one detector or trigger-policy source")


@dataclass(frozen=True, slots=True)
class IncidentOpenResult:
    incident_id: str
    display_id: str
    workflow_version: int
    disposition: IncidentDisposition


class IncidentStore(Protocol):
    def transaction(self) -> AbstractContextManager[None]: ...

    def open_or_attach_incident(
        self, *, scope: Scope, request: IncidentOpenRequest
    ) -> IncidentOpenResult: ...

    def complete_inbox(
        self,
        *,
        scope: Scope,
        owner: str,
        claim: ClaimedEvent,
        result_ref: str | None,
        error_class: str | None = None,
    ) -> None: ...
