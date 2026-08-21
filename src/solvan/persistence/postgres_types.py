"""Public workflow-store value types and conflict errors."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class ClaimLost(RuntimeError):
    """Raised when a stale claimant attempts to complete another claimant's claim."""


class WorkflowConflict(RuntimeError):
    """Raised when workflow version or lease ownership changed before commit."""


class AggregateType(StrEnum):
    INCIDENT = "INCIDENT"
    RELIABILITY_CASE = "RELIABILITY_CASE"


class IngressDisposition(StrEnum):
    ACCEPTED = "ACCEPTED"
    DUPLICATE = "DUPLICATE"


@dataclass(frozen=True, slots=True)
class LeaseHandle:
    aggregate_type: AggregateType
    entity_id: str
    owner: str
    token: UUID
    workflow_version: int
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class TransitionWrite:
    from_state: str
    to_state: str
    transition_key: str
    actor_type: str
    actor_id: str
    reason_code: str
    rationale_summary: str
    evidence_refs: tuple[str, ...] = ()
    policy_decision_id: str | None = None
    trace_id: str | None = None


@dataclass(frozen=True, slots=True)
class IngressResult:
    event_id: str
    disposition: IngressDisposition
    processing_state: str
