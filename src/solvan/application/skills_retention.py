"""Fail-closed retention and regional deletion decisions for skill objects."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from solvan.domain import Scope

SETTLEMENT_OUTCOMES = frozenset(
    {
        "DELETED",
        "ALREADY_DELETED",
        "CLAIM_SUPERSEDED",
        "LEGAL_HOLD_ACTIVE",
        "REGION_DENIED",
        "RETENTION_NOT_EXPIRED",
    }
)


@dataclass(frozen=True, slots=True)
class RetentionRecord:
    object_kind: str
    object_id: str
    storage_region: str
    retention_until: datetime
    legal_hold_ref: str | None


@dataclass(frozen=True, slots=True)
class RetentionCandidate:
    record: RetentionRecord
    object_uri: str
    object_generation: str | None
    deletion_job_ref: str


class ObjectDeleter(Protocol):
    def delete(self, *, uri: str, expected_generation: str | None = None) -> str: ...


class RetentionDeletionRepository(Protocol):
    def claim_due(
        self, *, scope: Scope, region: str, now: datetime, limit: int
    ) -> tuple[RetentionCandidate, ...]: ...

    def settle(
        self,
        *,
        scope: Scope,
        candidate: RetentionCandidate,
        deleter: ObjectDeleter,
        requested_region: str,
        now: datetime,
    ) -> str: ...


def deletion_decision(
    record: RetentionRecord,
    *,
    requested_region: str,
    now: datetime | None = None,
) -> str:
    """Return a closed decision; callers must persist ``DELETED`` atomically."""
    if record.storage_region != requested_region:
        raise ValueError("REGION_DENIED")
    if record.legal_hold_ref is not None:
        raise ValueError("LEGAL_HOLD_ACTIVE")
    current = now or datetime.now(UTC)
    if current < record.retention_until:
        raise ValueError("RETENTION_NOT_EXPIRED")
    return "DELETE_ELIGIBLE"


def execute_due_deletions(
    *,
    repository: RetentionDeletionRepository,
    deleter: ObjectDeleter,
    scope: Scope,
    region: str,
    now: datetime | None = None,
    limit: int = 20,
) -> int:
    """Delete only claimed, expired, same-region objects and settle receipts.

    Settlement holds the control row lock, re-runs :func:`deletion_decision`
    against the locked state, and only then invokes the provider delete, so a
    hold attached after the claim refuses deletion before any object is
    destroyed.  A refused or superseded candidate leaves the object intact and
    is never counted as deleted.
    """
    if limit < 1 or limit > 100:
        raise ValueError("deletion batch limit is outside policy")
    current = now or datetime.now(UTC)
    candidates = repository.claim_due(scope=scope, region=region, now=current, limit=limit)
    completed = 0
    for candidate in candidates:
        deletion_decision(candidate.record, requested_region=region, now=current)
        outcome = repository.settle(
            scope=scope,
            candidate=candidate,
            deleter=deleter,
            requested_region=region,
            now=current,
        )
        if outcome not in SETTLEMENT_OUTCOMES:
            raise ValueError("DELETION_OUTCOME_UNKNOWN")
        if outcome == "DELETED":
            completed += 1
    return completed
