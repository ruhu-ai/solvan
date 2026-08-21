"""Reliability Case opening and token-fenced scheduled continuation contracts."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from solvan.application.investigation import CoordinatorAuthority
from solvan.domain import Scope


class ReliabilityCaseConflict(RuntimeError):
    """Case creation or scheduled continuation lost its durable authority."""


@dataclass(frozen=True, slots=True)
class CaseSchedule:
    logical_step_key: str
    next_action_kind: str
    wake_at: datetime
    reason: str

    def __post_init__(self) -> None:
        if not self.logical_step_key.strip() or not self.next_action_kind.strip():
            raise ValueError("case logical step and next action are required")
        if not self.reason.strip():
            raise ValueError("case wakeup reason is required")
        if self.wake_at.tzinfo is None or self.wake_at.utcoffset() is None:
            raise ValueError("case wakeup timestamp must be timezone-aware")


@dataclass(frozen=True, slots=True)
class ReliabilityCaseRecord:
    case_id: str
    display_id: str
    workflow_version: int
    wakeup_id: str
    created: bool


@dataclass(frozen=True, slots=True)
class ClaimedWakeup:
    wakeup_id: str
    case_id: str
    logical_step_key: str
    reason: str
    wake_at: datetime
    claim_token: UUID
    claim_expires_at: datetime


class ReliabilityCaseRepository(Protocol):
    def transaction(self) -> AbstractContextManager[None]: ...

    def open_for_mitigated_incident(
        self,
        *,
        scope: Scope,
        incident_id: str,
        authority: CoordinatorAuthority,
        schedule: CaseSchedule,
    ) -> ReliabilityCaseRecord: ...


class ReliabilityCaseCoordinator:
    def __init__(self, repository: ReliabilityCaseRepository) -> None:
        self._repository = repository

    def open_for_mitigated_incident(
        self,
        *,
        scope: Scope,
        incident_id: str,
        authority: CoordinatorAuthority,
        schedule: CaseSchedule,
    ) -> ReliabilityCaseRecord:
        with self._repository.transaction():
            return self._repository.open_for_mitigated_incident(
                scope=scope,
                incident_id=incident_id,
                authority=authority,
                schedule=schedule,
            )
