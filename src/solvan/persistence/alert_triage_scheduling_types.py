"""Shared durable Alert scheduling records and closed errors."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from solvan.application.alert_admission import AlertAdmissionResult
from solvan.domain import Scope


class AlertSchedulingError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class AlertAdmissionCommit:
    admission_id: str
    episode_id: str
    decision: str
    reason_code: str
    work_id: str | None
    reservation_id: str | None
    due_at: datetime | None
    created: bool


@dataclass(frozen=True, slots=True)
class AlertTriageClaim:
    triage_run_id: str
    agent_run_id: str
    episode_id: str
    work_id: str
    claim_token: str
    claim_epoch: int
    lease_expires_at: datetime
    reclaimed: bool


class AlertAdmissionWriter(Protocol):
    """Private persistence seam required by the scheduling mixin."""

    def _current_admission(
        self, *, cursor: Any, values: dict[str, Any]
    ) -> dict[str, Any] | None: ...

    def _append_admission(
        self,
        *,
        cursor: Any,
        scope: Scope,
        episode: dict[str, Any],
        result: AlertAdmissionResult,
        work_id: str | None,
        reservation_id: str | None,
        request_hash: str | None,
        decided_at: datetime,
    ) -> AlertAdmissionCommit: ...
