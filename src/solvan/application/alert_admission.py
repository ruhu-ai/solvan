"""Deterministic Alert Triage admission decisions for specification 21."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AdmissionDecision(StrEnum):
    ADMITTED = "ADMITTED"
    SUPPRESSED = "SUPPRESSED"
    BLOCKED = "BLOCKED"
    PENDING = "PENDING"


class CapacityDecision(StrEnum):
    RESERVED = "RESERVED"
    WAITING = "WAITING"
    EXHAUSTED = "EXHAUSTED"


class AlertAdmissionInput(BaseModel):
    """Facts already verified by their owning application boundaries."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_state: Literal["OPEN", "CLOSED"]
    observed_at: datetime
    evaluated_at: datetime
    maximum_queue_age_ms: int = Field(ge=1_000)
    pending_for_target: int = Field(ge=0)
    maximum_pending_per_target: int = Field(ge=1)
    cooldown_until: datetime | None = None
    fence_failure_reason: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    capacity_decision: CapacityDecision
    capacity_receipt_ref: str | None = Field(default=None, min_length=1, max_length=512)
    capacity_retry_at: datetime | None = None

    @model_validator(mode="after")
    def exact_capacity_shape(self) -> AlertAdmissionInput:
        if self.capacity_decision is CapacityDecision.RESERVED:
            if self.capacity_receipt_ref is None or self.capacity_retry_at is not None:
                raise ValueError("reserved capacity requires only its exact receipt")
        elif self.capacity_receipt_ref is not None:
            raise ValueError("non-reserved capacity cannot carry a reservation receipt")
        if self.capacity_decision is CapacityDecision.WAITING and self.capacity_retry_at is None:
            raise ValueError("waiting capacity requires a retry time")
        if (
            self.capacity_decision is CapacityDecision.EXHAUSTED
            and self.capacity_retry_at is not None
        ):
            raise ValueError("exhausted capacity cannot imply an authorized retry")
        return self


class AlertAdmissionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: AdmissionDecision
    reason_code: str
    budget_receipt_ref: str | None = None
    cooldown_until: datetime | None = None
    due_at: datetime | None = None


def evaluate_alert_admission(request: AlertAdmissionInput) -> AlertAdmissionResult:
    """Apply closed precedence; no model output or provider prose is accepted."""

    if request.source_state == "CLOSED":
        return AlertAdmissionResult(
            decision=AdmissionDecision.SUPPRESSED,
            reason_code="SOURCE_ALREADY_CLOSED",
        )
    if request.fence_failure_reason is not None:
        return AlertAdmissionResult(
            decision=AdmissionDecision.BLOCKED,
            reason_code=request.fence_failure_reason,
        )
    age_ms = (request.evaluated_at - request.observed_at).total_seconds() * 1_000
    if age_ms < 0:
        return AlertAdmissionResult(
            decision=AdmissionDecision.BLOCKED,
            reason_code="SOURCE_TIME_INVALID",
        )
    if age_ms > request.maximum_queue_age_ms:
        return AlertAdmissionResult(
            decision=AdmissionDecision.BLOCKED,
            reason_code="TRIAGE_QUEUE_EXPIRED",
        )
    if request.cooldown_until is not None and request.cooldown_until > request.evaluated_at:
        return AlertAdmissionResult(
            decision=AdmissionDecision.SUPPRESSED,
            reason_code="COOLDOWN_ACTIVE",
            cooldown_until=request.cooldown_until,
        )
    if request.pending_for_target >= request.maximum_pending_per_target:
        return AlertAdmissionResult(
            decision=AdmissionDecision.SUPPRESSED,
            reason_code="PENDING_LIMIT_REACHED",
        )
    if request.capacity_decision is CapacityDecision.WAITING:
        return AlertAdmissionResult(
            decision=AdmissionDecision.PENDING,
            reason_code="CENTRAL_CAPACITY_WAIT",
            due_at=request.capacity_retry_at,
        )
    if request.capacity_decision is CapacityDecision.EXHAUSTED:
        return AlertAdmissionResult(
            decision=AdmissionDecision.BLOCKED,
            reason_code="TRIAGE_CAPACITY_EXHAUSTED",
        )
    return AlertAdmissionResult(
        decision=AdmissionDecision.ADMITTED,
        reason_code="TRIAGE_ADMITTED",
        budget_receipt_ref=request.capacity_receipt_ref,
    )
