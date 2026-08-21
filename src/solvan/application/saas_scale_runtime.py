"""Deterministic local runtime controls for the SaaS target profile.

The deployed shared-cell implementation will execute the same decisions in
Cloud SQL.  This module deliberately contains no tenant content and accepts
no tenant or placement choice from a model or request payload; it is the
small state-machine seam used by the local harness and by the future broker
adapter.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from solvan.application.saas_scale import ScaleRuntimeError

_LIFECYCLE_TRANSITIONS: frozenset[tuple[str, str]] = frozenset(
    {
        ("PENDING", "QUIESCING"),
        ("PENDING", "BLOCKED"),
        ("PENDING", "FAILED"),
        ("PENDING", "CANCELLED"),
        ("QUIESCING", "EXPORTING"),
        ("QUIESCING", "VERIFYING"),
        ("QUIESCING", "BLOCKED"),
        ("QUIESCING", "FAILED"),
        ("QUIESCING", "CANCELLED"),
        ("EXPORTING", "RESTORING"),
        ("EXPORTING", "VERIFYING"),
        ("EXPORTING", "BLOCKED"),
        ("EXPORTING", "FAILED"),
        ("RESTORING", "VERIFYING"),
        ("RESTORING", "BLOCKED"),
        ("RESTORING", "FAILED"),
        ("VERIFYING", "CUTOVER_READY"),
        ("VERIFYING", "COMPLETED"),
        ("VERIFYING", "BLOCKED"),
        ("VERIFYING", "FAILED"),
        ("CUTOVER_READY", "CUTOVER_COMMITTED"),
        ("CUTOVER_READY", "BLOCKED"),
        ("CUTOVER_READY", "FAILED"),
        ("CUTOVER_READY", "CANCELLED"),
        ("CUTOVER_COMMITTED", "COMPLETED"),
        ("BLOCKED", "PENDING"),
        ("BLOCKED", "FAILED"),
        ("BLOCKED", "CANCELLED"),
    }
)
_TERMINAL_LIFECYCLE_STATES = frozenset({"COMPLETED", "FAILED", "CANCELLED"})


@dataclass(frozen=True, slots=True)
class LifecycleJobState:
    organization_id: str
    job_id: str
    job_kind: str
    expected_placement_epoch: int
    source_cell_id: str
    state: str = "PENDING"
    destination_cell_id: str | None = None
    proposed_placement_epoch: int | None = None
    request_hash: str = ""
    quiesce_receipt_hash: str | None = None
    source_high_water: int | None = None
    export_manifest_hash: str | None = None
    destination_verification_hash: str | None = None
    isolation_verification_hash: str | None = None
    cutover_decision_ref: str | None = None
    completion_proof_hash: str | None = None
    legal_hold_ref: str | None = None
    unsettled_mutation_count: int = 0

    def __post_init__(self) -> None:
        if not self.organization_id or not self.job_id or self.expected_placement_epoch < 1:
            raise ValueError("lifecycle identity and expected epoch are required")
        if self.job_kind not in {
            "PROVISION",
            "SUSPEND",
            "RESUME",
            "MOVE",
            "EXPORT",
            "DELETE",
            "RESTORE_TEST",
        }:
            raise ValueError("unknown lifecycle job kind")
        if self.state not in {
            "PENDING",
            "QUIESCING",
            "EXPORTING",
            "RESTORING",
            "VERIFYING",
            "CUTOVER_READY",
            "CUTOVER_COMMITTED",
            "COMPLETED",
            "BLOCKED",
            "FAILED",
            "CANCELLED",
        }:
            raise ValueError("unknown lifecycle state")
        if self.request_hash and not self.request_hash.startswith("sha256:"):
            raise ValueError("request hash must be typed")
        if (
            self.proposed_placement_epoch is not None
            and self.proposed_placement_epoch <= self.expected_placement_epoch
        ):
            raise ValueError("destination placement epoch must increase")
        if self.unsettled_mutation_count < 0:
            raise ValueError("unsettled mutation count cannot be negative")


class LifecycleController:
    """Apply the target lifecycle table without implicit rollback or skips."""

    def transition(
        self,
        job: LifecycleJobState,
        *,
        expected_from: str,
        to_state: str,
        completion_proof_hash: str | None = None,
    ) -> LifecycleJobState:
        if not isinstance(job, LifecycleJobState):
            raise ScaleRuntimeError("lifecycle operands must be typed application records")
        if job.state != expected_from:
            raise ScaleRuntimeError("lifecycle transition lost its expected state fence")
        if job.state in _TERMINAL_LIFECYCLE_STATES:
            raise ScaleRuntimeError("terminal lifecycle job is immutable")
        if (expected_from, to_state) not in _LIFECYCLE_TRANSITIONS:
            raise ScaleRuntimeError("undeclared lifecycle job transition")
        if (
            job.job_kind == "MOVE"
            and to_state == "COMPLETED"
            and expected_from != "CUTOVER_COMMITTED"
        ):
            raise ScaleRuntimeError("move completion requires the committed cutover")
        if to_state == "COMPLETED":
            if job.job_kind == "DELETE" and (job.legal_hold_ref or job.unsettled_mutation_count):
                raise ScaleRuntimeError(
                    "delete completion requires no legal hold or unsettled mutation"
                )
            proof = completion_proof_hash or job.completion_proof_hash
            if not proof or not proof.startswith("sha256:"):
                raise ScaleRuntimeError("lifecycle completion requires a typed proof")
            job = replace(job, completion_proof_hash=proof)
        return replace(job, state=to_state)

    def prepare_move(
        self,
        job: LifecycleJobState,
        *,
        destination_cell_id: str,
        proposed_placement_epoch: int,
        quiesce_receipt_hash: str,
        source_high_water: int,
        export_manifest_hash: str,
        destination_verification_hash: str,
        isolation_verification_hash: str,
        cutover_decision_ref: str,
    ) -> LifecycleJobState:
        """Create a cutover-ready move only from a verified, fenced state."""

        if not isinstance(job, LifecycleJobState):
            raise ScaleRuntimeError("lifecycle operands must be typed application records")
        if job.job_kind != "MOVE" or job.state != "VERIFYING":
            raise ScaleRuntimeError("move cutover requires a VERIFYING move job")
        if not destination_cell_id or destination_cell_id == job.source_cell_id:
            raise ScaleRuntimeError("move destination must be a different cell")
        if proposed_placement_epoch <= job.expected_placement_epoch:
            raise ScaleRuntimeError("move epoch must be strictly monotonic")
        if source_high_water < 0 or not cutover_decision_ref.startswith("ref_"):
            raise ScaleRuntimeError("move verification operands are invalid")
        hashes = (
            quiesce_receipt_hash,
            export_manifest_hash,
            destination_verification_hash,
            isolation_verification_hash,
        )
        if any(not value.startswith("sha256:") for value in hashes):
            raise ScaleRuntimeError("move receipts must be typed hashes")
        return replace(
            job,
            state="CUTOVER_READY",
            destination_cell_id=destination_cell_id,
            proposed_placement_epoch=proposed_placement_epoch,
            quiesce_receipt_hash=quiesce_receipt_hash,
            source_high_water=source_high_water,
            export_manifest_hash=export_manifest_hash,
            destination_verification_hash=destination_verification_hash,
            isolation_verification_hash=isolation_verification_hash,
            cutover_decision_ref=cutover_decision_ref,
        )

    def commit_move(self, job: LifecycleJobState, *, decision_ref: str) -> LifecycleJobState:
        if not isinstance(job, LifecycleJobState):
            raise ScaleRuntimeError("lifecycle operands must be typed application records")
        if job.state != "CUTOVER_READY" or job.cutover_decision_ref != decision_ref:
            raise ScaleRuntimeError("move cutover decision is stale or mismatched")
        return replace(job, state="CUTOVER_COMMITTED")


@dataclass(frozen=True, slots=True)
class SequencedEvent:
    organization_id: str
    project_id: str
    environment_id: str
    event_id: str
    event_ref: str
    event_hash: str
    placement_epoch: int
    created_at: datetime
    state: str = "UNSEQUENCED"
    attempt_count: int = 0
    claim_token: UUID | None = None
    claim_expires_at: datetime | None = None
    scope_sequence: int | None = None
    error_ref: str | None = None


class CommittedEventSequencer:
    """In-memory equivalent of the target post-commit sequencer contract."""

    def __init__(self, *, placement_epoch: int, now: datetime | None = None) -> None:
        if placement_epoch < 1:
            raise ValueError("placement epoch must be positive")
        self.placement_epoch = placement_epoch
        self._next_sequence = 1
        self._events: dict[str, SequencedEvent] = {}
        self._now = now or datetime.now(UTC)

    @property
    def events(self) -> tuple[SequencedEvent, ...]:
        return tuple(self._events.values())

    def ingest(self, event: SequencedEvent) -> SequencedEvent:
        if event.placement_epoch != self.placement_epoch:
            raise ScaleRuntimeError("event placement epoch is stale")
        existing = self._events.get(event.event_id)
        if existing is not None:
            if existing.event_hash != event.event_hash:
                raise ScaleRuntimeError("event id was reused with a different payload")
            return existing
        if any(existing.event_hash == event.event_hash for existing in self._events.values()):
            raise ScaleRuntimeError("duplicate committed event payload")
        self._events[event.event_id] = event
        return event

    def claim(
        self, event_id: str, *, now: datetime | None = None, lease_seconds: int = 30
    ) -> SequencedEvent:
        moment = now or self._now
        event = self._events.get(event_id)
        if event is None or event.placement_epoch != self.placement_epoch:
            raise ScaleRuntimeError("event is absent or stale")
        if event.state == "QUARANTINED":
            raise ScaleRuntimeError("poison event blocks its cursor")
        if event.state == "CLAIMED" and event.claim_expires_at and event.claim_expires_at > moment:
            raise ScaleRuntimeError("event claim is still live")
        if event.state not in {"UNSEQUENCED", "CLAIMED"}:
            raise ScaleRuntimeError("event is not claimable")
        if not 1 <= lease_seconds <= 300:
            raise ValueError("event lease must be bounded")
        claimed = replace(
            event,
            state="CLAIMED",
            claim_token=uuid4(),
            claim_expires_at=moment + timedelta(seconds=lease_seconds),
            attempt_count=event.attempt_count + 1,
        )
        self._events[event_id] = claimed
        return claimed

    def sequence(
        self, event_id: str, *, claim_token: UUID, now: datetime | None = None
    ) -> SequencedEvent:
        moment = now or self._now
        event = self._events.get(event_id)
        if event is not None and event.state == "QUARANTINED":
            raise ScaleRuntimeError("quarantined event blocks its cursor")
        if event is None or event.state != "CLAIMED" or event.claim_token != claim_token:
            raise ScaleRuntimeError("event claim token is stale")
        if event.claim_expires_at is None or event.claim_expires_at <= moment:
            raise ScaleRuntimeError("event claim expired")
        if any(other.state == "QUARANTINED" for other in self._events.values()):
            raise ScaleRuntimeError("quarantined event blocks scope sequencing")
        sequenced = replace(
            event,
            state="SEQUENCED",
            scope_sequence=self._next_sequence,
            claim_token=None,
            claim_expires_at=None,
        )
        self._next_sequence += 1
        self._events[event_id] = sequenced
        return sequenced

    def quarantine(self, event_id: str, *, claim_token: UUID, error_ref: str) -> SequencedEvent:
        event = self._events.get(event_id)
        if event is None or event.state != "CLAIMED" or event.claim_token != claim_token:
            raise ScaleRuntimeError("event claim token is stale")
        if not error_ref.startswith("ref_"):
            raise ValueError("poison error must be a typed reference")
        quarantined = replace(
            event, state="QUARANTINED", claim_token=None, claim_expires_at=None, error_ref=error_ref
        )
        self._events[event_id] = quarantined
        return quarantined

    def supersede(self, event_id: str, *, error_ref: str) -> SequencedEvent:
        event = self._events.get(event_id)
        if event is None or event.state != "QUARANTINED" or event.error_ref != error_ref:
            raise ScaleRuntimeError("poison event supersession is not authorized")
        superseded = replace(event, state="SUPERSEDED")
        self._events[event_id] = superseded
        return superseded


def typed_event_hash(event_ref: str, payload_hash: str) -> str:
    """Derive a content-free event hash for idempotent ingress tests."""

    if not event_ref.startswith("ref_") or not payload_hash.startswith("sha256:"):
        raise ValueError("event reference and payload hash must be typed")
    return "sha256:" + hashlib.sha256(f"{event_ref}:{payload_hash}".encode()).hexdigest()
