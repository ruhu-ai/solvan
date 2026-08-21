"""Private action actuator orchestration with deterministic reconciliation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol
from uuid import UUID

from solvan.application.action_gates import ActionPreMutationGate
from solvan.application.actions import ExecutionAuthorization
from solvan.domain import (
    ActionContractError,
    ActionPolicyError,
    AuthorizedActionMaterial,
    Scope,
    canonical_json_hash,
    freeze_json,
)
from solvan.domain.actions import FrozenJson


class ReservationConflict(RuntimeError):
    """Raised when the target changed or another action owns it."""


class ReservationLost(RuntimeError):
    """Raised when a stale reservation token attempts to heartbeat or finalize."""


class AmbiguousMutation(RuntimeError):
    """The connector request may have reached production and requires reconciliation."""

    def __init__(self, connector_request_id: str | None) -> None:
        super().__init__("connector outcome is ambiguous")
        self.connector_request_id = connector_request_id


class ExecutionResult(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    AMBIGUOUS = "AMBIGUOUS"


class DispatchPhase(StrEnum):
    PREPARED = "PREPARED"
    MUTATION_ISSUED = "MUTATION_ISSUED"
    RECONCILING = "RECONCILING"


class ReconciliationResult(StrEnum):
    EFFECT_CONFIRMED = "EFFECT_CONFIRMED"
    NO_EFFECT_CONFIRMED = "NO_EFFECT_CONFIRMED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class TargetReservation:
    reservation_id: str
    action_id: str
    target_key: str
    expected_target_epoch: int
    reservation_epoch: int
    owner_identity: str
    lease_token: UUID
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class UndoPlan:
    descriptor: Mapping[str, FrozenJson]

    @classmethod
    def from_object(cls, descriptor: dict[str, Any]) -> UndoPlan:
        return cls(freeze_json(descriptor))

    @property
    def content_hash(self) -> str:
        return canonical_json_hash(self.descriptor)


@dataclass(frozen=True, slots=True)
class ExecutionReceiptWrite:
    action_id: str
    attempt: int
    connector_request_id: str | None
    idempotency_key: str
    before_state_ref: str
    after_state_ref: str | None
    observed_target_version: str | None
    started_at: datetime
    connector_returned_at: datetime | None
    reconciled_at: datetime | None
    result: ExecutionResult
    error_class: str | None
    actor_identity: str
    trace_id: str | None


@dataclass(frozen=True, slots=True)
class TargetObservation:
    state_ref: str
    version: str

    @property
    def content_hash(self) -> str:
        return canonical_json_hash({"state_ref": self.state_ref, "version": self.version})


@dataclass(frozen=True, slots=True)
class PredictedEffect:
    descriptor: Mapping[str, FrozenJson]
    connector_revision: str

    def __post_init__(self) -> None:
        if not self.connector_revision:
            raise ActionContractError("connector revision must not be empty")

    @classmethod
    def from_object(cls, descriptor: dict[str, Any], *, connector_revision: str) -> PredictedEffect:
        return cls(freeze_json(descriptor), connector_revision)

    @property
    def content_hash(self) -> str:
        return canonical_json_hash(self.descriptor)


@dataclass(frozen=True, slots=True)
class MutationCall:
    connector_request_id: str
    returned_at: datetime


@dataclass(frozen=True, slots=True)
class Reconciliation:
    result: ReconciliationResult
    observation: TargetObservation | None
    reconciled_at: datetime


@dataclass(frozen=True, slots=True)
class ActuatorDispatch:
    dispatch_id: str
    effect_receipt_id: str
    actuator_id: str
    reservation: TargetReservation
    material: AuthorizedActionMaterial
    idempotency_key: str
    phase: DispatchPhase
    policy_hash: str
    request_hash: str
    expected_effect_hash: str
    predicted_effect_hash: str
    connector_revision: str
    before_state: TargetObservation
    customer_audit_sink_ref: str
    lease_token: UUID
    started_at: datetime
    connector_request_id: str | None
    connector_returned_at: datetime | None
    trace_id: str | None


@dataclass(frozen=True, slots=True)
class CustomerAuditRecord:
    dispatch_id: str
    action_id: str
    content: Mapping[str, FrozenJson]

    @property
    def content_hash(self) -> str:
        return canonical_json_hash(self.content)


class CustomerAuditSink(Protocol):
    def write(self, *, sink_ref: str, record: CustomerAuditRecord) -> str: ...


class ActionExecutionStore(Protocol):
    def claim_recovery(
        self,
        *,
        scope: Scope,
        action_id: str,
        actuator_id: str,
        owner_identity: str,
        ttl_ms: int,
    ) -> ActuatorDispatch | None: ...

    def acquire_reservation(
        self,
        *,
        scope: Scope,
        action_id: str,
        owner_identity: str,
        ttl_ms: int,
    ) -> TargetReservation: ...

    def authorize_for_execution(
        self, *, scope: Scope, reservation: TargetReservation
    ) -> ExecutionAuthorization: ...

    def authorize_prepared_dispatch(
        self, *, scope: Scope, dispatch: ActuatorDispatch
    ) -> ExecutionAuthorization: ...

    def heartbeat(
        self, *, scope: Scope, reservation: TargetReservation, ttl_ms: int
    ) -> datetime: ...

    def release_before_mutation(
        self, *, scope: Scope, reservation: TargetReservation, reason: str
    ) -> None: ...

    def prepare_dispatch(
        self,
        *,
        scope: Scope,
        reservation: TargetReservation,
        authority: ExecutionAuthorization,
        actuator_id: str,
        owner_identity: str,
        before_state: TargetObservation,
        prediction: PredictedEffect,
        undo_plan: UndoPlan,
        trace_id: str | None,
        ttl_ms: int,
    ) -> ActuatorDispatch: ...

    def claim_mutation(
        self, *, scope: Scope, dispatch: ActuatorDispatch, ttl_ms: int
    ) -> ActuatorDispatch: ...

    def record_connector_ack(
        self,
        *,
        scope: Scope,
        dispatch: ActuatorDispatch,
        connector_request_id: str | None,
        connector_returned_at: datetime | None,
        ttl_ms: int,
    ) -> ActuatorDispatch: ...

    def finalize_dispatch(
        self,
        *,
        scope: Scope,
        dispatch: ActuatorDispatch,
        receipt: ExecutionReceiptWrite,
        customer_audit_ref: str,
    ) -> str: ...


class MutationConnector(Protocol):
    def observe(self, material: AuthorizedActionMaterial) -> TargetObservation: ...

    def dry_run(
        self, material: AuthorizedActionMaterial, *, before_state: TargetObservation
    ) -> PredictedEffect: ...

    def derive_undo(
        self, material: AuthorizedActionMaterial, *, before_state: TargetObservation
    ) -> UndoPlan: ...

    def mutate(
        self, material: AuthorizedActionMaterial, *, idempotency_key: str
    ) -> MutationCall: ...

    def reconcile(
        self, material: AuthorizedActionMaterial, *, idempotency_key: str
    ) -> Reconciliation: ...


class Clock(Protocol):
    def now(self) -> datetime: ...


@dataclass(frozen=True, slots=True)
class ActuationResult:
    receipt_id: str
    result: ExecutionResult
    reservation_id: str


class ActionActuator:
    """Execute one stored action; connectors never choose the final result."""

    def __init__(
        self,
        *,
        store: ActionExecutionStore,
        connector: MutationConnector,
        customer_audit: CustomerAuditSink,
        clock: Clock,
        actuator_id: str,
        actor_identity: str,
        reservation_ttl_ms: int,
        pre_mutation_gate: ActionPreMutationGate,
    ) -> None:
        self._store = store
        self._connector = connector
        self._customer_audit = customer_audit
        self._clock = clock
        self._actuator_id = actuator_id
        self._actor_identity = actor_identity
        self._reservation_ttl_ms = reservation_ttl_ms
        self._pre_mutation_gate = pre_mutation_gate

    def execute(self, *, scope: Scope, action_id: str, trace_id: str | None) -> ActuationResult:
        recovery = self._store.claim_recovery(
            scope=scope,
            action_id=action_id,
            actuator_id=self._actuator_id,
            owner_identity=self._actor_identity,
            ttl_ms=self._reservation_ttl_ms,
        )
        if recovery is not None:
            if recovery.phase is DispatchPhase.PREPARED:
                authority = self._store.authorize_prepared_dispatch(scope=scope, dispatch=recovery)
                if authority.material != recovery.material:
                    raise ActionPolicyError("prepared_dispatch_material_drift")
                if authority.material.scope != scope:
                    raise ActionPolicyError("execution_scope_drift")
                self._pre_mutation_gate.check(scope=scope, authority=authority)
                return self._issue_and_reconcile(scope=scope, dispatch=recovery)
            return self._reconcile_only(scope=scope, dispatch=recovery)

        reservation = self._store.acquire_reservation(
            scope=scope,
            action_id=action_id,
            owner_identity=self._actor_identity,
            ttl_ms=self._reservation_ttl_ms,
        )
        try:
            authority = self._store.authorize_for_execution(scope=scope, reservation=reservation)
            if authority.material.scope != scope:
                raise ActionPolicyError("execution_scope_drift")
        except (ActionPolicyError, ReservationLost):
            self._store.release_before_mutation(
                scope=scope, reservation=reservation, reason="AUTHORIZATION_FAILED"
            )
            raise
        before = self._connector.observe(authority.material)
        if before.version != authority.material.expected_target_version:
            self._store.release_before_mutation(
                scope=scope, reservation=reservation, reason="PRECONDITION_FAILED"
            )
            raise ActionPolicyError("connector_target_version_changed")
        try:
            prediction = self._connector.dry_run(authority.material, before_state=before)
            effect_matches = prediction.content_hash == authority.material.expected_effect_hash
        except Exception as error:
            self._store.release_before_mutation(
                scope=scope, reservation=reservation, reason="DRY_RUN_MISMATCH"
            )
            raise ActionPolicyError("dry_run_prediction_invalid") from error
        if not effect_matches:
            self._store.release_before_mutation(
                scope=scope, reservation=reservation, reason="DRY_RUN_MISMATCH"
            )
            raise ActionPolicyError("dry_run_effect_mismatch")
        try:
            self._pre_mutation_gate.check(scope=scope, authority=authority)
        except ActionPolicyError:
            self._store.release_before_mutation(
                scope=scope, reservation=reservation, reason="AUTHORIZATION_FAILED"
            )
            raise
        undo_plan = self._connector.derive_undo(authority.material, before_state=before)
        dispatch = self._store.prepare_dispatch(
            scope=scope,
            reservation=reservation,
            authority=authority,
            actuator_id=self._actuator_id,
            owner_identity=self._actor_identity,
            before_state=before,
            prediction=prediction,
            undo_plan=undo_plan,
            trace_id=trace_id,
            ttl_ms=self._reservation_ttl_ms,
        )
        return self._issue_and_reconcile(scope=scope, dispatch=dispatch)

    def _issue_and_reconcile(self, *, scope: Scope, dispatch: ActuatorDispatch) -> ActuationResult:
        issued = self._store.claim_mutation(
            scope=scope, dispatch=dispatch, ttl_ms=self._reservation_ttl_ms
        )
        connector_request_id: str | None = None
        connector_returned_at: datetime | None = None
        error_class: str | None = None
        try:
            call = self._connector.mutate(issued.material, idempotency_key=issued.idempotency_key)
            connector_request_id = call.connector_request_id
            connector_returned_at = call.returned_at
        except AmbiguousMutation as error:
            connector_request_id = error.connector_request_id
            error_class = "AMBIGUOUS_CONNECTOR_RETURN"
        acknowledged = self._store.record_connector_ack(
            scope=scope,
            dispatch=issued,
            connector_request_id=connector_request_id,
            connector_returned_at=connector_returned_at,
            ttl_ms=self._reservation_ttl_ms,
        )
        return self._reconcile_and_finalize(
            scope=scope, dispatch=acknowledged, error_class=error_class
        )

    def _reconcile_only(self, *, scope: Scope, dispatch: ActuatorDispatch) -> ActuationResult:
        acknowledged = self._store.record_connector_ack(
            scope=scope,
            dispatch=dispatch,
            connector_request_id=dispatch.connector_request_id,
            connector_returned_at=dispatch.connector_returned_at,
            ttl_ms=self._reservation_ttl_ms,
        )
        return self._reconcile_and_finalize(
            scope=scope,
            dispatch=acknowledged,
            error_class=(
                "AMBIGUOUS_CONNECTOR_RETURN" if acknowledged.connector_request_id is None else None
            ),
        )

    def _reconcile_and_finalize(
        self,
        *,
        scope: Scope,
        dispatch: ActuatorDispatch,
        error_class: str | None,
    ) -> ActuationResult:
        reconciliation = self._connector.reconcile(
            dispatch.material, idempotency_key=dispatch.idempotency_key
        )
        result = {
            ReconciliationResult.EFFECT_CONFIRMED: ExecutionResult.SUCCEEDED,
            ReconciliationResult.NO_EFFECT_CONFIRMED: ExecutionResult.FAILED,
            ReconciliationResult.UNKNOWN: ExecutionResult.AMBIGUOUS,
        }[reconciliation.result]
        if result is ExecutionResult.AMBIGUOUS:
            error_class = error_class or "RECONCILIATION_INCONCLUSIVE"
        receipt = ExecutionReceiptWrite(
            action_id=dispatch.material.action_id,
            attempt=1,
            connector_request_id=dispatch.connector_request_id,
            idempotency_key=dispatch.idempotency_key,
            before_state_ref=dispatch.before_state.state_ref,
            after_state_ref=(
                None if reconciliation.observation is None else reconciliation.observation.state_ref
            ),
            observed_target_version=(
                None if reconciliation.observation is None else reconciliation.observation.version
            ),
            started_at=dispatch.started_at,
            connector_returned_at=dispatch.connector_returned_at,
            reconciled_at=reconciliation.reconciled_at,
            result=result,
            error_class=error_class,
            actor_identity=self._actor_identity,
            trace_id=dispatch.trace_id,
        )
        audit_record = self._audit_record(dispatch=dispatch, receipt=receipt)
        customer_audit_ref = self._customer_audit.write(
            sink_ref=dispatch.customer_audit_sink_ref, record=audit_record
        )
        receipt_id = self._store.finalize_dispatch(
            scope=scope,
            dispatch=dispatch,
            receipt=receipt,
            customer_audit_ref=customer_audit_ref,
        )
        return ActuationResult(receipt_id, result, dispatch.reservation.reservation_id)

    @staticmethod
    def _audit_record(
        *, dispatch: ActuatorDispatch, receipt: ExecutionReceiptWrite
    ) -> CustomerAuditRecord:
        content = freeze_json(
            {
                "action_id": receipt.action_id,
                "actor_identity": receipt.actor_identity,
                "after_state_ref": receipt.after_state_ref,
                "before_state_ref": receipt.before_state_ref,
                "connector_request_id": receipt.connector_request_id,
                "dispatch_id": dispatch.dispatch_id,
                "error_class": receipt.error_class,
                "expected_effect_hash": dispatch.expected_effect_hash,
                "idempotency_key": receipt.idempotency_key,
                "observed_target_version": receipt.observed_target_version,
                "policy_hash": dispatch.policy_hash,
                "predicted_effect_hash": dispatch.predicted_effect_hash,
                "reconciled_at": (
                    receipt.reconciled_at.isoformat() if receipt.reconciled_at else None
                ),
                "request_hash": dispatch.request_hash,
                "result": receipt.result.value,
                "schema_version": 1,
                "started_at": receipt.started_at.isoformat(),
                "trace_id": receipt.trace_id,
            }
        )
        return CustomerAuditRecord(dispatch.dispatch_id, receipt.action_id, content)
