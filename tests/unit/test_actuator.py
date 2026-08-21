from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from solvan.application import ActionActuator
from solvan.application.actuator import (
    ActuatorDispatch,
    AmbiguousMutation,
    CustomerAuditRecord,
    DispatchPhase,
    ExecutionReceiptWrite,
    ExecutionResult,
    MutationCall,
    PredictedEffect,
    Reconciliation,
    ReconciliationResult,
    TargetObservation,
    TargetReservation,
    UndoPlan,
)
from solvan.domain import ActionPolicyError
from tests.unit.test_action_authorization import authority

NOW = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)


class FakeClock:
    def now(self) -> datetime:
        return NOW


class FakeStore:
    def __init__(self, *, reject_authority: bool = False) -> None:
        self.reservation = TargetReservation(
            reservation_id="rsv_00000000000000000000000000",
            action_id=authority().material.action_id,
            target_key=authority().material.target_key,
            expected_target_epoch=authority().material.expected_target_epoch,
            reservation_epoch=authority().material.expected_target_epoch + 1,
            owner_identity="spiffe://solvan/actuator",
            lease_token=UUID("00000000-0000-0000-0000-000000000001"),
            expires_at=NOW + timedelta(minutes=1),
        )
        self.reject_authority = reject_authority
        self.heartbeats = 0
        self.release_reason: str | None = None
        self.receipt: ExecutionReceiptWrite | None = None
        self.dispatch: ActuatorDispatch | None = None

    def claim_recovery(self, **_kwargs: object) -> ActuatorDispatch | None:
        return None

    def acquire_reservation(self, **_kwargs: object) -> TargetReservation:
        return self.reservation

    def authorize_for_execution(self, **_kwargs: object):  # type: ignore[no-untyped-def]
        if self.reject_authority:
            raise ActionPolicyError("approval_expired")
        return authority()

    def authorize_prepared_dispatch(self, **_kwargs: object):  # type: ignore[no-untyped-def]
        return authority()

    def heartbeat(self, **_kwargs: object) -> datetime:
        self.heartbeats += 1
        return self.reservation.expires_at

    def release_before_mutation(self, *, reason: str, **_kwargs: object) -> None:
        self.release_reason = reason

    def prepare_dispatch(self, **kwargs: object) -> ActuatorDispatch:
        before_state = kwargs["before_state"]
        assert isinstance(before_state, TargetObservation)
        prepared = ActuatorDispatch(
            dispatch_id="dsp_00000000000000000000000000",
            effect_receipt_id="aef_00000000000000000000000000",
            actuator_id="atr_00000000000000000000000000",
            reservation=self.reservation,
            material=authority().material,
            idempotency_key="action-idempotency-1",
            phase=DispatchPhase.PREPARED,
            policy_hash="sha256:" + "1" * 64,
            request_hash="sha256:" + "2" * 64,
            expected_effect_hash=authority().material.expected_effect_hash,
            predicted_effect_hash=authority().material.expected_effect_hash,
            connector_revision="fake-connector.v1",
            before_state=before_state,
            customer_audit_sink_ref="projects/solvan-test/logs/solvan",
            lease_token=UUID("00000000-0000-0000-0000-000000000002"),
            started_at=NOW,
            connector_request_id=None,
            connector_returned_at=None,
            trace_id=kwargs["trace_id"] if isinstance(kwargs["trace_id"], str) else None,
        )
        self.dispatch = prepared
        return prepared

    def claim_mutation(self, *, dispatch: ActuatorDispatch, **_kwargs: object) -> ActuatorDispatch:
        self.dispatch = replace(dispatch, phase=DispatchPhase.MUTATION_ISSUED)
        return self.dispatch

    def record_connector_ack(
        self,
        *,
        dispatch: ActuatorDispatch,
        connector_request_id: str | None,
        connector_returned_at: datetime | None,
        **_kwargs: object,
    ) -> ActuatorDispatch:
        self.dispatch = replace(
            dispatch,
            phase=DispatchPhase.RECONCILING,
            connector_request_id=connector_request_id,
            connector_returned_at=connector_returned_at,
        )
        return self.dispatch

    def finalize_dispatch(self, *, receipt: ExecutionReceiptWrite, **_kwargs: object) -> str:
        self.receipt = receipt
        return "rcp_00000000000000000000000000"


class FakePreMutationGate:
    def __init__(self, *, error: ActionPolicyError | None = None) -> None:
        self.error = error
        self.calls = 0

    def check(self, **_kwargs: object) -> None:
        self.calls += 1
        if self.error is not None:
            raise self.error


class FakeAudit:
    def __init__(self) -> None:
        self.records: list[CustomerAuditRecord] = []

    def write(self, *, sink_ref: str, record: CustomerAuditRecord) -> str:
        assert sink_ref == "projects/solvan-test/logs/solvan"
        self.records.append(record)
        return "projects/solvan-test/logs/solvan#receipt"


class FailOnceAudit(FakeAudit):
    def __init__(self) -> None:
        super().__init__()
        self.attempts = 0

    def write(self, *, sink_ref: str, record: CustomerAuditRecord) -> str:
        self.attempts += 1
        if self.attempts == 1:
            raise RuntimeError("customer audit unavailable")
        return super().write(sink_ref=sink_ref, record=record)


class FakeConnector:
    def __init__(
        self,
        *,
        before_version: str = "revision-v2",
        reconciliation_result: ReconciliationResult = ReconciliationResult.EFFECT_CONFIRMED,
        ambiguous_call: bool = False,
        prediction_matches: bool = True,
        dry_run_error: Exception | None = None,
    ) -> None:
        self.before_version = before_version
        self.reconciliation_result = reconciliation_result
        self.ambiguous_call = ambiguous_call
        self.prediction_matches = prediction_matches
        self.dry_run_error = dry_run_error
        self.mutated = False
        self.idempotency_keys: list[str] = []
        self.calls: list[str] = []

    def observe(self, _material: object) -> TargetObservation:
        self.calls.append("observe")
        return TargetObservation("gs://state/before", self.before_version)

    def dry_run(self, material, *, before_state: TargetObservation) -> PredictedEffect:  # type: ignore[no-untyped-def]
        self.calls.append("dry_run")
        if self.dry_run_error is not None:
            raise self.dry_run_error
        if self.prediction_matches:
            return PredictedEffect(material.expected_effect, "fake-connector.v1")
        return PredictedEffect.from_object(
            {
                "profile": "hostile-weaker-profile.v1",
                "schema_version": 1,
                "target_key": material.target_key,
            },
            connector_revision="fake-connector.v1",
        )

    def derive_undo(self, material, *, before_state: TargetObservation) -> UndoPlan:  # type: ignore[no-untyped-def]
        self.calls.append("derive_undo")
        return UndoPlan.from_object(
            {
                "before_state_ref": before_state.state_ref,
                "profile": "fake-undo.v1",
                "target_key": material.target_key,
            }
        )

    def mutate(self, _material: object, *, idempotency_key: str) -> MutationCall:
        self.calls.append("mutate")
        self.mutated = True
        self.idempotency_keys.append(idempotency_key)
        if self.ambiguous_call:
            raise AmbiguousMutation("connector-request-1")
        return MutationCall("connector-request-1", NOW)

    def reconcile(self, _material: object, *, idempotency_key: str) -> Reconciliation:
        self.calls.append("reconcile")
        self.idempotency_keys.append(idempotency_key)
        observation = (
            None
            if self.reconciliation_result is ReconciliationResult.UNKNOWN
            else TargetObservation("gs://state/after", "revision-v1")
        )
        return Reconciliation(self.reconciliation_result, observation, NOW)


def actuator(
    store: FakeStore,
    connector: FakeConnector,
    *,
    pre_mutation_gate: FakePreMutationGate | None = None,
) -> ActionActuator:
    return ActionActuator(
        store=store,
        connector=connector,
        customer_audit=FakeAudit(),
        clock=FakeClock(),
        actuator_id="atr_00000000000000000000000000",
        actor_identity="spiffe://solvan/actuator",
        reservation_ttl_ms=30_000,
        pre_mutation_gate=pre_mutation_gate or FakePreMutationGate(),
    )


def test_exact_dry_run_match_is_required_before_mutation() -> None:
    store = FakeStore()
    connector = FakeConnector()
    result = actuator(store, connector).execute(
        scope=authority().material.scope,
        action_id=authority().material.action_id,
        trace_id="trace-1",
    )

    assert result.result is ExecutionResult.SUCCEEDED
    assert store.receipt is not None
    assert store.receipt.observed_target_version == "revision-v1"
    assert store.heartbeats == 0
    assert connector.idempotency_keys == ["action-idempotency-1", "action-idempotency-1"]
    assert connector.calls == [
        "observe",
        "dry_run",
        "derive_undo",
        "mutate",
        "reconcile",
    ]


def test_customer_audit_retry_reconciles_without_repeating_mutation() -> None:
    class RecoveryStore(FakeStore):
        recover = False

        def claim_recovery(self, **_kwargs: object) -> ActuatorDispatch | None:
            return self.dispatch if self.recover else None

    store = RecoveryStore()
    connector = FakeConnector()
    audit = FailOnceAudit()
    service = ActionActuator(
        store=store,
        connector=connector,
        customer_audit=audit,
        clock=FakeClock(),
        actuator_id="atr_00000000000000000000000000",
        actor_identity="spiffe://solvan/actuator",
        reservation_ttl_ms=30_000,
        pre_mutation_gate=FakePreMutationGate(),
    )
    with pytest.raises(RuntimeError, match="customer audit unavailable"):
        service.execute(
            scope=authority().material.scope,
            action_id=authority().material.action_id,
            trace_id="trace-audit-retry",
        )
    assert connector.calls.count("mutate") == 1
    assert store.dispatch is not None
    assert store.dispatch.phase is DispatchPhase.RECONCILING

    store.recover = True
    result = service.execute(
        scope=authority().material.scope,
        action_id=authority().material.action_id,
        trace_id="trace-audit-retry",
    )
    assert result.result is ExecutionResult.SUCCEEDED
    assert connector.calls.count("mutate") == 1
    assert connector.calls.count("reconcile") == 2
    assert audit.attempts == 2


def test_dry_run_mismatch_is_refused_and_never_mutates() -> None:
    store = FakeStore()
    connector = FakeConnector(prediction_matches=False)

    with pytest.raises(ActionPolicyError, match="dry_run_effect_mismatch"):
        actuator(store, connector).execute(
            scope=authority().material.scope,
            action_id=authority().material.action_id,
            trace_id=None,
        )

    assert store.release_reason == "DRY_RUN_MISMATCH"
    assert store.receipt is None
    assert connector.mutated is False
    assert connector.calls == ["observe", "dry_run"]


def test_invalid_dry_run_prediction_is_refused_and_never_mutates() -> None:
    store = FakeStore()
    connector = FakeConnector(dry_run_error=ValueError("untrusted prediction"))

    with pytest.raises(ActionPolicyError, match="dry_run_prediction_invalid"):
        actuator(store, connector).execute(
            scope=authority().material.scope,
            action_id=authority().material.action_id,
            trace_id=None,
        )

    assert store.release_reason == "DRY_RUN_MISMATCH"
    assert store.receipt is None
    assert connector.mutated is False


def test_timeout_and_unknown_reconciliation_remain_ambiguous() -> None:
    store = FakeStore()
    connector = FakeConnector(
        ambiguous_call=True, reconciliation_result=ReconciliationResult.UNKNOWN
    )
    result = actuator(store, connector).execute(
        scope=authority().material.scope,
        action_id=authority().material.action_id,
        trace_id=None,
    )

    assert result.result is ExecutionResult.AMBIGUOUS
    assert store.receipt is not None
    assert store.receipt.error_class == "AMBIGUOUS_CONNECTOR_RETURN"


def test_changed_connector_target_releases_without_mutation() -> None:
    store = FakeStore()
    connector = FakeConnector(before_version="revision-v3")
    with pytest.raises(ActionPolicyError, match="connector_target_version_changed"):
        actuator(store, connector).execute(
            scope=authority().material.scope,
            action_id=authority().material.action_id,
            trace_id=None,
        )

    assert store.release_reason == "PRECONDITION_FAILED"
    assert connector.mutated is False


def test_failed_authorization_releases_without_mutation() -> None:
    store = FakeStore(reject_authority=True)
    connector = FakeConnector()
    with pytest.raises(ActionPolicyError, match="approval_expired"):
        actuator(store, connector).execute(
            scope=authority().material.scope,
            action_id=authority().material.action_id,
            trace_id=None,
        )

    assert store.release_reason == "AUTHORIZATION_FAILED"
    assert connector.mutated is False


def test_pre_mutation_gate_runs_after_dry_run_before_dispatch() -> None:
    store = FakeStore()
    connector = FakeConnector()
    gate = FakePreMutationGate()

    result = actuator(store, connector, pre_mutation_gate=gate).execute(
        scope=authority().material.scope,
        action_id=authority().material.action_id,
        trace_id=None,
    )

    assert result.result is ExecutionResult.SUCCEEDED
    assert gate.calls == 1
    assert connector.calls[:3] == ["observe", "dry_run", "derive_undo"]


def test_pre_mutation_gate_refusal_releases_and_never_mutates() -> None:
    store = FakeStore()
    connector = FakeConnector()
    gate = FakePreMutationGate(error=ActionPolicyError("earned_autonomy_precondition_failed"))

    with pytest.raises(ActionPolicyError, match="earned_autonomy_precondition_failed"):
        actuator(store, connector, pre_mutation_gate=gate).execute(
            scope=authority().material.scope,
            action_id=authority().material.action_id,
            trace_id=None,
        )

    assert gate.calls == 1
    assert store.release_reason == "AUTHORIZATION_FAILED"
    assert connector.mutated is False
    assert connector.calls == ["observe", "dry_run"]


def test_prepared_recovery_revalidates_gate_before_mutation() -> None:
    class PreparedRecoveryStore(FakeStore):
        def claim_recovery(self, **_kwargs: object) -> ActuatorDispatch | None:
            return self.dispatch

        def authorize_prepared_dispatch(self, **_kwargs: object):  # type: ignore[no-untyped-def]
            return authority()

    store = PreparedRecoveryStore()
    store.prepare_dispatch(
        before_state=TargetObservation("gs://state/before", "revision-v2"), trace_id=None
    )
    connector = FakeConnector()
    gate = FakePreMutationGate(error=ActionPolicyError("earned_autonomy_precondition_failed"))

    with pytest.raises(ActionPolicyError, match="earned_autonomy_precondition_failed"):
        actuator(store, connector, pre_mutation_gate=gate).execute(
            scope=authority().material.scope,
            action_id=authority().material.action_id,
            trace_id=None,
        )

    assert gate.calls == 1
    assert connector.calls == []
    assert store.dispatch is not None
    assert store.dispatch.phase is DispatchPhase.PREPARED


def test_authority_scope_drift_releases_before_any_connector_read() -> None:
    class ScopeDriftStore(FakeStore):
        def authorize_for_execution(self, **_kwargs: object):  # type: ignore[no-untyped-def]
            approved = authority()
            return replace(
                approved,
                material=replace(
                    approved.material,
                    scope=replace(
                        approved.material.scope,
                        environment_id="env_00000000000000000000000001",
                    ),
                ),
            )

    store = ScopeDriftStore()
    connector = FakeConnector()

    with pytest.raises(ActionPolicyError, match="execution_scope_drift"):
        actuator(store, connector).execute(
            scope=authority().material.scope,
            action_id=authority().material.action_id,
            trace_id=None,
        )

    assert store.release_reason == "AUTHORIZATION_FAILED"
    assert connector.calls == []
