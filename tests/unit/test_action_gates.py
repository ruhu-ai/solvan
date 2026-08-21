from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from solvan.application.action_gates import (
    CompositeActionPreMutationGate,
    GraphActionBinding,
)
from solvan.application.actions import StandingAuthority
from solvan.domain import (
    ActionPolicyError,
    ExecutionAuthoritySnapshot,
    PreauthorizationContext,
    PreauthorizationStatus,
    RiskClass,
    Scope,
    StandingPreauthorization,
)
from solvan.persistence.earned_autonomy import EarnedAutonomyOperands
from solvan.persistence.production_graph import CurrentGraphProjection
from solvan.persistence.target_action_gates import (
    PostgresEarnedAutonomyActionGate,
    PostgresGraphActionBindingResolver,
    ProductionGraphActionGate,
)
from tests.unit.test_action_authorization import authority

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)


def _projection(**overrides: object) -> CurrentGraphProjection:
    values: dict[str, object] = {
        "snapshot_id": "pgs-current",
        "snapshot_version": 4,
        "reconciled_at": datetime(2026, 8, 12, 9, 0, tzinfo=UTC),
        "age_seconds": 30,
        "completeness": "COMPLETE",
        "autonomy_eligible": True,
        "assisted_usable": True,
        "cell_id": "cell-eu",
        "placement_epoch": 7,
        "graph_policy_binding_epoch": 3,
    }
    values.update(overrides)
    return CurrentGraphProjection(**values)  # type: ignore[arg-type]


def _standing() -> StandingAuthority:
    approved = authority()
    now = datetime(2026, 8, 12, 9, 0, tzinfo=UTC)
    standing = StandingPreauthorization(
        preauthorization_id="preauth-1",
        version=1,
        status=PreauthorizationStatus.APPROVED,
        action_type=approved.material.action_type,
        service_id="payments",
        incident_class="connection-exhaustion",
        maximum_risk_class=RiskClass.MEDIUM,
        payload_constraints=approved.material.payload,
        maximum_attempts=1,
        cooldown_ms=600_000,
        valid_from=now,
        valid_until=datetime(2026, 8, 13, 9, 0, tzinfo=UTC),
    )
    return StandingAuthority(
        material=approved.material,
        authority=standing,
        context=PreauthorizationContext(
            service_id="payments",
            incident_class="connection-exhaustion",
            action_attempt_count=0,
            cooldown_until=None,
            now=now,
        ),
        execution=ExecutionAuthoritySnapshot(
            now=now,
            workflow_version=approved.material.workflow_version,
            evidence_version=approved.material.evidence_version,
            target_version=approved.material.expected_target_version,
            target_epoch=approved.material.expected_target_epoch,
            reservation_expected_target_epoch=approved.material.expected_target_epoch,
            reservation_epoch=approved.material.expected_target_epoch + 1,
            policy_version=approved.material.policy_version,
            approver_role_active=False,
            reservation_action_id=approved.material.action_id,
        ),
        idempotency_key="action-idempotency-1",
    )


def test_graph_gate_accepts_only_exact_current_eligible_binding() -> None:
    gate = ProductionGraphActionGate(
        read_current=lambda _scope: _projection(),
        resolve_binding=lambda _scope, _material: GraphActionBinding("pgs-current", "cell-eu", 7),
    )

    gate.check(scope=SCOPE, authority=_standing())


@pytest.mark.parametrize(
    "projection, binding, error",
    [
        (
            _projection(autonomy_eligible=False),
            GraphActionBinding("pgs-current", "cell-eu", 7),
            "graph_not_autonomy_eligible",
        ),
        (_projection(), GraphActionBinding("pgs-old", "cell-eu", 7), "graph_snapshot_changed"),
        (
            _projection(),
            GraphActionBinding("pgs-current", "cell-other", 7),
            "graph_placement_changed",
        ),
        (_projection(), GraphActionBinding("pgs-current", "cell-eu", 8), "graph_placement_changed"),
    ],
)
def test_graph_gate_refuses_stale_or_mismatched_authority(
    projection: CurrentGraphProjection,
    binding: GraphActionBinding,
    error: str,
) -> None:
    gate = ProductionGraphActionGate(
        read_current=lambda _scope: projection,
        resolve_binding=lambda _scope, _material: binding,
    )

    with pytest.raises(ActionPolicyError, match=error):
        gate.check(scope=SCOPE, authority=_standing())


def test_graph_gate_is_not_required_for_human_approved_actions() -> None:
    approved = authority()
    gate = ProductionGraphActionGate(
        read_current=lambda _scope: (_ for _ in ()).throw(AssertionError("must not read")),
        resolve_binding=lambda _scope, _material: (_ for _ in ()).throw(
            AssertionError("must not resolve")
        ),
    )

    gate.check(scope=SCOPE, authority=approved)


def test_graph_gate_converts_target_read_failure_to_policy_refusal() -> None:
    gate = ProductionGraphActionGate(
        read_current=lambda _scope: (_ for _ in ()).throw(RuntimeError("target unavailable")),
        resolve_binding=lambda _scope, _material: GraphActionBinding("pgs-current", "cell-eu", 7),
    )

    with pytest.raises(ActionPolicyError, match="graph_precondition_unavailable"):
        gate.check(scope=SCOPE, authority=_standing())


def test_composite_gate_preserves_order_and_fail_closed_behavior() -> None:
    calls: list[str] = []

    class Gate:
        def __init__(self, name: str, error: bool = False) -> None:
            self.name = name
            self.error = error

        def check(self, **_kwargs: object) -> None:
            calls.append(self.name)
            if self.error:
                raise ActionPolicyError("gate refused")

    composite = CompositeActionPreMutationGate(
        (Gate("graph"), Gate("quality", True), Gate("never"))
    )

    with pytest.raises(ActionPolicyError, match="gate refused"):
        composite.check(scope=SCOPE, authority=_standing())
    assert calls == ["graph", "quality"]


class _GateResult:
    def __init__(self, row: tuple[object, ...] | None = None) -> None:
        self._row = row

    def fetchone(self) -> tuple[object, ...] | None:
        return self._row


class _GateConnection:
    def __init__(self, row: tuple[object, ...]) -> None:
        self.row = row
        self.statements: list[str] = []

    def __enter__(self) -> _GateConnection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def transaction(self):  # type: ignore[no-untyped-def]
        return nullcontext()

    def execute(self, statement: str, _params: object = None) -> _GateResult:
        self.statements.append(statement)
        if "FROM solvan_quality.earned_action_reservations" in statement:
            return _GateResult(self.row)
        return _GateResult()


def _existing_reservation_row() -> tuple[object, ...]:
    standing = _standing()
    return (
        "cell-eu",
        7,
        "ear_00000000000000000000000000",
        standing.material.action_type.value,
        standing.material.target_key,
        standing.authority.preauthorization_id,
        standing.authority.version,
        "cmp_00000000000000000000000000",
        "CONNECTOR_CALL",
        4,
        "cap_receipt",
        UUID("11111111-1111-4111-8111-111111111111"),
        datetime.now(UTC) + timedelta(minutes=2),
    )


def test_earned_gate_sets_serializable_before_loading_and_reuses_exact_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _GateConnection(_existing_reservation_row())
    calls: list[tuple[object, EarnedAutonomyOperands]] = []

    def reserve(bound_connection: object, *, operands: EarnedAutonomyOperands) -> None:
        calls.append((bound_connection, operands))

    monkeypatch.setattr(
        "solvan.persistence.target_action_gates.reserve_earned_action_in_transaction", reserve
    )
    gate = PostgresEarnedAutonomyActionGate(
        connect=lambda: connection,  # type: ignore[arg-type,return-value]
    )

    gate.check(scope=SCOPE, authority=_standing())

    assert connection.statements[0] == "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"
    assert calls and calls[0][0] is connection
    assert calls[0][1].reservation_id == _existing_reservation_row()[2]


def test_earned_gate_converts_target_refusal_to_action_policy_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _GateConnection(_existing_reservation_row())

    def reserve(_connection: object, *, operands: object) -> None:
        del operands
        raise RuntimeError("target function refused")

    monkeypatch.setattr(
        "solvan.persistence.target_action_gates.reserve_earned_action_in_transaction", reserve
    )
    gate = PostgresEarnedAutonomyActionGate(
        connect=lambda: connection,  # type: ignore[arg-type,return-value]
    )

    with pytest.raises(ActionPolicyError, match="earned_autonomy_precondition_failed"):
        gate.check(scope=SCOPE, authority=_standing())


def test_postgres_binding_resolver_reads_owner_and_current_placement() -> None:
    class Result:
        def fetchone(self) -> tuple[str, str, int]:
            return ("pgs-current", "cell-eu", 7)

    class Connection:
        def __init__(self) -> None:
            self.params: dict[str, object] | None = None
            self.statement = ""

        def execute(self, statement: str, params: dict[str, object]) -> Result:
            self.statement = statement
            self.params = params
            return Result()

    connection = Connection()
    binding = PostgresGraphActionBindingResolver(connection)(SCOPE, _standing().material)  # type: ignore[arg-type]

    assert binding == GraphActionBinding("pgs-current", "cell-eu", 7)
    assert connection.params is not None
    assert connection.params["action_id"] == _standing().material.action_id
    assert "owner_entity_id" not in connection.params
    assert "FROM solvan_graph.graph_scope_bindings" in connection.statement


def test_postgres_binding_resolver_refuses_missing_snapshot() -> None:
    class Result:
        def fetchone(self) -> None:
            return None

    class Connection:
        def execute(self, _statement: str, _params: dict[str, object]) -> Result:
            return Result()

    with pytest.raises(ActionPolicyError, match="graph_action_binding_missing"):
        PostgresGraphActionBindingResolver(Connection())(SCOPE, _standing().material)  # type: ignore[arg-type]
