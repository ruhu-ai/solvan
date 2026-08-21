from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from solvan.domain import (
    ActionType,
    AuthorizedActionMaterial,
    PreauthorizationStatus,
    RiskClass,
    Scope,
    StandingPreauthorization,
    derive_expected_effect,
    freeze_json,
)
from solvan.persistence.earned_autonomy import EarnedAutonomyOperands, reserve_earned_action


class _Result:
    def __init__(self, row=None):
        self._row = row

    def fetchone(self):
        return self._row


class _Connection:
    def __init__(self, row):
        self.calls = []
        self._row = row

    def execute(self, statement, params=None):
        self.calls.append((statement, params))
        if "FROM solvan_quality.earned_action_reservations" in statement:
            return _Result(self._row)
        return _Result()


def _operands() -> EarnedAutonomyOperands:
    now = datetime.now(UTC)
    payload = freeze_json({"admin_operation": "RECYCLE_DB_POOL", "drain_timeout_ms": 1000})
    expected = derive_expected_effect(
        action_type=ActionType.PAYMENTS_POOL_RECYCLE,
        target_key="payments/pool",
        expected_target_version="1",
        payload=payload,
    )
    material = AuthorizedActionMaterial(
        action_id="act_earned",
        scope=Scope(
            "org_00000000000000000000000000",
            "prj_00000000000000000000000000",
            "env_00000000000000000000000000",
        ),
        owner_entity_id="INC-1",
        workflow_version=1,
        evidence_version=1,
        action_type=ActionType.PAYMENTS_POOL_RECYCLE,
        target_key="payments/pool",
        expected_target_version="1",
        expected_target_epoch=1,
        payload=payload,
        expected_effect=expected.descriptor,
        expected_effect_hash=expected.content_hash,
        risk_class=RiskClass.MEDIUM,
        reversible=True,
        rollback_plan=freeze_json({"kind": "automatic-recreate"}),
        policy_version="policy-1",
        verification_profile_id="payments-recovery",
        verification_profile_version=1,
        expires_at=now + timedelta(minutes=5),
    )
    standing = StandingPreauthorization(
        preauthorization_id="preauth-1",
        version=1,
        status=PreauthorizationStatus.APPROVED,
        action_type=ActionType.PAYMENTS_POOL_RECYCLE,
        service_id="payments",
        incident_class="connection-exhaustion",
        maximum_risk_class=RiskClass.MEDIUM,
        payload_constraints=material.payload,
        maximum_attempts=1,
        cooldown_ms=600_000,
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(hours=1),
    )
    return EarnedAutonomyOperands(
        material=material,
        standing_authority=standing,
        cell_id="cell_eu_1",
        placement_epoch=7,
        reservation_id="ear_1",
        competence_receipt_id="cmp_1",
        capacity_resource_kind="CONNECTOR_CALL",
        capacity_binding_epoch=4,
        capacity_receipt_id="cap_1",
        lease_token=UUID("11111111-1111-4111-8111-111111111111"),
        expires_at=now + timedelta(minutes=2),
    )


def test_reservation_sets_serializable_before_any_authority_read() -> None:
    operands = _operands()
    row = (
        operands.reservation_id,
        operands.material.action_id,
        operands.material.action_type.value,
        operands.material.target_key,
        "pgs_1",
        operands.competence_receipt_id,
        17,
        operands.lease_token,
        operands.expires_at,
    )
    connection = _Connection(row)

    receipt = reserve_earned_action(connection, operands=operands)  # type: ignore[arg-type]

    assert connection.calls[0][0] == "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"
    assert "quality_reserve_earned_action" in connection.calls[1][0]
    assert connection.calls[1][1]["action_id"] == operands.material.action_id
    assert connection.calls[1][1]["target_key"] == operands.material.target_key
    assert receipt.falsification_sequence_high_water == 17
