from datetime import UTC, datetime, timedelta

import pytest

from solvan.domain import (
    ActionPolicyError,
    ActionType,
    PreauthorizationContext,
    PreauthorizationStatus,
    RiskClass,
    StandingPreauthorization,
    freeze_json,
    validate_standing_preauthorization,
)
from tests.unit.test_actions import action

NOW = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)
PAYLOAD = freeze_json({"admin_operation": "RECYCLE_DB_POOL", "drain_timeout_ms": 5000})


def authority(**overrides: object) -> StandingPreauthorization:
    values: dict[str, object] = {
        "preauthorization_id": "payments-pool-recycle-v1",
        "version": 1,
        "status": PreauthorizationStatus.APPROVED,
        "action_type": ActionType.PAYMENTS_POOL_RECYCLE,
        "service_id": "payments-api",
        "incident_class": "connection_exhaustion",
        "maximum_risk_class": RiskClass.MEDIUM,
        "payload_constraints": PAYLOAD,
        "maximum_attempts": 1,
        "cooldown_ms": 600_000,
        "valid_from": NOW - timedelta(days=1),
        "valid_until": NOW + timedelta(days=1),
    }
    values.update(overrides)
    return StandingPreauthorization(**values)  # type: ignore[arg-type]


def context(**overrides: object) -> PreauthorizationContext:
    values: dict[str, object] = {
        "service_id": "payments-api",
        "incident_class": "connection_exhaustion",
        "action_attempt_count": 0,
        "cooldown_until": None,
        "now": NOW,
    }
    values.update(overrides)
    return PreauthorizationContext(**values)  # type: ignore[arg-type]


def pool_action(**overrides: object):  # type: ignore[no-untyped-def]
    values: dict[str, object] = {
        "action_type": ActionType.PAYMENTS_POOL_RECYCLE,
        "risk_class": RiskClass.MEDIUM,
        "payload": PAYLOAD,
    }
    values.update(overrides)
    return action(**values)


def test_exact_standing_authority_allows_one_bounded_pool_recycle() -> None:
    validate_standing_preauthorization(
        material=pool_action(), authority=authority(), context=context()
    )


@pytest.mark.parametrize(
    ("material", "grant", "execution", "reason"),
    [
        (
            pool_action(),
            authority(status=PreauthorizationStatus.REVOKED),
            context(),
            "not_approved",
        ),
        (action(), authority(), context(), "action_mismatch"),
        (pool_action(risk_class=RiskClass.HIGH), authority(), context(), "risk_exceeded"),
        (pool_action(), authority(), context(service_id="checkout-api"), "service_mismatch"),
        (
            pool_action(
                payload=freeze_json(
                    {"admin_operation": "RECYCLE_DB_POOL", "drain_timeout_ms": 4000}
                )
            ),
            authority(),
            context(),
            "payload_mismatch",
        ),
        (pool_action(), authority(), context(action_attempt_count=1), "attempts_exhausted"),
        (
            pool_action(),
            authority(),
            context(cooldown_until=NOW + timedelta(seconds=1)),
            "cooldown_active",
        ),
        (
            pool_action(),
            authority(),
            context(now=NOW + timedelta(days=2)),
            "outside_validity",
        ),
    ],
)
def test_standing_authority_fails_closed_on_every_mismatch(
    material: object,
    grant: StandingPreauthorization,
    execution: PreauthorizationContext,
    reason: str,
) -> None:
    with pytest.raises(ActionPolicyError, match=reason):
        validate_standing_preauthorization(
            material=material,  # type: ignore[arg-type]
            authority=grant,
            context=execution,
        )
