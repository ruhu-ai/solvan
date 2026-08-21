from datetime import UTC, datetime

import httpx
import pytest

from solvan.application.actuator import (
    AmbiguousMutation,
    ReconciliationResult,
    TargetObservation,
)
from solvan.connectors.mutation.payments_admin import (
    ConnectorContractError,
    PaymentsAdminConnector,
)
from solvan.domain import ActionType, RiskClass, freeze_json
from tests.unit.test_actions import action


class TokenProvider:
    def token(self, *, audience: str) -> str:
        assert audience == "https://payments.internal"
        return "fixture-token"


def pool_action():  # type: ignore[no-untyped-def]
    return action(
        action_type=ActionType.PAYMENTS_POOL_RECYCLE,
        risk_class=RiskClass.MEDIUM,
        expected_target_version="pool-generation-7",
        payload=freeze_json({"admin_operation": "RECYCLE_DB_POOL", "drain_timeout_ms": 5000}),
    )


def connector(handler: httpx.MockTransport) -> PaymentsAdminConnector:
    return PaymentsAdminConnector(
        base_url="https://payments.internal",
        token_provider=TokenProvider(),
        client=httpx.Client(transport=handler),
    )


def test_typed_pool_recycle_observes_mutates_and_reconciles() -> None:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/v1/admin/connection-pool":
            return httpx.Response(
                200,
                json={"pool_generation": "pool-generation-7", "state_ref": "gs://before"},
            )
        if request.url.path.endswith(":recycle"):
            return httpx.Response(
                200,
                json={
                    "request_id": "request-1",
                    "returned_at": "2026-08-09T12:00:00Z",
                },
            )
        return httpx.Response(
            200,
            json={
                "result": "EFFECT_CONFIRMED",
                "state_ref": "gs://after",
                "pool_generation": "pool-generation-8",
                "reconciled_at": "2026-08-09T12:00:01Z",
            },
        )

    value = connector(httpx.MockTransport(handle))
    material = pool_action()
    before = value.observe(material)
    request_count_before_dry_run = len(requests)
    prediction = value.dry_run(material, before_state=before)
    assert len(requests) == request_count_before_dry_run
    assert prediction.content_hash == material.expected_effect_hash
    call = value.mutate(pool_action(), idempotency_key="idem-1")
    reconciliation = value.reconcile(pool_action(), idempotency_key="idem-1")

    assert call.returned_at == datetime(2026, 8, 9, 12, 0, tzinfo=UTC)
    assert reconciliation.result is ReconciliationResult.EFFECT_CONFIRMED
    assert requests[1].headers["idempotency-key"] == "idem-1"
    assert requests[1].headers["authorization"] == "Bearer fixture-token"


def test_timeout_is_ambiguous_and_requires_reconciliation() -> None:
    def timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("fixture timeout")

    with pytest.raises(AmbiguousMutation):
        connector(httpx.MockTransport(timeout)).mutate(
            pool_action(), idempotency_key="idem-timeout"
        )


def test_wrong_action_type_and_unknown_response_fields_fail_closed() -> None:
    value = connector(
        httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json={
                    "pool_generation": "pool-generation-7",
                    "state_ref": "gs://before",
                    "unexpected": True,
                },
            )
        )
    )
    with pytest.raises(ConnectorContractError, match="unsupported"):
        value.observe(action())
    with pytest.raises(ValueError, match="validation error"):
        value.observe(pool_action())


def test_payments_dry_run_refuses_stale_observation_without_api_mutation() -> None:
    requests: list[httpx.Request] = []
    value = connector(
        httpx.MockTransport(lambda request: requests.append(request) or httpx.Response(500))
    )

    with pytest.raises(ConnectorContractError, match="changed before dry run"):
        value.dry_run(
            pool_action(),
            before_state=TargetObservation("payments://before", "unexpected-generation"),
        )

    assert requests == []
