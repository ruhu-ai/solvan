import json

import httpx
import pytest

from solvan.application.actuator import (
    AmbiguousMutation,
    ReconciliationResult,
    TargetObservation,
)
from solvan.connectors.mutation.cloud_run import (
    CloudRunConnectorError,
    CloudRunRollbackConnector,
)
from solvan.domain import freeze_json
from tests.unit.test_actions import action

SERVICE = "projects/demo/locations/europe-west1/services/payments-api"


class TokenProvider:
    def token(self, *, scopes: tuple[str, ...]) -> str:
        assert scopes == ("https://www.googleapis.com/auth/cloud-platform",)
        return "access-token"


def rollback_action():  # type: ignore[no-untyped-def]
    return action(
        payload=freeze_json(
            {
                "service_name": SERVICE,
                "known_good_revision": "payments-v1",
                "percent": 100,
            }
        )
    )


def service(revision: str, *, etag: str = "etag-1") -> dict[str, object]:
    return {
        "name": SERVICE,
        "etag": etag,
        "trafficStatuses": [{"revision": revision, "percent": 100}],
    }


def test_cloud_run_rollback_uses_etag_and_reconciles_traffic() -> None:
    requests: list[httpx.Request] = []
    get_count = 0

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal get_count
        requests.append(request)
        if "/operations/" in request.url.path:
            return httpx.Response(200, json={"name": "operations/rollback-1", "done": True})
        if request.method == "GET":
            get_count += 1
            revision = "revision-v2" if get_count < 3 else "payments-v1"
            return httpx.Response(200, json=service(revision))
        return httpx.Response(200, json={"name": "operations/rollback-1"})

    connector = CloudRunRollbackConnector(
        token_provider=TokenProvider(),
        client=httpx.Client(transport=httpx.MockTransport(handle)),
        sleep=lambda _seconds: None,
    )
    material = rollback_action()
    before = connector.observe(material)
    request_count_before_dry_run = len(requests)
    prediction = connector.dry_run(material, before_state=before)
    assert len(requests) == request_count_before_dry_run
    assert prediction.content_hash == material.expected_effect_hash
    call = connector.mutate(rollback_action(), idempotency_key="rollback-1")
    result = connector.reconcile(rollback_action(), idempotency_key="rollback-1")

    assert call.connector_request_id == "operations/rollback-1"
    assert result.result is ReconciliationResult.EFFECT_CONFIRMED
    patch = next(request for request in requests if request.method == "PATCH")
    assert patch.headers["authorization"] == "Bearer access-token"
    assert patch.url.params["updateMask"] == "traffic"
    assert json.loads(patch.content)["etag"] == "etag-1"


def test_cloud_run_rollback_times_out_as_ambiguous_while_operation_is_running() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        if request.method == "PATCH" or "/operations/" in request.url.path:
            return httpx.Response(200, json={"name": "operations/rollback-1", "done": False})
        return httpx.Response(200, json=service("revision-v2"))

    connector = CloudRunRollbackConnector(
        token_provider=TokenProvider(),
        client=httpx.Client(transport=httpx.MockTransport(handle)),
        sleep=lambda _seconds: None,
        maximum_operation_polls=2,
    )
    with pytest.raises(AmbiguousMutation, match="connector outcome is ambiguous"):
        connector.mutate(rollback_action(), idempotency_key="rollback-1")


def test_split_traffic_is_inconclusive_instead_of_guessing_active_revision() -> None:
    connector = CloudRunRollbackConnector(
        token_provider=TokenProvider(),
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(
                    200,
                    json={
                        "name": SERVICE,
                        "etag": "etag-1",
                        "trafficStatuses": [
                            {"revision": "v1", "percent": 50},
                            {"revision": "v2", "percent": 50},
                        ],
                    },
                )
            )
        ),
    )
    with pytest.raises(CloudRunConnectorError, match="exactly one"):
        connector.observe(rollback_action())


def test_cloud_run_dry_run_refuses_stale_observation_without_api_mutation() -> None:
    requests: list[httpx.Request] = []
    value = CloudRunRollbackConnector(
        token_provider=TokenProvider(),
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: requests.append(request) or httpx.Response(500)
            )
        ),
    )

    with pytest.raises(CloudRunConnectorError, match="changed before dry run"):
        value.dry_run(
            rollback_action(),
            before_state=TargetObservation("cloudrun://before", "unexpected-revision"),
        )

    assert requests == []
