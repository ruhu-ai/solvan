from __future__ import annotations

import pytest

from solvan.platform.cloud_run_release import CloudRunReleaseClient, CloudRunReleaseError


class Response:
    def __init__(self, value: object) -> None:
        self._value = value

    def raise_for_status(self) -> None:
        return None

    def json(self) -> object:
        return self._value


class Session:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def get(self, url: str, **kwargs: object) -> Response:
        self.calls.append(("GET", url, kwargs))
        return Response(
            {
                "name": "projects/customer-production/locations/europe-west2/services/payments-api",
                "etag": "etag-1",
                "generation": "7",
                "latestReadyRevision": "payments-api-old",
                "template": {
                    "serviceAccount": (
                        "payments-runtime@customer-production.iam.gserviceaccount.com"
                    ),
                    "containers": [
                        {"name": "payments-api", "image": "old.example/app@sha256:" + "a" * 64}
                    ],
                },
                "traffic": [{"revision": "payments-api-old", "percent": 100}],
            }
        )

    def patch(self, url: str, **kwargs: object) -> Response:
        self.calls.append(("PATCH", url, kwargs))
        return Response(
            {"name": "projects/customer-production/locations/europe-west2/operations/1"}
        )


def _client(session: Session) -> CloudRunReleaseClient:
    return CloudRunReleaseClient(
        session=session,
        service_resource_name=(
            "projects/customer-production/locations/europe-west2/services/payments-api"
        ),
        runtime_service_account=("payments-runtime@customer-production.iam.gserviceaccount.com"),
        container_name="payments-api",
    )


def test_cloud_run_adapter_uses_only_registered_resource_and_etag() -> None:
    session = Session()
    client = _client(session)
    observed = client.observe()
    operation = client.prepare_canary(
        expected=observed,
        image="europe-west2-docker.pkg.dev/customer-production/apps/payments@sha256:" + "b" * 64,
        revision_name="payments-api-solvan1",
        canary_percent=10,
        predeploy_revision="payments-api-old",
    )
    assert operation.done is False
    method, url, kwargs = session.calls[-1]
    assert method == "PATCH"
    assert url.endswith(
        "/projects/customer-production/locations/europe-west2/services/payments-api"
    )
    assert kwargs["json"]["etag"] == "etag-1"  # type: ignore[index]
    assert kwargs["params"] == {
        "updateMask": "template.revision,template.serviceAccount,template.containers,traffic"
    }


def test_cloud_run_adapter_refuses_arbitrary_image_and_traffic() -> None:
    client = _client(Session())
    observed = client.observe()
    with pytest.raises(CloudRunReleaseError):
        client.prepare_canary(
            expected=observed,
            image="https://attacker.example/image",
            revision_name="payments-api-solvan1",
            canary_percent=10,
            predeploy_revision="payments-api-old",
        )
    with pytest.raises(CloudRunReleaseError):
        client.set_traffic(expected=observed, assignments=(("payments-api-old", 99),))
