import logging

from fastapi.testclient import TestClient

import apps.actuator.main as main
from apps.actuator.local_policy import KILL_SWITCH_VARIABLE
from apps.actuator.main import create_app
from solvan.observability import TELEMETRY_LOGGER_NAME


def test_actuator_health_has_no_mutation_authority_claim() -> None:
    with TestClient(create_app()) as client:
        assert client.get("/live").json() == {"status": "live"}


def test_actuator_rejects_missing_identity_before_configuration_or_database() -> None:
    with TestClient(create_app()) as client:
        response = client.post(
            "/internal/v1/actions/act_00000000000000000000000000:execute",
            json={
                "schema_version": 1,
                "invocation_id": "inv_00000000000000000000000000",
            },
        )
    assert response.status_code == 401


def test_actuator_rejects_legacy_caller_supplied_scope() -> None:
    with TestClient(create_app()) as client:
        response = client.post(
            "/internal/v1/actions/act_00000000000000000000000000:execute",
            headers={"Authorization": "Bearer unverified-test-token"},
            json={
                "schema_version": 1,
                "invocation_id": "inv_00000000000000000000000000",
                "organization_id": "org_attacker",
                "project_id": "prj_attacker",
                "environment_id": "env_attacker",
            },
        )

    assert response.status_code == 422
    assert all(error["type"] == "extra_forbidden" for error in response.json()["detail"])


def test_a_local_refusal_is_recorded_for_the_operator_not_only_the_caller(
    tmp_path, monkeypatch
) -> None:
    """A 403 the caller sees is not a signal the operator can alert on.

    The kill switch and the hourly budget are enforced inside this binary, so
    the only trace they leave outside it is what the refusal boundary emits.
    Without this record the deployed alert policy would match nothing forever.
    """

    engaged = tmp_path / "kill-switch"
    engaged.write_text("engaged")
    monkeypatch.setenv(KILL_SWITCH_VARIABLE, str(engaged))
    monkeypatch.setattr(main, "_authorize_caller", lambda authorization: None)

    records: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = Capture()
    logger = logging.getLogger(TELEMETRY_LOGGER_NAME)
    logger.addHandler(handler)
    try:
        with TestClient(create_app()) as client:
            response = client.post(
                "/internal/v1/actions/act_00000000000000000000000000:execute",
                headers={"Authorization": "Bearer verified-by-monkeypatch"},
                json={
                    "schema_version": 1,
                    "invocation_id": "inv_00000000000000000000000000",
                },
            )
    finally:
        logger.removeHandler(handler)

    assert response.status_code == 403
    assert response.json()["detail"]["reason_code"] == "LOCAL_KILL_SWITCH_ENGAGED"
    assert [record.getMessage() for record in records] == [
        "solvan.control.refused:LOCAL_KILL_SWITCH_ENGAGED"
    ]
