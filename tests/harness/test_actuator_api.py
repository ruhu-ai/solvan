from fastapi.testclient import TestClient

from apps.actuator.main import create_app


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
