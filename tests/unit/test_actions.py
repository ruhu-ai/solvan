from datetime import UTC, datetime

import pytest

from solvan.domain import (
    ActionContractError,
    ActionType,
    AuthorizedActionMaterial,
    RiskClass,
    Scope,
    derive_expected_effect,
    freeze_json,
)


def scope() -> Scope:
    return Scope(
        "org_00000000000000000000000000",
        "prj_00000000000000000000000000",
        "env_00000000000000000000000000",
    )


def action(**overrides: object) -> AuthorizedActionMaterial:
    values: dict[str, object] = {
        "action_id": "act_00000000000000000000000000",
        "scope": scope(),
        "owner_entity_id": "inc_00000000000000000000000000",
        "workflow_version": 7,
        "evidence_version": 3,
        "action_type": ActionType.CLOUD_RUN_TRAFFIC_ROLLBACK,
        "target_key": "org/project/env/cloud-run/payments-api/deployment",
        "expected_target_version": "revision-v2",
        "expected_target_epoch": 4,
        "payload": freeze_json(
            {
                "service_name": "projects/demo/locations/europe-west1/services/payments-api",
                "known_good_revision": "revision-v1",
                "percent": 100,
            }
        ),
        "risk_class": RiskClass.HIGH,
        "reversible": True,
        "rollback_plan": freeze_json({"restore": "revision-v2"}),
        "policy_version": "policy-v3",
        "verification_profile_id": "payments-availability",
        "verification_profile_version": 2,
        "expires_at": datetime(2026, 8, 9, 12, 0, tzinfo=UTC),
    }
    values.update(overrides)
    if "expected_effect" not in overrides or "expected_effect_hash" not in overrides:
        expected = derive_expected_effect(
            action_type=values["action_type"],  # type: ignore[arg-type]
            target_key=values["target_key"],  # type: ignore[arg-type]
            expected_target_version=values["expected_target_version"],  # type: ignore[arg-type]
            payload=values["payload"],  # type: ignore[arg-type]
        )
        values.setdefault("expected_effect", expected.descriptor)
        values.setdefault("expected_effect_hash", expected.content_hash)
    return AuthorizedActionMaterial(**values)  # type: ignore[arg-type]


def test_approval_digest_is_stable_across_json_key_order() -> None:
    first = action(
        payload=freeze_json(
            {
                "service_name": "projects/demo/locations/europe-west1/services/payments-api",
                "known_good_revision": "revision-v1",
                "percent": 100,
            }
        )
    )
    second = action(
        payload=freeze_json(
            {
                "percent": 100,
                "known_good_revision": "revision-v1",
                "service_name": "projects/demo/locations/europe-west1/services/payments-api",
            }
        )
    )

    assert first.approval_digest() == second.approval_digest()
    assert first.approval_digest().startswith("sha256:")


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("workflow_version", 8),
        ("evidence_version", 4),
        ("expected_target_version", "revision-v3"),
        ("expected_target_epoch", 5),
        ("policy_version", "policy-v4"),
        ("verification_profile_version", 3),
        ("expires_at", datetime(2026, 8, 9, 12, 1, tzinfo=UTC)),
    ],
)
def test_every_approval_binding_change_invalidates_digest(field: str, replacement: object) -> None:
    baseline = action()
    changed = action(**{field: replacement})

    assert baseline.approval_digest() != changed.approval_digest()


def test_expected_effect_change_invalidates_approval_digest() -> None:
    baseline = action()
    changed = action(
        payload=freeze_json(
            {
                "service_name": "projects/demo/locations/europe-west1/services/payments-api",
                "known_good_revision": "revision-v0",
                "percent": 100,
            }
        )
    )

    assert baseline.expected_effect_hash != changed.expected_effect_hash
    assert baseline.approval_digest() != changed.approval_digest()


def test_expected_effect_cannot_be_authored_outside_the_application_profile() -> None:
    expected = action().expected_effect
    weakened = freeze_json({**dict(expected), "traffic": []})
    with pytest.raises(ActionContractError, match="application-derived"):
        action(expected_effect=weakened)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"workflow_version": 0}, "workflow_version"),
        ({"evidence_version": -1}, "evidence_version"),
        ({"expected_target_epoch": -1}, "expected_target_epoch"),
        ({"verification_profile_version": 0}, "verification_profile_version"),
        ({"target_key": ""}, "target key"),
        ({"expected_target_version": ""}, "target key"),
        ({"policy_version": ""}, "policy"),
        ({"verification_profile_id": ""}, "policy"),
        ({"expires_at": datetime(2026, 8, 9, 12, 0)}, "timezone-aware"),
    ],
)
def test_invalid_action_contract_is_rejected(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ActionContractError, match=message):
        action(**overrides)


def test_non_json_and_non_finite_values_are_rejected() -> None:
    with pytest.raises(ActionContractError, match="canonical JSON"):
        freeze_json({"unsupported": {1, 2}})
    with pytest.raises(ActionContractError, match="canonical JSON"):
        freeze_json({"invalid": float("nan")})


def test_frozen_json_does_not_follow_caller_mutation() -> None:
    caller = {"operation": "rollback", "parameters": {"revisions": ["v1"]}}
    frozen = freeze_json(caller)
    caller["operation"] = "delete"
    caller["parameters"]["revisions"].append("v2")

    assert frozen["operation"] == "rollback"
    assert frozen["parameters"]["revisions"] == ("v1",)

    with pytest.raises(TypeError):
        frozen["operation"] = "delete"  # type: ignore[index]
    with pytest.raises(TypeError):
        frozen["parameters"]["other"] = True  # type: ignore[index]
