from __future__ import annotations

import pytest
from pydantic import ValidationError

from solvan.application.code_delivery_profiles import CodeDeliveryProfileInput


def _profile(**overrides: object) -> CodeDeliveryProfileInput:
    value: dict[str, object] = {
        "repository_binding_id": "ghr_00000000000000000000000000",
        "allowed_paths": ["src/**/*.py", "tests/**/*.py"],
        "required_checks": ["unit", "security"],
        "required_check_definition_paths": [".github/workflows/ci.yml"],
        "minimum_approvals": 1,
        "require_code_owner_review": True,
        "merge_method": "squash",
        "deployment_target_profile": "cloud-run/payments-production@1",
        "maximum_request_lifetime_minutes": 120,
    }
    value.update(overrides)
    return CodeDeliveryProfileInput.model_validate(value)


def test_profile_derives_all_policy_documents_and_a_stable_hash() -> None:
    profile = _profile()
    assert set(profile.documents) == {
        "required-checks",
        "reviewer",
        "pr-creation",
        "merge",
        "deployment",
    }
    assert profile.documents["pr-creation"] == {"schema_version": 1, "draft_required": True}
    assert profile.profile_hash == _profile().profile_hash


@pytest.mark.parametrize("path", [".github/workflows/**", "infra/**", "../src/**"])
def test_profile_refuses_repair_authority_over_control_plane_paths(path: str) -> None:
    with pytest.raises((ValidationError, ValueError)):
        _profile(allowed_paths=[path])


def test_profile_refuses_globbed_required_check_definition() -> None:
    with pytest.raises((ValidationError, ValueError)):
        _profile(required_check_definition_paths=[".github/workflows/*.yml"])
