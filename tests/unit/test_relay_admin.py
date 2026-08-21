from __future__ import annotations

import pytest
from pydantic import ValidationError

from apps.api.relay_admin import RelayDeploymentProfileApprovalCommand, RelaySourceBindingCommand
from solvan.domain import RelayAdapter

HASH = "sha256:" + "1" * 64


def _deployment_profile_approval() -> dict[str, object]:
    return {
        "schema_version": 1,
        "deployment_profile_id": "rdp_" + "0" * 26,
    }


def test_enrollment_approval_accepts_only_a_stored_deployment_profile() -> None:
    command = RelayDeploymentProfileApprovalCommand.model_validate(_deployment_profile_approval())
    assert command.deployment_profile_id.startswith("rdp_")
    with pytest.raises(ValidationError):
        RelayDeploymentProfileApprovalCommand.model_validate(
            {**_deployment_profile_approval(), "lifecycle": "READY"}
        )
    with pytest.raises(ValidationError):
        RelayDeploymentProfileApprovalCommand.model_validate(
            {**_deployment_profile_approval(), "principal_subject": "relay@example.test"}
        )


def test_source_binding_command_refuses_an_adapter_outside_the_qualified_set() -> None:
    command = RelaySourceBindingCommand.model_validate(
        {
            "schema_version": 1,
            "source_connection_id": "con_" + "0" * 26,
            "adapter_key": "cloud-monitoring.v1",
            "adapter_revision": "1",
        }
    )
    assert command.adapter_key == RelayAdapter.CLOUD_MONITORING.value
    with pytest.raises(ValidationError):
        RelaySourceBindingCommand.model_validate(
            {**command.model_dump(), "adapter_key": "error-reporting.v1"}
        )
    with pytest.raises(ValidationError):
        RelaySourceBindingCommand.model_validate(
            {**command.model_dump(), "source_connection_epoch": 99}
        )
    with pytest.raises(ValidationError):
        RelaySourceBindingCommand.model_validate(
            {**command.model_dump(), "local_binding_digest": HASH}
        )
