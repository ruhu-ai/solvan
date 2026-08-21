from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from solvan.application.delivery_commands import (
    DeliveryCommandError,
    DeliveryCommandKind,
    DeliveryCommandStatus,
    PrivateCommandEnvelope,
    PrivateCommandRecord,
    PrivateCommandResponse,
    payload_schema_hash,
)
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope


def _record() -> PrivateCommandRecord:
    payload = {
        "test_command_id": "rcc_01J00000000000000000000000",
        "candidate_tree_hash": "sha256:" + "a" * 64,
    }
    return PrivateCommandRecord(
        command_id="cmd_01J00000000000000000000000",
        scope=Scope(
            "org_00000000000000000000000000",
            "prj_00000000000000000000000000",
            "env_00000000000000000000000000",
        ),
        command_kind=DeliveryCommandKind.EXPLORATORY_SANDBOX_RUN,
        subject_id="run_01J00000000000000000000000",
        material_hash="sha256:" + "b" * 64,
        idempotency_key="delivery-command-0001",
        payload_ref="gs://solvan-private/commands/cmd.json",
        payload=payload,
        payload_hash=canonical_sha256(payload),
        payload_schema_hash=payload_schema_hash(DeliveryCommandKind.EXPLORATORY_SANDBOX_RUN),
        admitted_caller_identity="serviceAccount:workspace-adapter@example.com",
        admitted_audience_hash="sha256:" + "d" * 64,
        deadline=datetime.now(UTC) + timedelta(minutes=5),
        status=DeliveryCommandStatus.PREPARED,
    )


def test_private_command_is_only_routed_by_its_durable_id() -> None:
    record = _record()
    envelope = PrivateCommandEnvelope(command_id=record.command_id, payload=record.payload)
    record.validate_envelope(
        envelope,
        caller_identity=record.admitted_caller_identity,
        audience_hash=record.admitted_audience_hash,
        now=datetime.now(UTC),
    )
    with pytest.raises(DeliveryCommandError, match="payload differs"):
        record.validate_envelope(
            envelope.model_copy(
                update={"payload": {**record.payload, "candidate_tree_hash": "sha256:" + "e" * 64}}
            ),
            caller_identity=record.admitted_caller_identity,
            audience_hash=record.admitted_audience_hash,
            now=datetime.now(UTC),
        )


def test_command_shape_cannot_smuggle_scope_or_an_arbitrary_field() -> None:
    with pytest.raises(ValidationError):
        PrivateCommandEnvelope.model_validate(
            {
                "schema_version": 1,
                "command_id": "cmd_01J00000000000000000000000",
                "payload": {},
                "scope": {},
            }
        )
    payload = {
        "test_command_id": "rcc_01J00000000000000000000000",
        "candidate_tree_hash": "sha256:" + "a" * 64,
        "run_kind": "ADJUDICATION",
    }
    with pytest.raises(DeliveryCommandError, match="payload shape"):
        _record().model_copy(
            update={"payload": payload, "payload_hash": canonical_sha256(payload)}
        ).validate_record()


def test_only_provider_unavailability_can_be_a_retryable_result() -> None:
    with pytest.raises(ValidationError, match="retryable"):
        PrivateCommandResponse(
            command_id="cmd_01J00000000000000000000000",
            outcome="RETRYABLE",
            reason_code="MATERIAL_MISMATCH",
            observed_at=datetime.now(UTC),
        )


def test_command_payload_schema_hash_cannot_be_a_valid_digest_for_another_shape() -> None:
    with pytest.raises(DeliveryCommandError, match="schema"):
        _record().model_copy(update={"payload_schema_hash": "sha256:" + "c" * 64}).validate_record()


def test_workspace_tool_invocation_carries_one_closed_tool_input() -> None:
    payload = {
        "tool_revision": "workspace.code-repair.run-in-sandbox@1",
        "call_ordinal": 4,
        "tool_input": {
            "schema_version": 1,
            "test_command_id": "rcc_01J00000000000000000000000",
            "candidate_tree_hash": "sha256:" + "a" * 64,
        },
    }
    record = _record().model_copy(
        update={
            "command_kind": DeliveryCommandKind.WORKSPACE_TOOL_INVOKE,
            "payload": payload,
            "payload_hash": canonical_sha256(payload),
            "payload_schema_hash": payload_schema_hash(DeliveryCommandKind.WORKSPACE_TOOL_INVOKE),
        }
    )
    record.validate_record()

    smuggled = record.model_copy(
        update={
            "payload": {
                **payload,
                "tool_input": {**payload["tool_input"], "run_kind": "ADJUDICATION"},
            }
        }
    )
    with pytest.raises(DeliveryCommandError, match="closed tool invocation"):
        smuggled.validate_record()


def test_code_change_qualification_command_has_no_caller_supplied_material() -> None:
    record = _record().model_copy(
        update={
            "command_kind": DeliveryCommandKind.QUALIFY_CODE_CHANGE,
            "subject_id": "cqi_01J00000000000000000000000",
            "payload": {},
            "payload_hash": canonical_sha256({}),
            "payload_schema_hash": payload_schema_hash(DeliveryCommandKind.QUALIFY_CODE_CHANGE),
        }
    )
    record.validate_record()
    with pytest.raises(DeliveryCommandError, match="payload shape"):
        record.model_copy(
            update={
                "payload": {"repository": "attacker/repo"},
                "payload_hash": canonical_sha256({"repository": "attacker/repo"}),
            }
        ).validate_record()


def test_merge_command_must_bind_one_exact_github_observation() -> None:
    payload = {"github_observation_hash": "sha256:" + "a" * 64}
    record = _record().model_copy(
        update={
            "command_kind": DeliveryCommandKind.MERGE_PR,
            "payload": payload,
            "payload_hash": canonical_sha256(payload),
            "payload_schema_hash": payload_schema_hash(DeliveryCommandKind.MERGE_PR),
        }
    )
    record.validate_record()
    malformed = {"github_observation_hash": "sha256:not-a-digest"}
    with pytest.raises(DeliveryCommandError, match="observation binding"):
        record.model_copy(
            update={"payload": malformed, "payload_hash": canonical_sha256(malformed)}
        ).validate_record()
