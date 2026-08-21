"""Durable QUALIFY_CODE_CHANGE command handler for the GitHub Provider."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from solvan.application.code_change_qualification import (
    CodeChangeQualificationDocuments,
    CodeChangeQualificationInput,
    ObservedRepositoryFile,
    qualify_code_change,
)
from solvan.application.delivery_commands import (
    DeliveryCommandError,
    DeliveryCommandKind,
    DeliveryCommandStatus,
    DeliveryOutcome,
    DeliveryReasonCode,
    PrivateCommandEnvelope,
    PrivateCommandResponse,
)
from solvan.application.workspace_candidate import CandidateFile, CandidateTree
from solvan.application.workspace_hashing import canonical_sha256, sha256_bytes
from solvan.domain import Scope
from solvan.persistence.code_change_qualification_store import (
    PostgresCodeChangeQualificationStore,
    QualificationMaterial,
    QualifiedRepositoryReceipt,
)
from solvan.persistence.delivery_command_store import PostgresDeliveryCommandStore
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.github import GitHubClient
from solvan.platform.github_repository_qualification import (
    GitHubRepositoryQualificationReader,
)
from solvan.platform.google_rest import authorized_session
from solvan.platform.repository_snapshot import parse_repository_snapshot


class QualificationSettings(Protocol):
    coordinator_audience: str
    runtime_bucket: str
    service_revision: str


def execute_qualification(
    *,
    envelope: PrivateCommandEnvelope,
    caller: str,
    settings: QualificationSettings,
    client_factory: Callable[[int], GitHubClient],
    reader_factory: Callable[[int], GitHubRepositoryQualificationReader],
) -> dict[str, Any]:
    """Execute or reconcile one read-only provider qualification command."""

    now = datetime.now(UTC)
    session = authorized_session()
    evidence_reader = GcsEvidenceReader(
        allowed_buckets=frozenset({settings.runtime_bucket}), session=session
    )
    evidence_writer = GcsEvidenceWriter(bucket=settings.runtime_bucket, session=session)
    with connect_database() as connection:
        commands = PostgresDeliveryCommandStore(connection)
        command = commands.load(command_id=envelope.command_id, payload_reader=evidence_reader)
        command.validate_envelope(
            envelope,
            caller_identity=caller,
            audience_hash=sha256_bytes(settings.coordinator_audience.encode()),
            now=now,
        )
        prior = commands.load_terminal_response(
            command_id=command.command_id, payload_reader=evidence_reader
        )
        if prior is not None:
            prior_result = (
                evidence_reader.get_json(
                    uri=prior.receipt_ref,
                    expected_hash=prior.receipt_hash,
                    max_bytes=64_000,
                )
                if prior.receipt_ref is not None and prior.receipt_hash is not None
                else None
            )
            return {"command": prior.model_dump(mode="json"), "result": prior_result}
        if command.command_kind is not DeliveryCommandKind.QUALIFY_CODE_CHANGE:
            raise DeliveryCommandError("qualification endpoint accepts only its exact command kind")
        if command.status is DeliveryCommandStatus.PREPARED:
            if not commands.claim_for_issue(command_id=command.command_id):
                raise DeliveryCommandError("qualification command issue fence was already claimed")
        elif command.status is DeliveryCommandStatus.ISSUED:
            commands.begin_reconciliation(command_id=command.command_id)
        elif command.status is not DeliveryCommandStatus.RECONCILING:
            raise DeliveryCommandError("qualification command is no longer recoverable")
        material = PostgresCodeChangeQualificationStore(connection).load_material(
            scope=command.scope, intent_id=command.subject_id, now=now
        )
    try:
        qualification = _qualify(
            material=material,
            evidence_reader=evidence_reader,
            client=client_factory(material.installation_id),
            repository_reader=reader_factory(material.installation_id),
        )
    except ValueError:
        return _record_refusal(
            command_id=command.command_id,
            scope=command.scope,
            material=material,
            settings=settings,
            writer=evidence_writer,
            observed_at=now,
        )
    prefix = _prefix(command.scope.canonical_dict(), command.command_id)
    base_tree = evidence_writer.put_json(
        object_name=f"{prefix}/base-tree.json", value=qualification.base_tree
    )
    transform = evidence_writer.put_json(
        object_name=f"{prefix}/patch-transform.json",
        value=qualification.transform.canonical_dict(),
    )
    definitions = evidence_writer.put_json(
        object_name=f"{prefix}/required-check-definitions.json",
        value=qualification.required_check_definitions,
    )
    attributes = evidence_writer.put_json(
        object_name=f"{prefix}/attributes-evaluation.json",
        value=qualification.attributes_evaluation,
    )
    observation = evidence_writer.put_json(
        object_name=f"{prefix}/provider-observation.json",
        value=qualification.provider_observation,
    )
    receipt = QualifiedRepositoryReceipt(
        outcome="QUALIFIED",
        reason_code="QUALIFIED",
        repository_binding_id=material.repository_binding_id,
        repository_policy_hash=material.repository_policy_hash,
        code_delivery_profile_id=material.code_delivery_profile_id,
        code_delivery_profile_hash=material.code_delivery_profile_hash,
        default_branch=material.configured_default_branch,
        base_commit_sha=material.expected_base_commit_sha,
        base_tree_ref=base_tree.uri,
        base_tree_hash=qualification.transform.base_tree_hash,
        patch_transform_version=qualification.transform.version,
        patch_transform_ref=transform.uri,
        patch_transform_hash=qualification.transform.transform_hash,
        proposed_tree_hash=qualification.transform.proposed_tree_hash,
        base_required_check_definitions_ref=definitions.uri,
        base_required_check_definitions_hash=definitions.content_hash,
        attributes_evaluation_ref=attributes.uri,
        attributes_evaluation_hash=attributes.content_hash,
        provider_observation_ref=observation.uri,
        provider_observation_hash=observation.content_hash,
        provider_service_revision=settings.service_revision,
        observed_at=now,
    )
    return _complete(
        command_id=command.command_id,
        scope=command.scope,
        material=material,
        receipt=receipt,
        outcome=DeliveryOutcome.ACCEPTED,
        reason=DeliveryReasonCode.OPERATION_COMPLETED,
        writer=evidence_writer,
        observed_at=now,
    )


def _qualify(
    *,
    material: QualificationMaterial,
    evidence_reader: GcsEvidenceReader,
    client: GitHubClient,
    repository_reader: GitHubRepositoryQualificationReader,
) -> CodeChangeQualificationDocuments:
    repository = client.repository(owner=material.owner, name=material.name)
    observed_default = repository.get("default_branch")
    if not isinstance(observed_default, str):
        raise ValueError("provider repository response omitted its default branch")
    observed_commit = client.resolve_commit(
        owner=material.owner,
        name=material.name,
        ref=f"refs/heads/{observed_default}",
    )
    files = repository_reader.regular_file_tree(
        owner=material.owner,
        name=material.name,
        commit_sha=observed_commit,
    )
    snapshot_value = evidence_reader.get_json(
        uri=material.repository_snapshot_ref,
        expected_hash=material.repository_snapshot_hash,
        max_bytes=1_200_000,
    )
    if not isinstance(snapshot_value, dict):
        raise ValueError("repository snapshot is not an object")
    snapshot = parse_repository_snapshot(
        snapshot_value,
        expected_commit_sha=material.expected_base_commit_sha,
        allowed_file_globs=material.repair_allowed_paths,
        max_total_content_bytes=800_000,
    )
    candidate_value = evidence_reader.get_json(
        uri=material.candidate_manifest_ref,
        expected_hash=material.candidate_manifest_hash,
        max_bytes=1_200_000,
    )
    if not isinstance(candidate_value, dict):
        raise ValueError("candidate manifest is not an object")
    return qualify_code_change(
        CodeChangeQualificationInput(
            repository_binding_id=material.repository_binding_id,
            code_delivery_profile_id=material.code_delivery_profile_id,
            code_delivery_profile_hash=material.code_delivery_profile_hash,
            owner=material.owner,
            name=material.name,
            configured_default_branch=material.configured_default_branch,
            observed_default_branch=observed_default,
            expected_base_commit_sha=material.expected_base_commit_sha,
            observed_base_commit_sha=observed_commit,
            repair_allowed_paths=material.repair_allowed_paths,
            delivery_allowed_paths=material.delivery_allowed_paths,
            required_check_definition_paths=material.required_check_definition_paths,
            repair_base=CandidateTree(
                tuple(CandidateFile(item.path, item.content) for item in snapshot.files),
                material.repair_allowed_paths,
            ),
            repair_base_modes={item.path: item.mode for item in snapshot.files},
            candidate_manifest=candidate_value,
            observed_files=tuple(
                ObservedRepositoryFile(
                    item.path,
                    item.mode,
                    item.blob_sha,
                    item.content,
                    item.content_hash,
                )
                for item in files
            ),
        )
    )


def _record_refusal(
    *,
    command_id: str,
    scope: Scope,
    material: QualificationMaterial,
    settings: QualificationSettings,
    writer: GcsEvidenceWriter,
    observed_at: datetime,
) -> dict[str, Any]:
    observation_value = {
        "schema_version": 1,
        "qualification_intent_id": material.intent_id,
        "outcome": "REFUSED",
        "reason_code": "POLICY_REFUSED",
    }
    prefix = _prefix(scope.canonical_dict(), command_id)
    observation = writer.put_json(
        object_name=f"{prefix}/provider-observation.json", value=observation_value
    )
    receipt = QualifiedRepositoryReceipt(
        outcome="REFUSED",
        reason_code="POLICY_REFUSED",
        repository_binding_id=material.repository_binding_id,
        repository_policy_hash=material.repository_policy_hash,
        code_delivery_profile_id=material.code_delivery_profile_id,
        code_delivery_profile_hash=material.code_delivery_profile_hash,
        default_branch=None,
        base_commit_sha=None,
        base_tree_ref=None,
        base_tree_hash=None,
        patch_transform_version=None,
        patch_transform_ref=None,
        patch_transform_hash=None,
        proposed_tree_hash=None,
        base_required_check_definitions_ref=None,
        base_required_check_definitions_hash=None,
        attributes_evaluation_ref=None,
        attributes_evaluation_hash=None,
        provider_observation_ref=observation.uri,
        provider_observation_hash=observation.content_hash,
        provider_service_revision=settings.service_revision,
        observed_at=observed_at,
    )
    return _complete(
        command_id=command_id,
        scope=scope,
        material=material,
        receipt=receipt,
        outcome=DeliveryOutcome.REFUSED,
        reason=DeliveryReasonCode.POLICY_DENIED,
        writer=writer,
        observed_at=observed_at,
    )


def _complete(
    *,
    command_id: str,
    scope: Scope,
    material: QualificationMaterial,
    receipt: QualifiedRepositoryReceipt,
    outcome: DeliveryOutcome,
    reason: DeliveryReasonCode,
    writer: GcsEvidenceWriter,
    observed_at: datetime,
) -> dict[str, Any]:
    with connect_database() as connection, connection.transaction():
        qualification_id = PostgresCodeChangeQualificationStore(connection).record_receipt(
            scope=scope, intent_id=material.intent_id, receipt=receipt
        )
    result = {
        "schema_version": 1,
        "qualification_receipt_id": qualification_id,
        "outcome": receipt.outcome,
        "provider_observation_ref": receipt.provider_observation_ref,
        "provider_observation_hash": receipt.provider_observation_hash,
    }
    response_receipt = writer.put_json(
        object_name=f"commands/{command_id}/response.json", value=result
    )
    response = PrivateCommandResponse(
        command_id=command_id,
        outcome=outcome,
        reason_code=reason,
        receipt_ref=response_receipt.uri,
        receipt_hash=response_receipt.content_hash,
        observed_at=observed_at,
    )
    response_envelope = writer.put_json(
        object_name=f"commands/{command_id}/response-envelope.json",
        value=response.model_dump(mode="json"),
    )
    with connect_database() as connection, connection.transaction():
        PostgresDeliveryCommandStore(connection).complete(
            response,
            response_ref=response_envelope.uri,
            response_hash=canonical_sha256(response.model_dump(mode="json")),
        )
    return {"command": response.model_dump(mode="json"), "result": result}


def _prefix(scope: dict[str, str], command_id: str) -> str:
    return (
        f"{scope['organization_id']}/{scope['project_id']}/"
        f"{scope['environment_id']}/code-change-qualification/{command_id}"
    )
