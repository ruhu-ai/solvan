"""Private, command-only Cloud Run release Deployment Controller."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Header, HTTPException, status
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict, Field

from solvan.application.delivery_commands import (
    DeliveryCommandError,
    DeliveryCommandKind,
    DeliveryCommandStatus,
    DeliveryOutcome,
    DeliveryReasonCode,
    PrivateCommandEnvelope,
    PrivateCommandResponse,
)
from solvan.application.release_candidates import (
    ReleaseCandidateEnvelope,
    ReleaseCandidateExpected,
    verify_release_candidate,
)
from solvan.application.release_targets import ReleaseTargetObservation
from solvan.application.release_verification import (
    ReleaseEffectReceiptEnvelope,
    ReleaseEffectReceiptExpected,
    ReleaseHealthSnapshot,
    ReleaseHealthSnapshotExpected,
    ReleaseRollbackReceiptEnvelope,
    verify_release_effect_receipt,
    verify_release_health_snapshot,
    verify_release_rollback_receipt,
)
from solvan.application.workspace_hashing import canonical_sha256, sha256_bytes
from solvan.domain import Scope
from solvan.observability import instrument_fastapi
from solvan.persistence.delivery_command_store import PostgresDeliveryCommandStore
from solvan.persistence.release_rollout_store import PostgresReleaseRolloutStore
from solvan.persistence.release_target_observation_store import (
    PostgresReleaseTargetObservationStore,
    target_observation_document,
)
from solvan.platform.cloud_run_release import CloudRunReleaseClient
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.google_rest import authorized_session
from solvan.platform.workspace_attestation import GoogleKmsPublicKeyReader


class DeploymentControllerSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: Scope
    coordinator_audience: str = Field(pattern=r"^https://")
    coordinator_principal: str = Field(min_length=3)
    runtime_bucket: str = Field(min_length=3)
    service_principal: str = Field(min_length=3)
    service_revision: str = Field(min_length=1)

    @classmethod
    def from_env(cls) -> DeploymentControllerSettings:
        required = (
            "SOLVAN_ORGANIZATION_ID",
            "SOLVAN_SCOPE_PROJECT_ID",
            "SOLVAN_ENVIRONMENT_ID",
            "SOLVAN_DEPLOYMENT_CONTROLLER_AUDIENCE",
            "SOLVAN_COORDINATOR_SERVICE_ACCOUNT",
            "SOLVAN_RUNTIME_BUCKET",
            "SOLVAN_DEPLOYMENT_CONTROLLER_SERVICE_ACCOUNT",
        )
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            raise RuntimeError("missing Deployment Controller settings: " + ",".join(missing))
        return cls(
            scope=Scope(
                os.environ["SOLVAN_ORGANIZATION_ID"],
                os.environ["SOLVAN_SCOPE_PROJECT_ID"],
                os.environ["SOLVAN_ENVIRONMENT_ID"],
            ),
            coordinator_audience=os.environ["SOLVAN_DEPLOYMENT_CONTROLLER_AUDIENCE"],
            coordinator_principal=(
                "serviceAccount:" + os.environ["SOLVAN_COORDINATOR_SERVICE_ACCOUNT"]
            ),
            runtime_bucket=os.environ["SOLVAN_RUNTIME_BUCKET"],
            service_principal=(
                "serviceAccount:" + os.environ["SOLVAN_DEPLOYMENT_CONTROLLER_SERVICE_ACCOUNT"]
            ),
            service_revision=os.environ.get("K_REVISION", "LOCAL_UNQUALIFIED"),
        )


def _principal(authorization: str | None, settings: DeploymentControllerSettings) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing coordinator identity")
    try:
        claims = id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
            authorization.removeprefix("Bearer "),
            GoogleRequest(),
            audience=settings.coordinator_audience,
        )
    except (GoogleAuthError, ValueError) as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid coordinator identity") from error
    email = claims.get("email")
    expected = settings.coordinator_principal.removeprefix("serviceAccount:").lower()
    if (
        claims.get("email_verified") is not True
        or not isinstance(email, str)
        or email.lower() != expected
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "caller is not the coordinator identity")
    return f"serviceAccount:{email.lower()}"


def create_app() -> FastAPI:
    app = FastAPI(title="Solvan Deployment Controller", version="0.1.0")

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post("/internal/v1/commands:execute")
    def execute(
        envelope: PrivateCommandEnvelope,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        settings = DeploymentControllerSettings.from_env()
        caller = _principal(authorization, settings)
        try:
            with connect_database() as connection:
                row = connection.execute(
                    "SELECT command_kind FROM solvan_delivery.private_command_dispatches "
                    "WHERE id=%s",
                    (envelope.command_id,),
                ).fetchone()
            if row is None:
                raise DeliveryCommandError("private command does not exist")
            kind = DeliveryCommandKind(str(row[0]))
            if kind is DeliveryCommandKind.OBSERVE_RELEASE_TARGET:
                return _execute_observation(envelope=envelope, caller=caller, settings=settings)
            if kind is DeliveryCommandKind.START_ROLLOUT:
                return _execute_start_rollout(envelope=envelope, caller=caller, settings=settings)
            if kind is DeliveryCommandKind.PREPARE_CANARY:
                return _execute_prepare_canary(envelope=envelope, caller=caller, settings=settings)
            if kind is DeliveryCommandKind.PROMOTE_CANARY:
                return _execute_promote_canary(envelope=envelope, caller=caller, settings=settings)
            if kind is DeliveryCommandKind.FINALIZE_ROLLOUT:
                return _execute_finalize_rollout(
                    envelope=envelope, caller=caller, settings=settings
                )
            if kind is DeliveryCommandKind.REGISTER_VERIFICATION_FAILURE:
                return _execute_register_verification_failure(
                    envelope=envelope, caller=caller, settings=settings
                )
            if kind is DeliveryCommandKind.ROLLBACK_RELEASE:
                return _execute_rollback_release(
                    envelope=envelope, caller=caller, settings=settings
                )
            if kind is DeliveryCommandKind.FINALIZE_ROLLBACK:
                return _execute_finalize_rollback(
                    envelope=envelope, caller=caller, settings=settings
                )
            raise DeliveryCommandError("Deployment Controller command kind is not implemented")
        except (DeliveryCommandError, ValueError) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error

    instrument_fastapi(app, service_name="deployment-controller")
    return app


def _execute_observation(
    *, envelope: PrivateCommandEnvelope, caller: str, settings: DeploymentControllerSettings
) -> dict[str, Any]:
    now = datetime.now(UTC)
    session = authorized_session()
    reader = GcsEvidenceReader(
        allowed_buckets=frozenset({settings.runtime_bucket}), session=session
    )
    writer = GcsEvidenceWriter(bucket=settings.runtime_bucket, session=session)
    with connect_database() as connection:
        commands = PostgresDeliveryCommandStore(connection)
        command = commands.load(command_id=envelope.command_id, payload_reader=reader)
        command.validate_envelope(
            envelope,
            caller_identity=caller,
            audience_hash=sha256_bytes(settings.coordinator_audience.encode()),
            now=now,
        )
        prior = commands.load_terminal_response(
            command_id=command.command_id, payload_reader=reader
        )
        if prior is not None:
            return prior.model_dump(mode="json")
        if command.command_kind is not DeliveryCommandKind.OBSERVE_RELEASE_TARGET:
            raise DeliveryCommandError("Deployment Controller command kind is not implemented")
        if command.status is DeliveryCommandStatus.PREPARED:
            if not commands.claim_for_issue(command_id=command.command_id):
                raise DeliveryCommandError("target observation command was already claimed")
        elif command.status is DeliveryCommandStatus.ISSUED:
            commands.begin_reconciliation(command_id=command.command_id)
        elif command.status is not DeliveryCommandStatus.RECONCILING:
            raise DeliveryCommandError("target observation command is no longer recoverable")
        material = PostgresReleaseTargetObservationStore(connection).load(
            scope=command.scope,
            request_id=command.subject_id,
            material_hash=command.material_hash,
        )
    manifest = reader.get_json(
        uri=material.deployment_manifest_profile_ref,
        expected_hash=material.deployment_manifest_profile_hash,
        max_bytes=64_000,
    )
    if (
        set(manifest)
        != {
            "schema_version",
            "provider_kind",
            "service_resource_name",
            "runtime_service_account",
            "allowed_container_name",
            "mutable_fields",
        }
        or manifest.get("schema_version") != 1
        or manifest.get("provider_kind") != "GCP_CLOUD_RUN_V2"
    ):
        raise DeliveryCommandError("release target manifest profile is malformed")
    if (
        manifest.get("service_resource_name") != material.service_resource_name
        or manifest.get("runtime_service_account") != material.runtime_service_account
        or manifest.get("mutable_fields") != ["image", "revision_suffix", "traffic"]
        or not isinstance(manifest.get("allowed_container_name"), str)
    ):
        raise DeliveryCommandError("release target manifest profile differs")
    observation = CloudRunReleaseClient(
        session=session,
        service_resource_name=material.service_resource_name,
        runtime_service_account=material.runtime_service_account,
        container_name=str(manifest["allowed_container_name"]),
    ).observe()
    document = dict(target_observation_document(material=material, observation=observation))
    prefix = (
        f"{command.scope.organization_id}/{command.scope.project_id}/"
        f"{command.scope.environment_id}/release-target-observations/"
        f"{material.request_id}/{canonical_sha256(document)}"
    )
    assignment = writer.put_json(
        object_name=f"{prefix}/assignment.json",
        value={
            "schema_version": 1,
            "resource_name": observation.resource_name,
            "generation": observation.generation,
            "latest_ready_revision": observation.latest_ready_revision,
            "traffic": [list(item) for item in observation.traffic],
        },
    )
    document["assignment_ref"] = assignment.uri
    document["assignment_hash"] = assignment.content_hash
    receipt = writer.put_json(object_name=f"{prefix}/observation.json", value=document)
    with connect_database() as connection, connection.transaction():
        PostgresReleaseTargetObservationStore(connection).record(
            scope=command.scope,
            material=material,
            observation=observation,
            assignment_ref=assignment.uri,
            assignment_hash=assignment.content_hash,
            observation_ref=receipt.uri,
            observation_hash=receipt.content_hash,
            observer_identity=settings.service_principal,
            observer_revision=settings.service_revision,
            observed_at=now,
        )
    response = PrivateCommandResponse(
        command_id=command.command_id,
        outcome=DeliveryOutcome.ACCEPTED,
        reason_code=DeliveryReasonCode.OPERATION_COMPLETED,
        receipt_ref=receipt.uri,
        receipt_hash=receipt.content_hash,
        observed_at=now,
    )
    response_receipt = writer.put_json(
        object_name=f"private-command-responses/{command.command_id}.json",
        value=response.model_dump(mode="json"),
    )
    with connect_database() as connection, connection.transaction():
        PostgresDeliveryCommandStore(connection).complete(
            response,
            response_ref=response_receipt.uri,
            response_hash=response_receipt.content_hash,
        )
    return response.model_dump(mode="json")


def _execute_start_rollout(
    *, envelope: PrivateCommandEnvelope, caller: str, settings: DeploymentControllerSettings
) -> dict[str, Any]:
    now = datetime.now(UTC)
    session = authorized_session()
    reader = GcsEvidenceReader(
        allowed_buckets=frozenset({settings.runtime_bucket}), session=session
    )
    writer = GcsEvidenceWriter(bucket=settings.runtime_bucket, session=session)
    with connect_database() as connection:
        commands = PostgresDeliveryCommandStore(connection)
        command = commands.load(command_id=envelope.command_id, payload_reader=reader)
        command.validate_envelope(
            envelope,
            caller_identity=caller,
            audience_hash=sha256_bytes(settings.coordinator_audience.encode()),
            now=now,
        )
        prior = commands.load_terminal_response(
            command_id=command.command_id, payload_reader=reader
        )
        if prior is not None:
            return prior.model_dump(mode="json")
        if command.command_kind is not DeliveryCommandKind.START_ROLLOUT:
            raise DeliveryCommandError("rollout-start handler accepts only START_ROLLOUT")
        store = PostgresReleaseRolloutStore(connection)
        existing = store.started_rollout(
            scope=command.scope,
            request_id=command.subject_id,
            material_hash=command.material_hash,
        )
        if existing is None:
            candidate = store.candidate_for_start(
                scope=command.scope,
                request_id=command.subject_id,
                material_hash=command.material_hash,
                now=now,
            )
            with connection.transaction():
                if command.status is DeliveryCommandStatus.PREPARED:
                    if not commands.claim_for_issue(command_id=command.command_id):
                        raise DeliveryCommandError("rollout start command was already claimed")
                elif command.status is DeliveryCommandStatus.ISSUED:
                    commands.begin_reconciliation(command_id=command.command_id)
                elif command.status is not DeliveryCommandStatus.RECONCILING:
                    raise DeliveryCommandError("rollout start command is no longer recoverable")
                existing = store.start(
                    scope=command.scope,
                    candidate=candidate,
                    controller_identity=settings.service_principal,
                )
        elif command.status is DeliveryCommandStatus.PREPARED:
            if not commands.claim_for_issue(command_id=command.command_id):
                raise DeliveryCommandError("rollout start command was already claimed")
        elif command.status is DeliveryCommandStatus.ISSUED:
            commands.begin_reconciliation(command_id=command.command_id)
        elif command.status is not DeliveryCommandStatus.RECONCILING:
            raise DeliveryCommandError("rollout start command is no longer recoverable")
    operation_receipt = writer.put_json(
        object_name=f"deployment-rollouts/{existing.rollout_id}/created.json",
        value={
            "schema_version": 1,
            "rollout_id": existing.rollout_id,
            "code_change_request_id": command.subject_id,
            "start_material_hash": command.material_hash,
            "controller_identity": settings.service_principal,
            "controller_revision": settings.service_revision,
            "created_at": existing.created_at.isoformat(),
        },
    )
    return _complete_private_command(
        command_id=command.command_id,
        receipt_ref=operation_receipt.uri,
        receipt_hash=operation_receipt.content_hash,
        observed_at=existing.created_at,
        writer=writer,
    )


def _execute_prepare_canary(
    *, envelope: PrivateCommandEnvelope, caller: str, settings: DeploymentControllerSettings
) -> dict[str, Any]:
    now = datetime.now(UTC)
    session = authorized_session()
    reader = GcsEvidenceReader(
        allowed_buckets=frozenset({settings.runtime_bucket}), session=session
    )
    writer = GcsEvidenceWriter(bucket=settings.runtime_bucket, session=session)
    with connect_database() as connection:
        commands = PostgresDeliveryCommandStore(connection)
        command = commands.load(command_id=envelope.command_id, payload_reader=reader)
        command.validate_envelope(
            envelope,
            caller_identity=caller,
            audience_hash=sha256_bytes(settings.coordinator_audience.encode()),
            now=now,
        )
        prior = commands.load_terminal_response(
            command_id=command.command_id, payload_reader=reader
        )
        if prior is not None:
            return prior.model_dump(mode="json")
        if command.command_kind is not DeliveryCommandKind.PREPARE_CANARY:
            raise DeliveryCommandError("canary handler accepts only PREPARE_CANARY")
        store = PostgresReleaseRolloutStore(connection)
        with connection.transaction():
            store.prepare_canary_operation(
                scope=command.scope,
                rollout_id=command.subject_id,
                material_hash=command.material_hash,
                request_ref=command.payload_ref,
                request_hash=command.payload_hash,
            )
            if command.status is DeliveryCommandStatus.PREPARED:
                if not commands.claim_for_issue(command_id=command.command_id):
                    raise DeliveryCommandError("canary command was already claimed")
            elif command.status is DeliveryCommandStatus.ISSUED:
                commands.begin_reconciliation(command_id=command.command_id)
            elif command.status is not DeliveryCommandStatus.RECONCILING:
                raise DeliveryCommandError("canary command is no longer recoverable")
        completed = store.completed_operation(
            scope=command.scope,
            rollout_id=command.subject_id,
            operation_kind="PREPARE_CANARY",
            material_hash=command.material_hash,
        )
        if completed is None:
            material = store.load_canary(
                scope=command.scope,
                rollout_id=command.subject_id,
                material_hash=command.material_hash,
            )
    if completed is not None:
        return _complete_from_operation(
            command_id=command.command_id,
            operation=completed,
            reader=reader,
            writer=writer,
        )
    envelope_value = reader.get_json(
        uri=material.candidate_envelope_ref,
        expected_hash=material.candidate_envelope_hash,
        max_bytes=128_000,
    )
    candidate = ReleaseCandidateEnvelope.model_validate(envelope_value)
    verify_release_candidate(
        candidate,
        expected=ReleaseCandidateExpected(
            code_change_request_id=material.code_change_request_id,
            repository_binding_id=material.repository_binding_id,
            merged_commit_sha=material.merged_commit_sha,
            source_tree_hash=material.source_tree_hash,
            release_policy_hash=material.release_policy_hash,
            signer_identity=material.signer_identity,
            signer_key_version=material.signer_key_version,
            maximum_age_seconds=86400,
            now=now,
        ),
        evidence=reader,
        kms=GoogleKmsPublicKeyReader(session),
    )
    baseline_value = reader.get_json(
        uri=material.release_health_baseline_ref,
        expected_hash=material.release_health_baseline_hash,
        max_bytes=128_000,
    )
    baseline = ReleaseHealthSnapshot.model_validate(baseline_value)
    verify_release_health_snapshot(
        baseline,
        expected=ReleaseHealthSnapshotExpected(
            scope=command.scope,
            code_change_request_id=material.code_change_request_id,
            release_candidate_id=material.release_candidate_id,
            release_target_profile_id=material.release_target_profile_id,
            target_observation_hash=material.target_observation_hash,
            verification_profile_hash=material.verification_profile_hash,
            target_version=material.expected_target_version,
            target_assignment_hash=material.predeploy_assignment_hash,
            verifier_identity=material.verifier_identity,
            verifier_key_version=material.verifier_key_version,
        ),
        signature_ref=material.baseline_signature_ref,
        signature_hash=material.baseline_signature_hash,
        evidence=reader,
        kms=GoogleKmsPublicKeyReader(session),
    )
    profile = reader.get_json(
        uri=material.deployment_manifest_profile_ref,
        expected_hash=material.deployment_manifest_profile_hash,
        max_bytes=64_000,
    )
    deployment = reader.get_json(
        uri=candidate.deployment_manifest_ref,
        expected_hash=candidate.deployment_manifest_hash,
        max_bytes=64_000,
    )
    if set(deployment) != {"schema_version", "image", "container_name"} or (
        deployment.get("schema_version") != 1
        or deployment.get("image") != candidate.build_artifact_ref
        or deployment.get("container_name") != profile.get("allowed_container_name")
    ):
        raise DeliveryCommandError("candidate deployment manifest is not the approved shape")
    container_name = profile.get("allowed_container_name")
    if not isinstance(container_name, str):
        raise DeliveryCommandError("target container name is unavailable")
    client = CloudRunReleaseClient(
        session=session,
        service_resource_name=material.service_resource_name,
        runtime_service_account=material.runtime_service_account,
        container_name=container_name,
    )
    observed = client.observe()
    service_name = material.service_resource_name.rsplit("/", 1)[1]
    revision_name = f"{service_name[:34]}-sv-{material.release_candidate_id[-20:].lower()}"
    expected_traffic = tuple(
        sorted(
            (
                (revision_name, material.first_canary_percent),
                (material.predeploy_revision, 100 - material.first_canary_percent),
            )
        )
    )
    if material.operation_status == "PREPARED":
        if (
            str(observed.generation) != material.expected_target_version
            or observed.assignment_hash != material.predeploy_assignment_hash
        ):
            raise DeliveryCommandError("Cloud Run target changed after deployment approval")
        with connect_database() as connection, connection.transaction():
            if not PostgresReleaseRolloutStore(connection).claim_canary(
                scope=command.scope, operation_id=material.operation_id
            ):
                raise DeliveryCommandError("canary effect fence was already claimed")
        operation = client.prepare_canary(
            expected=observed,
            image=candidate.build_artifact_ref,
            revision_name=revision_name,
            canary_percent=material.first_canary_percent,
            predeploy_revision=material.predeploy_revision,
        )
        with connect_database() as connection, connection.transaction():
            PostgresReleaseRolloutStore(connection).record_provider_operation(
                scope=command.scope,
                operation_id=material.operation_id,
                provider_request_id=operation.name,
            )
        return {"command_id": command.command_id, "outcome": "RECONCILING"}
    provider_operation_name: str
    if material.provider_request_id is None:
        final = client.observe()
        if final.traffic != expected_traffic or final.image != candidate.build_artifact_ref:
            return _complete_ambiguous_operation(
                command_id=command.command_id,
                scope=command.scope,
                rollout_id=material.rollout_id,
                operation_id=material.operation_id,
                operation_kind="PREPARE_CANARY",
                error_class="PROVIDER_HANDLE_LOST_TARGET_NOT_EXACT",
                provider_operation_name=None,
                observed=final,
                writer=writer,
                controller_identity=settings.service_principal,
            )
        with connect_database() as connection, connection.transaction():
            effect_observed_at = PostgresReleaseRolloutStore(
                connection
            ).begin_reconciliation_without_provider_handle(
                scope=command.scope, operation_id=material.operation_id
            )
        provider_operation_name = "cloud-run-operation-name-unavailable"
    else:
        operation = client.operation(material.provider_request_id)
        if not operation.done:
            return {"command_id": command.command_id, "outcome": "RECONCILING"}
        if operation.error_code is not None:
            return _complete_ambiguous_operation(
                command_id=command.command_id,
                scope=command.scope,
                rollout_id=material.rollout_id,
                operation_id=material.operation_id,
                operation_kind="PREPARE_CANARY",
                error_class="PROVIDER_OPERATION_FAILED_AFTER_ISSUE",
                provider_operation_name=operation.name,
                observed=observed,
                writer=writer,
                controller_identity=settings.service_principal,
            )
        final = client.observe()
        if material.operation_reconciled_at is None:
            raise DeliveryCommandError("canary reconciliation has no durable start time")
        effect_observed_at = material.operation_reconciled_at
        provider_operation_name = operation.name
    if final.traffic != expected_traffic or final.image != candidate.build_artifact_ref:
        return _complete_ambiguous_operation(
            command_id=command.command_id,
            scope=command.scope,
            rollout_id=material.rollout_id,
            operation_id=material.operation_id,
            operation_kind="PREPARE_CANARY",
            error_class="PROVIDER_RESULT_TARGET_NOT_EXACT",
            provider_operation_name=provider_operation_name,
            observed=final,
            writer=writer,
            controller_identity=settings.service_principal,
        )
    receipt = writer.put_json(
        object_name=f"deployment-rollouts/{material.rollout_id}/prepare-canary.json",
        value={
            "schema_version": 1,
            "rollout_id": material.rollout_id,
            "operation_id": material.operation_id,
            "provider_operation_name": provider_operation_name,
            "target_profile_hash": material.target_profile_hash,
            "pre_generation": material.expected_target_version,
            "post_generation": final.generation,
            "expected_traffic_hash": canonical_sha256([list(item) for item in expected_traffic]),
            "observed_traffic_hash": canonical_sha256([list(item) for item in final.traffic]),
            "observed_at": effect_observed_at.isoformat(),
        },
    )
    with connect_database() as connection, connection.transaction():
        PostgresReleaseRolloutStore(connection).complete_canary(
            scope=command.scope,
            operation_id=material.operation_id,
            response_ref=receipt.uri,
            response_hash=receipt.content_hash,
            controller_identity=settings.service_principal,
        )
    return _complete_private_command(
        command_id=command.command_id,
        receipt_ref=receipt.uri,
        receipt_hash=receipt.content_hash,
        observed_at=effect_observed_at,
        writer=writer,
    )


def _verify_advancement_receipt(
    *,
    material: Any,
    scope: Scope,
    reader: GcsEvidenceReader,
    session: Any,
) -> ReleaseEffectReceiptEnvelope:
    candidate = material.candidate
    value = reader.get_json(
        uri=candidate.receipt_envelope_ref,
        expected_hash=candidate.receipt_envelope_hash,
        max_bytes=128_000,
    )
    receipt = ReleaseEffectReceiptEnvelope.model_validate(value)
    verify_release_effect_receipt(
        receipt,
        expected=ReleaseEffectReceiptExpected(
            scope=scope,
            deployment_rollout_id=candidate.rollout_id,
            stage_ordinal=candidate.current_stage_ordinal,
            observation_window_generation=1,
            verification_profile_hash=candidate.verification_profile_hash,
            release_health_baseline_hash=candidate.release_health_baseline_hash,
            predeploy_snapshot_hash=candidate.predeploy_snapshot_hash,
            intended_effect_hash=candidate.intended_effect_hash,
            verifier_identity=candidate.verifier_identity,
            verifier_key_version=candidate.verifier_key_version,
        ),
        signature_ref=candidate.signature_ref,
        signature_hash=candidate.signature_hash,
        evidence=reader,
        kms=GoogleKmsPublicKeyReader(session),
    )
    if receipt.result.value != "VERIFIED":
        raise DeliveryCommandError("rollout advancement requires a verified receipt")
    return receipt


def _release_client_for_advancement(
    *, material: Any, reader: GcsEvidenceReader, session: Any
) -> CloudRunReleaseClient:
    profile = reader.get_json(
        uri=material.deployment_manifest_profile_ref,
        expected_hash=material.deployment_manifest_profile_hash,
        max_bytes=64_000,
    )
    container_name = profile.get("allowed_container_name")
    if not isinstance(container_name, str):
        raise DeliveryCommandError("release target manifest profile is malformed")
    return CloudRunReleaseClient(
        session=session,
        service_resource_name=material.service_resource_name,
        runtime_service_account=material.runtime_service_account,
        container_name=container_name,
    )


def _execute_promote_canary(
    *, envelope: PrivateCommandEnvelope, caller: str, settings: DeploymentControllerSettings
) -> dict[str, Any]:
    now = datetime.now(UTC)
    session = authorized_session()
    reader = GcsEvidenceReader(
        allowed_buckets=frozenset({settings.runtime_bucket}), session=session
    )
    writer = GcsEvidenceWriter(bucket=settings.runtime_bucket, session=session)
    with connect_database() as connection:
        commands = PostgresDeliveryCommandStore(connection)
        command = commands.load(command_id=envelope.command_id, payload_reader=reader)
        command.validate_envelope(
            envelope,
            caller_identity=caller,
            audience_hash=sha256_bytes(settings.coordinator_audience.encode()),
            now=now,
        )
        prior = commands.load_terminal_response(
            command_id=command.command_id, payload_reader=reader
        )
        if prior is not None:
            return prior.model_dump(mode="json")
        if command.command_kind is not DeliveryCommandKind.PROMOTE_CANARY:
            raise DeliveryCommandError("promotion handler accepts only PROMOTE_CANARY")
        store = PostgresReleaseRolloutStore(connection)
        if command.status is DeliveryCommandStatus.PREPARED:
            candidate = store.candidate_for_advancement(
                scope=command.scope,
                rollout_id=command.subject_id,
                material_hash=command.material_hash,
                now=now,
            )
            if command.payload != {"prior_canary_receipt_hash": candidate.receipt_envelope_hash}:
                raise DeliveryCommandError("promotion command receipt binding differs")
            receipt_value = reader.get_json(
                uri=candidate.receipt_envelope_ref,
                expected_hash=candidate.receipt_envelope_hash,
                max_bytes=128_000,
            )
            receipt = ReleaseEffectReceiptEnvelope.model_validate(receipt_value)
            verify_release_effect_receipt(
                receipt,
                expected=ReleaseEffectReceiptExpected(
                    scope=command.scope,
                    deployment_rollout_id=candidate.rollout_id,
                    stage_ordinal=candidate.current_stage_ordinal,
                    observation_window_generation=1,
                    verification_profile_hash=candidate.verification_profile_hash,
                    release_health_baseline_hash=candidate.release_health_baseline_hash,
                    predeploy_snapshot_hash=candidate.predeploy_snapshot_hash,
                    intended_effect_hash=candidate.intended_effect_hash,
                    verifier_identity=candidate.verifier_identity,
                    verifier_key_version=candidate.verifier_key_version,
                ),
                signature_ref=candidate.signature_ref,
                signature_hash=candidate.signature_hash,
                evidence=reader,
                kms=GoogleKmsPublicKeyReader(session),
            )
            if receipt.result.value != "VERIFIED":
                raise DeliveryCommandError("promotion requires verified release effect")
            with connection.transaction():
                store.prepare_promotion_operation(
                    scope=command.scope,
                    candidate=candidate,
                    request_ref=command.payload_ref,
                    request_hash=command.payload_hash,
                )
                if not commands.claim_for_issue(command_id=command.command_id):
                    raise DeliveryCommandError("promotion command was already claimed")
        elif command.status is DeliveryCommandStatus.ISSUED:
            commands.begin_reconciliation(command_id=command.command_id)
        elif command.status is not DeliveryCommandStatus.RECONCILING:
            raise DeliveryCommandError("promotion command is no longer recoverable")
        completed = store.completed_operation(
            scope=command.scope,
            rollout_id=command.subject_id,
            operation_kind="PROMOTE_CANARY",
            material_hash=command.material_hash,
        )
        if completed is None:
            material = store.load_promotion(
                scope=command.scope,
                rollout_id=command.subject_id,
                material_hash=command.material_hash,
            )
    if completed is not None:
        return _complete_from_operation(
            command_id=command.command_id,
            operation=completed,
            reader=reader,
            writer=writer,
        )
    _verify_advancement_receipt(
        material=material, scope=command.scope, reader=reader, session=session
    )
    client = _release_client_for_advancement(material=material, reader=reader, session=session)
    observed = client.observe()
    if material.operation_id is None or material.expected_next_assignment is None:
        raise DeliveryCommandError("promotion operation material is incomplete")
    if material.operation_status == "PREPARED":
        if (
            observed.traffic != material.expected_current_assignment
            or observed.image != material.build_artifact_ref
        ):
            raise DeliveryCommandError("Cloud Run target changed before promotion")
        with connect_database() as connection, connection.transaction():
            if not PostgresReleaseRolloutStore(connection).claim_canary(
                scope=command.scope, operation_id=material.operation_id
            ):
                raise DeliveryCommandError("promotion effect fence was already claimed")
        operation = client.set_traffic(
            expected=observed, assignments=material.expected_next_assignment
        )
        with connect_database() as connection, connection.transaction():
            PostgresReleaseRolloutStore(connection).record_provider_operation(
                scope=command.scope,
                operation_id=material.operation_id,
                provider_request_id=operation.name,
            )
        return {"command_id": command.command_id, "outcome": "RECONCILING"}
    if material.provider_request_id is None:
        final = client.observe()
        if (
            final.traffic != material.expected_next_assignment
            or final.image != material.build_artifact_ref
        ):
            return _complete_ambiguous_operation(
                command_id=command.command_id,
                scope=command.scope,
                rollout_id=material.candidate.rollout_id,
                operation_id=material.operation_id,
                operation_kind="PROMOTE_CANARY",
                error_class="PROVIDER_HANDLE_LOST_TARGET_NOT_EXACT",
                provider_operation_name=None,
                observed=final,
                writer=writer,
                controller_identity=settings.service_principal,
            )
        with connect_database() as connection, connection.transaction():
            effect_observed_at = PostgresReleaseRolloutStore(
                connection
            ).begin_reconciliation_without_provider_handle(
                scope=command.scope, operation_id=material.operation_id
            )
        provider_operation_name = "cloud-run-operation-name-unavailable"
    else:
        operation = client.operation(material.provider_request_id)
        if not operation.done:
            return {"command_id": command.command_id, "outcome": "RECONCILING"}
        if operation.error_code is not None:
            return _complete_ambiguous_operation(
                command_id=command.command_id,
                scope=command.scope,
                rollout_id=material.candidate.rollout_id,
                operation_id=material.operation_id,
                operation_kind="PROMOTE_CANARY",
                error_class="PROVIDER_OPERATION_FAILED_AFTER_ISSUE",
                provider_operation_name=operation.name,
                observed=observed,
                writer=writer,
                controller_identity=settings.service_principal,
            )
        if material.operation_reconciled_at is None:
            raise DeliveryCommandError("promotion reconciliation has no durable start time")
        effect_observed_at = material.operation_reconciled_at
        final = client.observe()
        provider_operation_name = operation.name
    if (
        final.traffic != material.expected_next_assignment
        or final.image != material.build_artifact_ref
    ):
        return _complete_ambiguous_operation(
            command_id=command.command_id,
            scope=command.scope,
            rollout_id=material.candidate.rollout_id,
            operation_id=material.operation_id,
            operation_kind="PROMOTE_CANARY",
            error_class="PROVIDER_RESULT_TARGET_NOT_EXACT",
            provider_operation_name=provider_operation_name,
            observed=final,
            writer=writer,
            controller_identity=settings.service_principal,
        )
    operation_receipt = writer.put_json(
        object_name=(
            f"deployment-rollouts/{material.candidate.rollout_id}/"
            f"promote-{material.candidate.next_stage_ordinal}.json"
        ),
        value={
            "schema_version": 1,
            "rollout_id": material.candidate.rollout_id,
            "stage_ordinal": material.candidate.next_stage_ordinal,
            "operation_id": material.operation_id,
            "provider_operation_name": provider_operation_name,
            "target_profile_hash": material.release_target_profile_hash,
            "observed_traffic_hash": canonical_sha256([list(item) for item in final.traffic]),
            "observed_at": effect_observed_at.isoformat(),
        },
    )
    with connect_database() as connection, connection.transaction():
        PostgresReleaseRolloutStore(connection).complete_canary(
            scope=command.scope,
            operation_id=material.operation_id,
            response_ref=operation_receipt.uri,
            response_hash=operation_receipt.content_hash,
            controller_identity=settings.service_principal,
        )
    return _complete_private_command(
        command_id=command.command_id,
        receipt_ref=operation_receipt.uri,
        receipt_hash=operation_receipt.content_hash,
        observed_at=effect_observed_at,
        writer=writer,
    )


def _execute_finalize_rollout(
    *, envelope: PrivateCommandEnvelope, caller: str, settings: DeploymentControllerSettings
) -> dict[str, Any]:
    now = datetime.now(UTC)
    session = authorized_session()
    reader = GcsEvidenceReader(
        allowed_buckets=frozenset({settings.runtime_bucket}), session=session
    )
    writer = GcsEvidenceWriter(bucket=settings.runtime_bucket, session=session)
    with connect_database() as connection:
        commands = PostgresDeliveryCommandStore(connection)
        command = commands.load(command_id=envelope.command_id, payload_reader=reader)
        command.validate_envelope(
            envelope,
            caller_identity=caller,
            audience_hash=sha256_bytes(settings.coordinator_audience.encode()),
            now=now,
        )
        prior = commands.load_terminal_response(
            command_id=command.command_id, payload_reader=reader
        )
        if prior is not None:
            return prior.model_dump(mode="json")
        if command.command_kind is not DeliveryCommandKind.FINALIZE_ROLLOUT:
            raise DeliveryCommandError("finalization handler accepts only FINALIZE_ROLLOUT")
        store = PostgresReleaseRolloutStore(connection)
        material = store.load_finalization(
            scope=command.scope,
            rollout_id=command.subject_id,
            material_hash=command.material_hash,
            now=now,
        )
        if command.payload != {
            "final_verification_receipt_hash": (material.candidate.receipt_envelope_hash)
        }:
            raise DeliveryCommandError("finalization receipt binding differs")
    _verify_advancement_receipt(
        material=material, scope=command.scope, reader=reader, session=session
    )
    observed = _release_client_for_advancement(
        material=material, reader=reader, session=session
    ).observe()
    if (
        observed.traffic != material.expected_current_assignment
        or observed.image != material.build_artifact_ref
    ):
        raise DeliveryCommandError("Cloud Run target changed before finalization")
    with connect_database() as connection, connection.transaction():
        commands = PostgresDeliveryCommandStore(connection)
        if command.status is DeliveryCommandStatus.PREPARED:
            if not commands.claim_for_issue(command_id=command.command_id):
                raise DeliveryCommandError("finalization command was already claimed")
        elif command.status is DeliveryCommandStatus.ISSUED:
            commands.begin_reconciliation(command_id=command.command_id)
        elif command.status is not DeliveryCommandStatus.RECONCILING:
            raise DeliveryCommandError("finalization command is no longer recoverable")
        PostgresReleaseRolloutStore(connection).finalize_rollout(
            scope=command.scope, candidate=material.candidate
        )
    receipt = writer.put_json(
        object_name=f"deployment-rollouts/{material.candidate.rollout_id}/promoted.json",
        value={
            "schema_version": 1,
            "rollout_id": material.candidate.rollout_id,
            "final_verification_receipt_hash": (material.candidate.receipt_envelope_hash),
            "observed_target_version": str(observed.generation),
            "observed_assignment_hash": observed.assignment_hash,
            "controller_identity": settings.service_principal,
            "controller_revision": settings.service_revision,
            "observed_at": material.candidate.receipt_observed_at.isoformat(),
        },
    )
    return _complete_private_command(
        command_id=command.command_id,
        receipt_ref=receipt.uri,
        receipt_hash=receipt.content_hash,
        observed_at=material.candidate.receipt_observed_at,
        writer=writer,
    )


def _execute_register_verification_failure(
    *, envelope: PrivateCommandEnvelope, caller: str, settings: DeploymentControllerSettings
) -> dict[str, Any]:
    now = datetime.now(UTC)
    session = authorized_session()
    reader = GcsEvidenceReader(
        allowed_buckets=frozenset({settings.runtime_bucket}), session=session
    )
    writer = GcsEvidenceWriter(bucket=settings.runtime_bucket, session=session)
    with connect_database() as connection:
        commands = PostgresDeliveryCommandStore(connection)
        command = commands.load(command_id=envelope.command_id, payload_reader=reader)
        command.validate_envelope(
            envelope,
            caller_identity=caller,
            audience_hash=sha256_bytes(settings.coordinator_audience.encode()),
            now=now,
        )
        prior = commands.load_terminal_response(
            command_id=command.command_id, payload_reader=reader
        )
        if prior is not None:
            return prior.model_dump(mode="json")
        if command.command_kind is not DeliveryCommandKind.REGISTER_VERIFICATION_FAILURE:
            raise DeliveryCommandError("failure handler accepts only its exact command")
        matches = tuple(
            item
            for item in PostgresReleaseRolloutStore(connection).failure_candidates(
                scope=command.scope, now=now, include_dispatched=True
            )
            if item.rollout_id == command.subject_id and item.material_hash == command.material_hash
        )
        if len(matches) != 1:
            raise DeliveryCommandError("failed verification authority is stale")
        candidate = matches[0]
    value = reader.get_json(
        uri=candidate.receipt_envelope_ref,
        expected_hash=candidate.receipt_envelope_hash,
        max_bytes=128_000,
    )
    receipt = ReleaseEffectReceiptEnvelope.model_validate(value)
    verify_release_effect_receipt(
        receipt,
        expected=ReleaseEffectReceiptExpected(
            scope=command.scope,
            deployment_rollout_id=candidate.rollout_id,
            stage_ordinal=candidate.current_stage_ordinal,
            observation_window_generation=1,
            verification_profile_hash=candidate.verification_profile_hash,
            release_health_baseline_hash=candidate.release_health_baseline_hash,
            predeploy_snapshot_hash=candidate.predeploy_snapshot_hash,
            intended_effect_hash=candidate.intended_effect_hash,
            verifier_identity=candidate.verifier_identity,
            verifier_key_version=candidate.verifier_key_version,
        ),
        signature_ref=candidate.signature_ref,
        signature_hash=candidate.signature_hash,
        evidence=reader,
        kms=GoogleKmsPublicKeyReader(session),
    )
    if receipt.result.value == "VERIFIED" or command.payload != {
        "failed_verification_receipt_hash": candidate.receipt_envelope_hash
    }:
        raise DeliveryCommandError("verification failure registration material differs")
    state_receipt = writer.put_json(
        object_name=(
            f"deployment-rollouts/{candidate.rollout_id}/"
            f"verification-failed-{candidate.current_stage_ordinal}.json"
        ),
        value={
            "schema_version": 1,
            "rollout_id": candidate.rollout_id,
            "stage_ordinal": candidate.current_stage_ordinal,
            "verification_receipt_hash": candidate.receipt_envelope_hash,
            "result": receipt.result.value,
            "controller_identity": settings.service_principal,
            "recorded_at": receipt.observed_at.isoformat(),
        },
    )
    response = PrivateCommandResponse(
        command_id=command.command_id,
        outcome=DeliveryOutcome.ACCEPTED,
        reason_code=DeliveryReasonCode.OPERATION_COMPLETED,
        receipt_ref=state_receipt.uri,
        receipt_hash=state_receipt.content_hash,
        observed_at=receipt.observed_at,
    )
    response_receipt = writer.put_json(
        object_name=f"private-command-responses/{command.command_id}.json",
        value=response.model_dump(mode="json"),
    )
    with connect_database() as connection, connection.transaction():
        commands = PostgresDeliveryCommandStore(connection)
        if not commands.claim_for_issue(command_id=command.command_id):
            raise DeliveryCommandError("failure registration command was already claimed")
        PostgresReleaseRolloutStore(connection).register_verification_failure(
            scope=command.scope, candidate=candidate
        )
        commands.complete(
            response,
            response_ref=response_receipt.uri,
            response_hash=response_receipt.content_hash,
        )
    return response.model_dump(mode="json")


def _execute_rollback_release(
    *, envelope: PrivateCommandEnvelope, caller: str, settings: DeploymentControllerSettings
) -> dict[str, Any]:
    now = datetime.now(UTC)
    session = authorized_session()
    reader = GcsEvidenceReader(
        allowed_buckets=frozenset({settings.runtime_bucket}), session=session
    )
    writer = GcsEvidenceWriter(bucket=settings.runtime_bucket, session=session)
    with connect_database() as connection:
        commands = PostgresDeliveryCommandStore(connection)
        command = commands.load(command_id=envelope.command_id, payload_reader=reader)
        command.validate_envelope(
            envelope,
            caller_identity=caller,
            audience_hash=sha256_bytes(settings.coordinator_audience.encode()),
            now=now,
        )
        prior = commands.load_terminal_response(
            command_id=command.command_id, payload_reader=reader
        )
        if prior is not None:
            return prior.model_dump(mode="json")
        if command.command_kind is not DeliveryCommandKind.ROLLBACK_RELEASE:
            raise DeliveryCommandError("rollback handler accepts only ROLLBACK_RELEASE")
        store = PostgresReleaseRolloutStore(connection)
        if command.status is DeliveryCommandStatus.PREPARED:
            matches = tuple(
                item
                for item in store.rollback_candidates(
                    scope=command.scope, now=now, include_dispatched=True
                )
                if item.rollout_id == command.subject_id
                and item.material_hash == command.material_hash
            )
            if len(matches) != 1 or command.payload:
                raise DeliveryCommandError("approved rollback authority is stale")
            with connection.transaction():
                store.prepare_rollback_operation(
                    scope=command.scope,
                    candidate=matches[0],
                    request_ref=command.payload_ref,
                    request_hash=command.payload_hash,
                    controller_identity=settings.service_principal,
                )
                if not commands.claim_for_issue(command_id=command.command_id):
                    raise DeliveryCommandError("rollback command was already claimed")
        elif command.status is DeliveryCommandStatus.ISSUED:
            commands.begin_reconciliation(command_id=command.command_id)
        elif command.status is not DeliveryCommandStatus.RECONCILING:
            raise DeliveryCommandError("rollback command is no longer recoverable")
        completed = store.completed_operation(
            scope=command.scope,
            rollout_id=command.subject_id,
            operation_kind="ROLLBACK_RELEASE",
            material_hash=command.material_hash,
        )
        if completed is None:
            material = store.load_rollback(
                scope=command.scope,
                rollout_id=command.subject_id,
                material_hash=command.material_hash,
            )
    if completed is not None:
        return _complete_from_operation(
            command_id=command.command_id,
            operation=completed,
            reader=reader,
            writer=writer,
        )
    profile = reader.get_json(
        uri=material.deployment_manifest_profile_ref,
        expected_hash=material.deployment_manifest_profile_hash,
        max_bytes=64_000,
    )
    container_name = profile.get("allowed_container_name")
    if not isinstance(container_name, str):
        raise DeliveryCommandError("release target manifest profile is malformed")
    client = CloudRunReleaseClient(
        session=session,
        service_resource_name=material.service_resource_name,
        runtime_service_account=material.runtime_service_account,
        container_name=container_name,
    )
    observed = client.observe()
    expected_assignment = ((material.rollback_revision, 100),)
    if material.operation_status == "PREPARED":
        if (
            str(observed.generation) != material.expected_target_version
            or observed.assignment_hash != material.expected_assignment_hash
        ):
            raise DeliveryCommandError("Cloud Run target changed after rollback approval")
        with connect_database() as connection, connection.transaction():
            if not PostgresReleaseRolloutStore(connection).claim_canary(
                scope=command.scope, operation_id=material.operation_id
            ):
                raise DeliveryCommandError("rollback effect fence was already claimed")
        operation = client.set_traffic(expected=observed, assignments=expected_assignment)
        with connect_database() as connection, connection.transaction():
            PostgresReleaseRolloutStore(connection).record_provider_operation(
                scope=command.scope,
                operation_id=material.operation_id,
                provider_request_id=operation.name,
            )
        return {"command_id": command.command_id, "outcome": "RECONCILING"}
    if material.provider_request_id is None:
        final = client.observe()
        if final.traffic != expected_assignment:
            return _complete_ambiguous_operation(
                command_id=command.command_id,
                scope=command.scope,
                rollout_id=material.candidate.rollout_id,
                operation_id=material.operation_id,
                operation_kind="ROLLBACK_RELEASE",
                error_class="PROVIDER_HANDLE_LOST_TARGET_NOT_EXACT",
                provider_operation_name=None,
                observed=final,
                writer=writer,
                controller_identity=settings.service_principal,
            )
        with connect_database() as connection, connection.transaction():
            effect_observed_at = PostgresReleaseRolloutStore(
                connection
            ).begin_reconciliation_without_provider_handle(
                scope=command.scope, operation_id=material.operation_id
            )
        provider_operation_name = "cloud-run-operation-name-unavailable"
    else:
        operation = client.operation(material.provider_request_id)
        if not operation.done:
            return {"command_id": command.command_id, "outcome": "RECONCILING"}
        if operation.error_code is not None:
            return _complete_ambiguous_operation(
                command_id=command.command_id,
                scope=command.scope,
                rollout_id=material.candidate.rollout_id,
                operation_id=material.operation_id,
                operation_kind="ROLLBACK_RELEASE",
                error_class="PROVIDER_OPERATION_FAILED_AFTER_ISSUE",
                provider_operation_name=operation.name,
                observed=observed,
                writer=writer,
                controller_identity=settings.service_principal,
            )
        if material.operation_reconciled_at is None:
            raise DeliveryCommandError("rollback reconciliation has no durable start time")
        effect_observed_at = material.operation_reconciled_at
        final = client.observe()
        provider_operation_name = operation.name
    if final.traffic != expected_assignment:
        return _complete_ambiguous_operation(
            command_id=command.command_id,
            scope=command.scope,
            rollout_id=material.candidate.rollout_id,
            operation_id=material.operation_id,
            operation_kind="ROLLBACK_RELEASE",
            error_class="PROVIDER_RESULT_TARGET_NOT_EXACT",
            provider_operation_name=provider_operation_name,
            observed=final,
            writer=writer,
            controller_identity=settings.service_principal,
        )
    effect_receipt = writer.put_json(
        object_name=f"deployment-rollouts/{material.candidate.rollout_id}/rollback-effect.json",
        value={
            "schema_version": 1,
            "rollout_id": material.candidate.rollout_id,
            "operation_id": material.operation_id,
            "provider_operation_name": provider_operation_name,
            "rollback_revision": material.rollback_revision,
            "observed_target_version": str(final.generation),
            "observed_assignment_hash": final.assignment_hash,
            "observed_at": effect_observed_at.isoformat(),
        },
    )
    with connect_database() as connection, connection.transaction():
        PostgresReleaseRolloutStore(connection).complete_rollback_effect(
            scope=command.scope,
            operation_id=material.operation_id,
            response_ref=effect_receipt.uri,
            response_hash=effect_receipt.content_hash,
        )
    return _complete_private_command(
        command_id=command.command_id,
        receipt_ref=effect_receipt.uri,
        receipt_hash=effect_receipt.content_hash,
        observed_at=effect_observed_at,
        writer=writer,
    )


def _execute_finalize_rollback(
    *, envelope: PrivateCommandEnvelope, caller: str, settings: DeploymentControllerSettings
) -> dict[str, Any]:
    now = datetime.now(UTC)
    session = authorized_session()
    reader = GcsEvidenceReader(
        allowed_buckets=frozenset({settings.runtime_bucket}), session=session
    )
    writer = GcsEvidenceWriter(bucket=settings.runtime_bucket, session=session)
    with connect_database() as connection:
        commands = PostgresDeliveryCommandStore(connection)
        command = commands.load(command_id=envelope.command_id, payload_reader=reader)
        command.validate_envelope(
            envelope,
            caller_identity=caller,
            audience_hash=sha256_bytes(settings.coordinator_audience.encode()),
            now=now,
        )
        prior = commands.load_terminal_response(
            command_id=command.command_id, payload_reader=reader
        )
        if prior is not None:
            return prior.model_dump(mode="json")
        matches = tuple(
            item
            for item in PostgresReleaseRolloutStore(connection).rollback_finalization_candidates(
                scope=command.scope, now=now, include_dispatched=True
            )
            if item.rollout_id == command.subject_id and item.material_hash == command.material_hash
        )
        if len(matches) != 1:
            raise DeliveryCommandError("rollback finalization authority is stale")
        candidate = matches[0]
    value = reader.get_json(
        uri=candidate.receipt_envelope_ref,
        expected_hash=candidate.receipt_envelope_hash,
        max_bytes=64_000,
    )
    receipt = ReleaseRollbackReceiptEnvelope.model_validate(value)
    verify_release_rollback_receipt(
        receipt,
        scope=command.scope,
        rollout_id=candidate.rollout_id,
        expected_revision=candidate.expected_revision,
        verifier_identity=candidate.verifier_identity,
        verifier_key_version=candidate.verifier_key_version,
        signature_ref=candidate.signature_ref,
        signature_hash=candidate.signature_hash,
        evidence=reader,
        kms=GoogleKmsPublicKeyReader(session),
    )
    if receipt.result.value != "VERIFIED" or command.payload != {
        "rollback_verification_receipt_hash": candidate.receipt_envelope_hash
    }:
        raise DeliveryCommandError("rollback finalization receipt differs")
    state_receipt = writer.put_json(
        object_name=f"deployment-rollouts/{candidate.rollout_id}/rolled-back.json",
        value={
            "schema_version": 1,
            "rollout_id": candidate.rollout_id,
            "rollback_verification_receipt_hash": candidate.receipt_envelope_hash,
            "controller_identity": settings.service_principal,
            "recorded_at": candidate.receipt_observed_at.isoformat(),
        },
    )
    response = PrivateCommandResponse(
        command_id=command.command_id,
        outcome=DeliveryOutcome.ACCEPTED,
        reason_code=DeliveryReasonCode.OPERATION_COMPLETED,
        receipt_ref=state_receipt.uri,
        receipt_hash=state_receipt.content_hash,
        observed_at=candidate.receipt_observed_at,
    )
    response_receipt = writer.put_json(
        object_name=f"private-command-responses/{command.command_id}.json",
        value=response.model_dump(mode="json"),
    )
    with connect_database() as connection, connection.transaction():
        commands = PostgresDeliveryCommandStore(connection)
        if not commands.claim_for_issue(command_id=command.command_id):
            raise DeliveryCommandError("rollback finalization was already claimed")
        PostgresReleaseRolloutStore(connection).finalize_rollback(
            scope=command.scope, candidate=candidate, controller_identity=settings.service_principal
        )
        commands.complete(
            response, response_ref=response_receipt.uri, response_hash=response_receipt.content_hash
        )
    return response.model_dump(mode="json")


def _complete_private_command(
    *,
    command_id: str,
    receipt_ref: str,
    receipt_hash: str,
    observed_at: datetime,
    writer: GcsEvidenceWriter,
) -> dict[str, Any]:
    response = PrivateCommandResponse(
        command_id=command_id,
        outcome=DeliveryOutcome.ACCEPTED,
        reason_code=DeliveryReasonCode.OPERATION_COMPLETED,
        receipt_ref=receipt_ref,
        receipt_hash=receipt_hash,
        observed_at=observed_at,
    )
    stored = writer.put_json(
        object_name=f"private-command-responses/{command_id}.json",
        value=response.model_dump(mode="json"),
    )
    with connect_database() as connection, connection.transaction():
        PostgresDeliveryCommandStore(connection).complete(
            response, response_ref=stored.uri, response_hash=stored.content_hash
        )
    return response.model_dump(mode="json")


def _complete_ambiguous_operation(
    *,
    command_id: str,
    scope: Scope,
    rollout_id: str,
    operation_id: str,
    operation_kind: str,
    error_class: str,
    provider_operation_name: str | None,
    observed: ReleaseTargetObservation,
    writer: GcsEvidenceWriter,
    controller_identity: str,
) -> dict[str, Any]:
    """Terminally fence an unknowable post-issue effect and preserve evidence."""

    observed_at = datetime.now(UTC)
    document = {
        "schema_version": 1,
        "rollout_id": rollout_id,
        "operation_id": operation_id,
        "operation_kind": operation_kind,
        "error_class": error_class,
        "provider_operation_name": provider_operation_name,
        "observed_target": {
            "resource_name": observed.resource_name,
            "generation": observed.generation,
            "image": observed.image,
            "latest_ready_revision": observed.latest_ready_revision,
            "traffic": [list(item) for item in observed.traffic],
            "assignment_hash": observed.assignment_hash,
        },
        "observed_at": observed_at.isoformat(),
    }
    document_hash = canonical_sha256(document).removeprefix("sha256:")
    receipt = writer.put_json(
        object_name=(
            f"deployment-rollouts/{rollout_id}/ambiguity/{operation_id}-{document_hash}.json"
        ),
        value=document,
    )
    response = PrivateCommandResponse(
        command_id=command_id,
        outcome=DeliveryOutcome.AMBIGUOUS,
        reason_code=DeliveryReasonCode.EXTERNAL_STATE_AMBIGUOUS,
        receipt_ref=receipt.uri,
        receipt_hash=receipt.content_hash,
        observed_at=observed_at,
    )
    response_hash = canonical_sha256(response.model_dump(mode="json")).removeprefix("sha256:")
    stored = writer.put_json(
        object_name=f"private-command-responses/{command_id}/{response_hash}.json",
        value=response.model_dump(mode="json"),
    )
    with connect_database() as connection, connection.transaction():
        PostgresReleaseRolloutStore(connection).mark_operation_ambiguous(
            scope=scope,
            operation_id=operation_id,
            response_ref=receipt.uri,
            response_hash=receipt.content_hash,
            error_class=error_class,
            controller_identity=controller_identity,
        )
        PostgresDeliveryCommandStore(connection).complete(
            response, response_ref=stored.uri, response_hash=stored.content_hash
        )
    return response.model_dump(mode="json")


def _complete_from_operation(
    *,
    command_id: str,
    operation: Any,
    reader: GcsEvidenceReader,
    writer: GcsEvidenceWriter,
) -> dict[str, Any]:
    value = reader.get_json(
        uri=operation.response_ref,
        expected_hash=operation.response_hash,
        max_bytes=64_000,
    )
    observed_at_value = value.get("observed_at")
    if not isinstance(observed_at_value, str):
        raise DeliveryCommandError("completed operation receipt has no observation time")
    try:
        observed_at = datetime.fromisoformat(observed_at_value)
    except ValueError as error:
        raise DeliveryCommandError("completed operation receipt time is malformed") from error
    if observed_at.tzinfo is None:
        raise DeliveryCommandError("completed operation receipt time is not timezone-aware")
    return _complete_private_command(
        command_id=command_id,
        receipt_ref=operation.response_ref,
        receipt_hash=operation.response_hash,
        observed_at=observed_at,
        writer=writer,
    )


app = create_app()
