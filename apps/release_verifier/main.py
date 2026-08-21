"""Private independent baseline and release-effect verifier."""

from __future__ import annotations

import hashlib
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
from solvan.application.release_authority import ReleaseVerificationProfile
from solvan.application.release_verification import (
    ReleaseEffectReceiptEnvelope,
    ReleaseHealthSnapshot,
    ReleaseHealthSnapshotExpected,
    ReleaseRollbackReceiptEnvelope,
    ReleaseVerificationEvaluation,
    ReleaseVerificationResult,
    evaluate_release_health,
    verify_release_health_snapshot,
)
from solvan.application.workspace_hashing import canonical_sha256, sha256_bytes
from solvan.domain import Scope
from solvan.observability import instrument_fastapi
from solvan.persistence.delivery_command_store import PostgresDeliveryCommandStore
from solvan.persistence.release_effect_verification_store import (
    PostgresReleaseEffectVerificationStore,
)
from solvan.persistence.release_health_baseline_store import (
    PostgresReleaseHealthBaselineStore,
)
from solvan.persistence.release_rollback_verification_store import (
    PostgresReleaseRollbackVerificationStore,
)
from solvan.platform.cloud_run_health import CloudRunHealthReader
from solvan.platform.cloud_run_observer import CloudRunServiceObserver
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.google_rest import authorized_session
from solvan.platform.relay_signing import GoogleKmsSigner
from solvan.platform.workspace_attestation import GoogleKmsPublicKeyReader


class ReleaseVerifierSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: Scope
    audience: str = Field(pattern=r"^https://")
    coordinator_principal: str = Field(min_length=3)
    runtime_bucket: str = Field(min_length=3)
    service_principal: str = Field(min_length=3)
    signing_key_version: str = Field(pattern=r"^projects/.+/cryptoKeyVersions/[1-9][0-9]*$")
    service_revision: str = Field(min_length=1)

    @classmethod
    def from_env(cls) -> ReleaseVerifierSettings:
        names = (
            "SOLVAN_ORGANIZATION_ID",
            "SOLVAN_SCOPE_PROJECT_ID",
            "SOLVAN_ENVIRONMENT_ID",
            "SOLVAN_RELEASE_VERIFIER_AUDIENCE",
            "SOLVAN_COORDINATOR_SERVICE_ACCOUNT",
            "SOLVAN_RUNTIME_BUCKET",
            "SOLVAN_RELEASE_VERIFIER_SERVICE_ACCOUNT",
            "SOLVAN_RELEASE_VERIFIER_SIGNING_KEY_VERSION",
        )
        missing = [name for name in names if not os.environ.get(name)]
        if missing:
            raise RuntimeError("missing Release Verifier settings: " + ",".join(missing))
        return cls(
            scope=Scope(
                os.environ["SOLVAN_ORGANIZATION_ID"],
                os.environ["SOLVAN_SCOPE_PROJECT_ID"],
                os.environ["SOLVAN_ENVIRONMENT_ID"],
            ),
            audience=os.environ["SOLVAN_RELEASE_VERIFIER_AUDIENCE"],
            coordinator_principal=(
                "serviceAccount:" + os.environ["SOLVAN_COORDINATOR_SERVICE_ACCOUNT"]
            ),
            runtime_bucket=os.environ["SOLVAN_RUNTIME_BUCKET"],
            service_principal=(
                "serviceAccount:" + os.environ["SOLVAN_RELEASE_VERIFIER_SERVICE_ACCOUNT"]
            ),
            signing_key_version=os.environ["SOLVAN_RELEASE_VERIFIER_SIGNING_KEY_VERSION"],
            service_revision=os.environ.get("K_REVISION", "LOCAL_UNQUALIFIED"),
        )


def _principal(authorization: str | None, settings: ReleaseVerifierSettings) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing coordinator identity")
    try:
        claims = id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
            authorization.removeprefix("Bearer "),
            GoogleRequest(),
            audience=settings.audience,
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
    app = FastAPI(title="Solvan Release Verifier", version="0.1.0")

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post("/internal/v1/commands:execute")
    def execute(
        envelope: PrivateCommandEnvelope,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        settings = ReleaseVerifierSettings.from_env()
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
            if kind is DeliveryCommandKind.OBSERVE_RELEASE_BASELINE:
                return _execute_baseline(envelope=envelope, caller=caller, settings=settings)
            if kind is DeliveryCommandKind.VERIFY_RELEASE_EFFECT:
                return _execute_effect(envelope=envelope, caller=caller, settings=settings)
            if kind is DeliveryCommandKind.VERIFY_ROLLBACK_EFFECT:
                return _execute_rollback_verification(
                    envelope=envelope, caller=caller, settings=settings
                )
            raise DeliveryCommandError("Release Verifier command kind is not implemented")
        except (DeliveryCommandError, ValueError) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error

    instrument_fastapi(app, service_name="release-verifier")
    return app


def _execute_baseline(
    *, envelope: PrivateCommandEnvelope, caller: str, settings: ReleaseVerifierSettings
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
            audience_hash=sha256_bytes(settings.audience.encode()),
            now=now,
        )
        prior = commands.load_terminal_response(
            command_id=command.command_id, payload_reader=reader
        )
        if prior is not None:
            return prior.model_dump(mode="json")
        if command.command_kind is not DeliveryCommandKind.OBSERVE_RELEASE_BASELINE:
            raise DeliveryCommandError("Release Verifier command kind is not implemented")
        store = PostgresReleaseHealthBaselineStore(connection)
        material = store.load(
            scope=command.scope,
            request_id=command.subject_id,
            material_hash=command.material_hash,
        )
        if command.payload != {
            "verification_profile_hash": material.verification_profile_hash,
            "target_observation_hash": material.target_observation_hash,
        }:
            raise DeliveryCommandError("release baseline command payload differs")
        if (
            material.verifier_identity != settings.service_principal
            or material.verifier_key_version != settings.signing_key_version
        ):
            raise DeliveryCommandError("release baseline verifier authority differs")
        existing = store.existing(scope=command.scope, material=material)
        if existing is not None:
            if command.status is DeliveryCommandStatus.PREPARED:
                if not commands.claim_for_issue(command_id=command.command_id):
                    raise DeliveryCommandError("release baseline command was already claimed")
            elif command.status is DeliveryCommandStatus.ISSUED:
                commands.begin_reconciliation(command_id=command.command_id)
            elif command.status is not DeliveryCommandStatus.RECONCILING:
                raise DeliveryCommandError("release baseline command is no longer recoverable")
            return _complete(
                command_id=command.command_id,
                receipt_ref=existing.baseline_ref,
                receipt_hash=existing.baseline_hash,
                observed_at=now,
                writer=writer,
            )
        if command.status is DeliveryCommandStatus.PREPARED:
            if not commands.claim_for_issue(command_id=command.command_id):
                raise DeliveryCommandError("release baseline command was already claimed")
        elif command.status is DeliveryCommandStatus.ISSUED:
            commands.begin_reconciliation(command_id=command.command_id)
        elif command.status is not DeliveryCommandStatus.RECONCILING:
            raise DeliveryCommandError("release baseline command is no longer recoverable")
    profile_value = reader.get_json(
        uri=material.verification_profile_ref,
        expected_hash=material.verification_profile_hash,
        max_bytes=64_000,
    )
    profile = ReleaseVerificationProfile.model_validate(profile_value)
    if (
        profile.external_project_id != material.external_project_id
        or profile.cloud_run_service_name != material.service_name
        or profile.verifier_identity != material.verifier_identity
        or profile.verifier_key_version != material.verifier_key_version
    ):
        raise DeliveryCommandError("release verification profile differs from target")
    health = CloudRunHealthReader(
        session=session,
        project_id=material.external_project_id,
        service_name=material.service_name,
    )
    measurements = tuple(
        health.observe(
            rule.signal_kind,
            window_start=material.window_start,
            window_end=material.window_end,
        )
        for rule in profile.health_signals
    )
    snapshot = ReleaseHealthSnapshot(
        scope=command.scope,
        code_change_request_id=material.request_id,
        release_candidate_id=material.release_candidate_id,
        release_target_profile_id=material.release_target_profile_id,
        target_observation_hash=material.target_observation_hash,
        verification_profile_hash=material.verification_profile_hash,
        target_version=material.target_version,
        target_assignment_hash=material.target_assignment_hash,
        external_project_id=material.external_project_id,
        cloud_run_service_name=material.service_name,
        window_start=material.window_start,
        window_end=material.window_end,
        measurements=measurements,
        observed_at=now,
    )
    prefix = f"release-health-baselines/{material.request_id}/{command.material_hash}"
    snapshot_hash = canonical_sha256(snapshot.model_dump(mode="json"))
    baseline = writer.put_json(
        object_name=f"{prefix}/baseline-{snapshot_hash.removeprefix('sha256:')}.json",
        value=snapshot.model_dump(mode="json"),
    )
    signature = GoogleKmsSigner().sign_sha256(
        hashlib.sha256(snapshot.signed_payload()).digest(),
        key_version=material.verifier_key_version,
    )
    signature_receipt = writer.put_bytes(
        object_name=(f"{prefix}/signature-{sha256_bytes(signature).removeprefix('sha256:')}.der"),
        content=signature,
        content_type="application/octet-stream",
    )
    with connect_database() as connection, connection.transaction():
        PostgresReleaseHealthBaselineStore(connection).record(
            scope=command.scope,
            material=material,
            snapshot=snapshot,
            baseline_ref=baseline.uri,
            baseline_hash=baseline.content_hash,
            signature_ref=signature_receipt.uri,
            signature_hash=signature_receipt.content_hash,
        )
    return _complete(
        command_id=command.command_id,
        receipt_ref=baseline.uri,
        receipt_hash=baseline.content_hash,
        observed_at=now,
        writer=writer,
    )


def _execute_effect(
    *, envelope: PrivateCommandEnvelope, caller: str, settings: ReleaseVerifierSettings
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
            audience_hash=sha256_bytes(settings.audience.encode()),
            now=now,
        )
        prior = commands.load_terminal_response(
            command_id=command.command_id, payload_reader=reader
        )
        if prior is not None:
            return prior.model_dump(mode="json")
        if command.command_kind is not DeliveryCommandKind.VERIFY_RELEASE_EFFECT:
            raise DeliveryCommandError("release effect handler accepts only its exact command")
        store = PostgresReleaseEffectVerificationStore(connection)
        material = store.load(
            scope=command.scope,
            rollout_id=command.subject_id,
            material_hash=command.material_hash,
        )
        if command.payload != {
            "verification_profile_hash": material.verification_profile_hash,
            "predeploy_snapshot_hash": material.predeploy_snapshot_hash,
            "intended_effect_hash": material.intended_effect_hash,
            "observation_window_generation": material.observation_window_generation,
        }:
            raise DeliveryCommandError("release verification command payload differs")
        if (
            material.verifier_identity != settings.service_principal
            or material.verifier_key_version != settings.signing_key_version
            or now < material.window_end
        ):
            raise DeliveryCommandError("release verification authority or window differs")
        if command.status is DeliveryCommandStatus.PREPARED:
            if not commands.claim_for_issue(command_id=command.command_id):
                raise DeliveryCommandError("release verification command was already claimed")
        elif command.status is DeliveryCommandStatus.ISSUED:
            commands.begin_reconciliation(command_id=command.command_id)
        elif command.status is not DeliveryCommandStatus.RECONCILING:
            raise DeliveryCommandError("release verification command is no longer recoverable")
        existing = store.existing(scope=command.scope, material=material)
        if existing is not None:
            return _complete(
                command_id=command.command_id,
                receipt_ref=existing.envelope_ref,
                receipt_hash=existing.envelope_hash,
                observed_at=existing.observed_at,
                writer=writer,
            )
    profile_value = reader.get_json(
        uri=material.verification_profile_ref,
        expected_hash=material.verification_profile_hash,
        max_bytes=64_000,
    )
    profile = ReleaseVerificationProfile.model_validate(profile_value)
    if (
        profile.external_project_id != material.external_project_id
        or profile.cloud_run_service_name != material.service_name
        or profile.verifier_identity != material.verifier_identity
        or profile.verifier_key_version != material.verifier_key_version
    ):
        raise DeliveryCommandError("release verification profile differs from rollout")
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
            target_version=material.baseline_target_version,
            target_assignment_hash=material.baseline_assignment_hash,
            verifier_identity=material.verifier_identity,
            verifier_key_version=material.verifier_key_version,
        ),
        signature_ref=material.baseline_signature_ref,
        signature_hash=material.baseline_signature_hash,
        evidence=reader,
        kms=GoogleKmsPublicKeyReader(session),
    )
    manifest = reader.get_json(
        uri=material.deployment_manifest_profile_ref,
        expected_hash=material.deployment_manifest_profile_hash,
        max_bytes=64_000,
    )
    container_name = manifest.get("allowed_container_name")
    if not isinstance(container_name, str):
        raise DeliveryCommandError("release target manifest profile is malformed")
    observed = CloudRunServiceObserver(
        session=session,
        service_resource_name=material.service_resource_name,
        runtime_service_account=material.runtime_service_account,
        container_name=container_name,
    ).observe()
    health = CloudRunHealthReader(
        session=session,
        project_id=material.external_project_id,
        service_name=material.service_name,
    )
    measurements = tuple(
        health.observe(
            rule.signal_kind,
            window_start=material.window_start,
            window_end=material.window_end,
        )
        for rule in profile.health_signals
    )
    postdeploy = ReleaseHealthSnapshot(
        scope=command.scope,
        code_change_request_id=material.code_change_request_id,
        release_candidate_id=material.release_candidate_id,
        release_target_profile_id=material.release_target_profile_id,
        target_observation_hash=material.target_observation_hash,
        verification_profile_hash=material.verification_profile_hash,
        target_version=str(observed.generation),
        target_assignment_hash=observed.assignment_hash,
        external_project_id=material.external_project_id,
        cloud_run_service_name=material.service_name,
        window_start=material.window_start,
        window_end=material.window_end,
        measurements=measurements,
        observed_at=now,
    )
    evaluation = evaluate_release_health(
        rules=profile.health_signals, baseline=baseline, postdeploy=postdeploy
    )
    if (
        observed.traffic != material.expected_assignment
        or observed.image != material.build_artifact_ref
    ):
        evaluation = ReleaseVerificationEvaluation(
            result=ReleaseVerificationResult.INCONCLUSIVE,
            rationale_codes=("DEPLOYED_TARGET_STATE_DIFFERS",),
        )
    prefix = (
        f"release-verifications/{material.rollout_id}/"
        f"{material.stage_ordinal}-{material.observation_window_generation}"
    )
    post_receipt = writer.put_json(
        object_name=(
            f"{prefix}/postdeploy-observation-"
            f"{canonical_sha256(postdeploy.model_dump(mode='json')).removeprefix('sha256:')}.json"
        ),
        value=postdeploy.model_dump(mode="json"),
    )
    receipt = ReleaseEffectReceiptEnvelope(
        scope=command.scope,
        deployment_rollout_id=material.rollout_id,
        stage_ordinal=material.stage_ordinal,
        observation_window_generation=material.observation_window_generation,
        verification_profile_hash=material.verification_profile_hash,
        release_health_baseline_ref=material.release_health_baseline_ref,
        release_health_baseline_hash=material.release_health_baseline_hash,
        predeploy_snapshot_ref=material.predeploy_snapshot_ref,
        predeploy_snapshot_hash=material.predeploy_snapshot_hash,
        postdeploy_observation_ref=post_receipt.uri,
        postdeploy_observation_hash=post_receipt.content_hash,
        intended_effect_hash=material.intended_effect_hash,
        observed_target_version=str(observed.generation),
        observed_assignment_hash=observed.assignment_hash,
        window_start=material.window_start,
        window_end=material.window_end,
        result=evaluation.result,
        rationale_codes=evaluation.rationale_codes,
        verifier_identity=material.verifier_identity,
        verifier_key_version=material.verifier_key_version,
        observed_at=now,
    )
    envelope_receipt = writer.put_json(
        object_name=(
            f"{prefix}/receipt-"
            f"{canonical_sha256(receipt.model_dump(mode='json')).removeprefix('sha256:')}.json"
        ),
        value=receipt.model_dump(mode="json"),
    )
    signature = GoogleKmsSigner().sign_sha256(
        hashlib.sha256(receipt.signed_payload()).digest(),
        key_version=material.verifier_key_version,
    )
    signature_receipt = writer.put_bytes(
        object_name=(f"{prefix}/signature-{sha256_bytes(signature).removeprefix('sha256:')}.der"),
        content=signature,
        content_type="application/octet-stream",
    )
    with connect_database() as connection, connection.transaction():
        PostgresReleaseEffectVerificationStore(connection).record(
            scope=command.scope,
            material=material,
            envelope=receipt,
            receipt_envelope_ref=envelope_receipt.uri,
            receipt_envelope_hash=envelope_receipt.content_hash,
            signature_ref=signature_receipt.uri,
            signature_hash=signature_receipt.content_hash,
        )
    return _complete(
        command_id=command.command_id,
        receipt_ref=envelope_receipt.uri,
        receipt_hash=envelope_receipt.content_hash,
        observed_at=now,
        writer=writer,
    )


def _execute_rollback_verification(
    *, envelope: PrivateCommandEnvelope, caller: str, settings: ReleaseVerifierSettings
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
            audience_hash=sha256_bytes(settings.audience.encode()),
            now=now,
        )
        prior = commands.load_terminal_response(
            command_id=command.command_id, payload_reader=reader
        )
        if prior is not None:
            return prior.model_dump(mode="json")
        store = PostgresReleaseRollbackVerificationStore(connection)
        material = store.load(
            scope=command.scope, rollout_id=command.subject_id, material_hash=command.material_hash
        )
        if (
            command.payload
            or material.verifier_identity != settings.service_principal
            or (material.verifier_key_version != settings.signing_key_version)
        ):
            raise DeliveryCommandError("rollback verification authority differs")
        if command.status is DeliveryCommandStatus.PREPARED:
            if not commands.claim_for_issue(command_id=command.command_id):
                raise DeliveryCommandError("rollback verification was already claimed")
        elif command.status is DeliveryCommandStatus.ISSUED:
            commands.begin_reconciliation(command_id=command.command_id)
        elif command.status is not DeliveryCommandStatus.RECONCILING:
            raise DeliveryCommandError("rollback verification is no longer recoverable")
        existing = store.existing(scope=command.scope, material=material)
        if existing is not None:
            return _complete(
                command_id=command.command_id,
                receipt_ref=existing.envelope_ref,
                receipt_hash=existing.envelope_hash,
                observed_at=existing.observed_at,
                writer=writer,
            )
    manifest = reader.get_json(
        uri=material.deployment_manifest_profile_ref,
        expected_hash=material.deployment_manifest_profile_hash,
        max_bytes=64_000,
    )
    container_name = manifest.get("allowed_container_name")
    if not isinstance(container_name, str):
        raise DeliveryCommandError("rollback target manifest is malformed")
    observed = CloudRunServiceObserver(
        session=session,
        service_resource_name=material.service_resource_name,
        runtime_service_account=material.runtime_service_account,
        container_name=container_name,
    ).observe()
    expected_assignment = ((material.expected_revision, 100),)
    result = (
        ReleaseVerificationResult.VERIFIED
        if observed.traffic == expected_assignment
        else ReleaseVerificationResult.FAILED
    )
    receipt = ReleaseRollbackReceiptEnvelope(
        scope=command.scope,
        deployment_rollout_id=material.rollout_id,
        expected_revision=material.expected_revision,
        observed_target_version=str(observed.generation),
        observed_assignment_hash=observed.assignment_hash,
        result=result,
        verifier_identity=material.verifier_identity,
        verifier_key_version=material.verifier_key_version,
        observed_at=now,
    )
    prefix = f"rollback-verifications/{material.rollout_id}"
    envelope_receipt = writer.put_json(
        object_name=(
            f"{prefix}/receipt-"
            f"{canonical_sha256(receipt.model_dump(mode='json')).removeprefix('sha256:')}.json"
        ),
        value=receipt.model_dump(mode="json"),
    )
    signature = GoogleKmsSigner().sign_sha256(
        hashlib.sha256(receipt.signed_payload()).digest(), key_version=material.verifier_key_version
    )
    signature_receipt = writer.put_bytes(
        object_name=(f"{prefix}/signature-{sha256_bytes(signature).removeprefix('sha256:')}.der"),
        content=signature,
        content_type="application/octet-stream",
    )
    with connect_database() as connection, connection.transaction():
        PostgresReleaseRollbackVerificationStore(connection).record(
            scope=command.scope,
            material=material,
            receipt=receipt,
            envelope_ref=envelope_receipt.uri,
            envelope_hash=envelope_receipt.content_hash,
            signature_ref=signature_receipt.uri,
            signature_hash=signature_receipt.content_hash,
        )
    return _complete(
        command_id=command.command_id,
        receipt_ref=envelope_receipt.uri,
        receipt_hash=envelope_receipt.content_hash,
        observed_at=now,
        writer=writer,
    )


def _complete(
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
    response_receipt = writer.put_json(
        object_name=f"private-command-responses/{command_id}.json",
        value=response.model_dump(mode="json"),
    )
    with connect_database() as connection, connection.transaction():
        PostgresDeliveryCommandStore(connection).complete(
            response,
            response_ref=response_receipt.uri,
            response_hash=response_receipt.content_hash,
        )
    return response.model_dump(mode="json")


app = create_app()
