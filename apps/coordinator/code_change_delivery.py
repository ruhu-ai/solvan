"""Coordinator recovery loop for approved governed GitHub PR creation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from psycopg import Connection

from apps.coordinator.contracts import CoordinatorSettings
from solvan.application.delivery_commands import (
    DeliveryCommandKind,
    DeliveryCommandStatus,
    PrivateCommandEnvelope,
    PrivateCommandRecord,
    payload_schema_hash,
)
from solvan.application.release_verification import (
    ReleaseEffectReceiptEnvelope,
    ReleaseEffectReceiptExpected,
    ReleaseRollbackReceiptEnvelope,
    ReleaseVerificationResult,
    verify_release_effect_receipt,
    verify_release_rollback_receipt,
)
from solvan.application.workspace_hashing import sha256_bytes
from solvan.domain import new_identifier
from solvan.persistence.code_change_merge_store import PostgresCodeChangeMergeStore
from solvan.persistence.code_change_operation_store import (
    PostgresCodeChangeOperationStore,
)
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
from solvan.persistence.release_rollout_store import PostgresReleaseRolloutStore
from solvan.persistence.release_target_observation_store import (
    PostgresReleaseTargetObservationStore,
)
from solvan.platform.deployment_controller import DeploymentControllerClient
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.github_release import (
    GitHubReleaseProviderClient,
    GoogleIdentityTokenProvider,
)
from solvan.platform.google_rest import authorized_session
from solvan.platform.release_verifier import ReleaseVerifierClient
from solvan.platform.workspace_attestation import GoogleKmsPublicKeyReader


def advance_code_change_delivery(
    *, settings: CoordinatorSettings, connection: Connection[Any]
) -> None:
    config = settings.github_release
    if config is None:
        return
    operations = PostgresCodeChangeOperationStore(connection)
    with connection.transaction():
        operations.advance_approved_pr_creations(
            scope=settings.scope,
            coordinator_identity=settings.coordinator_principal,
        )
    session = authorized_session()
    writer = GcsEvidenceWriter(bucket=settings.runtime_bucket, session=session)
    reader = GcsEvidenceReader(
        allowed_buckets=frozenset({settings.runtime_bucket}), session=session
    )
    commands = PostgresDeliveryCommandStore(connection)
    merges = PostgresCodeChangeMergeStore(connection)
    targets = PostgresReleaseTargetObservationStore(connection)
    rollouts = PostgresReleaseRolloutStore(connection)
    baselines = PostgresReleaseHealthBaselineStore(connection)
    verifications = PostgresReleaseEffectVerificationStore(connection)
    rollback_verifications = PostgresReleaseRollbackVerificationStore(connection)
    for candidate in operations.pr_command_candidates(scope=settings.scope):
        command_id = new_identifier("cmd")
        payload: dict[str, object] = {}
        payload_receipt = writer.put_json(
            object_name=(
                f"{settings.scope.organization_id}/{settings.scope.project_id}/"
                f"{settings.scope.environment_id}/code-change-requests/"
                f"{candidate.request_id}/{command_id}/command.json"
            ),
            value=payload,
        )
        command = PrivateCommandRecord(
            command_id=command_id,
            scope=settings.scope,
            command_kind=DeliveryCommandKind.CREATE_PR,
            subject_id=candidate.request_id,
            material_hash=candidate.material_hash,
            idempotency_key=f"create-pr:{candidate.request_id}",
            payload_ref=payload_receipt.uri,
            payload=payload,
            payload_hash=payload_receipt.content_hash,
            payload_schema_hash=payload_schema_hash(DeliveryCommandKind.CREATE_PR),
            admitted_caller_identity=settings.coordinator_principal,
            admitted_audience_hash=sha256_bytes(config.audience.encode()),
            deadline=candidate.expires_at,
            status=DeliveryCommandStatus.PREPARED,
        )
        with connection.transaction():
            operations.prepare_pr_operations(
                scope=settings.scope,
                candidate=candidate,
                request_ref=payload_receipt.uri,
                request_hash=payload_receipt.content_hash,
            )
            commands.prepare(command)
    for merge_candidate in merges.candidates(scope=settings.scope):
        command_id = new_identifier("cmd")
        payload = {"github_observation_hash": merge_candidate.github_observation_hash}
        payload_receipt = writer.put_json(
            object_name=(
                f"{settings.scope.organization_id}/{settings.scope.project_id}/"
                f"{settings.scope.environment_id}/code-change-requests/"
                f"{merge_candidate.request_id}/{command_id}/command.json"
            ),
            value=payload,
        )
        command = PrivateCommandRecord(
            command_id=command_id,
            scope=settings.scope,
            command_kind=DeliveryCommandKind.MERGE_PR,
            subject_id=merge_candidate.request_id,
            material_hash=merge_candidate.material_hash,
            idempotency_key=f"merge-pr:{merge_candidate.request_id}",
            payload_ref=payload_receipt.uri,
            payload=payload,
            payload_hash=payload_receipt.content_hash,
            payload_schema_hash=payload_schema_hash(DeliveryCommandKind.MERGE_PR),
            admitted_caller_identity=settings.coordinator_principal,
            admitted_audience_hash=sha256_bytes(config.audience.encode()),
            deadline=merge_candidate.deadline,
            status=DeliveryCommandStatus.PREPARED,
        )
        with connection.transaction():
            merges.prepare(
                scope=settings.scope,
                candidate=merge_candidate,
                request_ref=payload_receipt.uri,
                request_hash=payload_receipt.content_hash,
            )
            commands.prepare(command)
    if settings.deployment_controller is not None:
        for target_candidate in targets.candidates(scope=settings.scope):
            command_id = new_identifier("cmd")
            payload = {}
            payload_receipt = writer.put_json(
                object_name=(
                    f"{settings.scope.organization_id}/{settings.scope.project_id}/"
                    f"{settings.scope.environment_id}/code-change-requests/"
                    f"{target_candidate.request_id}/{command_id}/command.json"
                ),
                value=payload,
            )
            command = PrivateCommandRecord(
                command_id=command_id,
                scope=settings.scope,
                command_kind=DeliveryCommandKind.OBSERVE_RELEASE_TARGET,
                subject_id=target_candidate.request_id,
                material_hash=target_candidate.material_hash,
                idempotency_key=f"observe-release-target:{target_candidate.request_id}",
                payload_ref=payload_receipt.uri,
                payload=payload,
                payload_hash=payload_receipt.content_hash,
                payload_schema_hash=payload_schema_hash(DeliveryCommandKind.OBSERVE_RELEASE_TARGET),
                admitted_caller_identity=settings.coordinator_principal,
                admitted_audience_hash=sha256_bytes(
                    settings.deployment_controller.audience.encode()
                ),
                deadline=target_candidate.deadline,
                status=DeliveryCommandStatus.PREPARED,
            )
            with connection.transaction():
                commands.prepare(command)
    if settings.release_verifier is not None:
        now = datetime.now(UTC)
        for baseline_candidate in baselines.candidates(scope=settings.scope, now=now):
            command_id = new_identifier("cmd")
            payload = {
                "verification_profile_hash": (baseline_candidate.verification_profile_hash),
                "target_observation_hash": baseline_candidate.target_observation_hash,
            }
            payload_receipt = writer.put_json(
                object_name=(
                    f"{settings.scope.organization_id}/{settings.scope.project_id}/"
                    f"{settings.scope.environment_id}/release-health-baselines/"
                    f"{baseline_candidate.request_id}/{command_id}/command.json"
                ),
                value=payload,
            )
            with connection.transaction():
                commands.prepare(
                    PrivateCommandRecord(
                        command_id=command_id,
                        scope=settings.scope,
                        command_kind=DeliveryCommandKind.OBSERVE_RELEASE_BASELINE,
                        subject_id=baseline_candidate.request_id,
                        material_hash=baseline_candidate.material_hash,
                        idempotency_key=(
                            f"release-baseline:{baseline_candidate.request_id}:"
                            f"{baseline_candidate.target_observation_hash}"
                        )[:255],
                        payload_ref=payload_receipt.uri,
                        payload=payload,
                        payload_hash=payload_receipt.content_hash,
                        payload_schema_hash=payload_schema_hash(
                            DeliveryCommandKind.OBSERVE_RELEASE_BASELINE
                        ),
                        admitted_caller_identity=settings.coordinator_principal,
                        admitted_audience_hash=sha256_bytes(
                            settings.release_verifier.audience.encode()
                        ),
                        deadline=baseline_candidate.deadline,
                        status=DeliveryCommandStatus.PREPARED,
                    )
                )
        for verification_candidate in verifications.candidates(scope=settings.scope, now=now):
            command_id = new_identifier("cmd")
            payload = {
                "verification_profile_hash": (verification_candidate.verification_profile_hash),
                "predeploy_snapshot_hash": verification_candidate.predeploy_snapshot_hash,
                "intended_effect_hash": verification_candidate.intended_effect_hash,
                "observation_window_generation": (
                    verification_candidate.observation_window_generation
                ),
            }
            payload_receipt = writer.put_json(
                object_name=(
                    f"{settings.scope.organization_id}/{settings.scope.project_id}/"
                    f"{settings.scope.environment_id}/release-verifications/"
                    f"{verification_candidate.rollout_id}/{command_id}/command.json"
                ),
                value=payload,
            )
            with connection.transaction():
                commands.prepare(
                    PrivateCommandRecord(
                        command_id=command_id,
                        scope=settings.scope,
                        command_kind=DeliveryCommandKind.VERIFY_RELEASE_EFFECT,
                        subject_id=verification_candidate.rollout_id,
                        material_hash=verification_candidate.material_hash,
                        idempotency_key=(
                            f"verify-release:{verification_candidate.rollout_id}:"
                            f"{verification_candidate.stage_ordinal}:1"
                        ),
                        payload_ref=payload_receipt.uri,
                        payload=payload,
                        payload_hash=payload_receipt.content_hash,
                        payload_schema_hash=payload_schema_hash(
                            DeliveryCommandKind.VERIFY_RELEASE_EFFECT
                        ),
                        admitted_caller_identity=settings.coordinator_principal,
                        admitted_audience_hash=sha256_bytes(
                            settings.release_verifier.audience.encode()
                        ),
                        deadline=verification_candidate.deadline,
                        status=DeliveryCommandStatus.PREPARED,
                    )
                )
        for rollback_verification in rollback_verifications.candidates(scope=settings.scope):
            command_id = new_identifier("cmd")
            payload = {}
            payload_receipt = writer.put_json(
                object_name=(
                    f"{settings.scope.organization_id}/{settings.scope.project_id}/"
                    f"{settings.scope.environment_id}/rollback-verifications/"
                    f"{rollback_verification.rollout_id}/{command_id}/command.json"
                ),
                value=payload,
            )
            with connection.transaction():
                commands.prepare(
                    PrivateCommandRecord(
                        command_id=command_id,
                        scope=settings.scope,
                        command_kind=DeliveryCommandKind.VERIFY_ROLLBACK_EFFECT,
                        subject_id=rollback_verification.rollout_id,
                        material_hash=rollback_verification.material_hash,
                        idempotency_key=f"verify-rollback:{rollback_verification.rollout_id}",
                        payload_ref=payload_receipt.uri,
                        payload=payload,
                        payload_hash=payload_receipt.content_hash,
                        payload_schema_hash=payload_schema_hash(
                            DeliveryCommandKind.VERIFY_ROLLBACK_EFFECT
                        ),
                        admitted_caller_identity=settings.coordinator_principal,
                        admitted_audience_hash=sha256_bytes(
                            settings.release_verifier.audience.encode()
                        ),
                        deadline=rollback_verification.deadline,
                        status=DeliveryCommandStatus.PREPARED,
                    )
                )
    if settings.deployment_controller is not None:
        now = datetime.now(UTC)
        for rollout_candidate in rollouts.candidates(scope=settings.scope, now=now):
            command_id = new_identifier("cmd")
            payload = {}
            payload_receipt = writer.put_json(
                object_name=(
                    f"{settings.scope.organization_id}/{settings.scope.project_id}/"
                    f"{settings.scope.environment_id}/deployment-rollouts/"
                    f"{rollout_candidate.request_id}/{command_id}/command.json"
                ),
                value=payload,
            )
            with connection.transaction():
                commands.prepare(
                    PrivateCommandRecord(
                        command_id=command_id,
                        scope=settings.scope,
                        command_kind=DeliveryCommandKind.START_ROLLOUT,
                        subject_id=rollout_candidate.request_id,
                        material_hash=rollout_candidate.material_hash,
                        idempotency_key=(
                            f"start-rollout:{rollout_candidate.request_id}:"
                            f"{rollout_candidate.decision_id}"
                        ),
                        payload_ref=payload_receipt.uri,
                        payload=payload,
                        payload_hash=payload_receipt.content_hash,
                        payload_schema_hash=payload_schema_hash(DeliveryCommandKind.START_ROLLOUT),
                        admitted_caller_identity=settings.coordinator_principal,
                        admitted_audience_hash=sha256_bytes(
                            settings.deployment_controller.audience.encode()
                        ),
                        deadline=rollout_candidate.command_deadline,
                        status=DeliveryCommandStatus.PREPARED,
                    )
                )
        for canary_candidate in rollouts.canary_candidates(scope=settings.scope, now=now):
            command_id = new_identifier("cmd")
            payload = {}
            payload_receipt = writer.put_json(
                object_name=(
                    f"{settings.scope.organization_id}/{settings.scope.project_id}/"
                    f"{settings.scope.environment_id}/deployment-rollouts/"
                    f"{canary_candidate.rollout_id}/{command_id}/command.json"
                ),
                value=payload,
            )
            with connection.transaction():
                commands.prepare(
                    PrivateCommandRecord(
                        command_id=command_id,
                        scope=settings.scope,
                        command_kind=DeliveryCommandKind.PREPARE_CANARY,
                        subject_id=canary_candidate.rollout_id,
                        material_hash=canary_candidate.material_hash,
                        idempotency_key=f"prepare-canary:{canary_candidate.rollout_id}:1",
                        payload_ref=payload_receipt.uri,
                        payload=payload,
                        payload_hash=payload_receipt.content_hash,
                        payload_schema_hash=payload_schema_hash(DeliveryCommandKind.PREPARE_CANARY),
                        admitted_caller_identity=settings.coordinator_principal,
                        admitted_audience_hash=sha256_bytes(
                            settings.deployment_controller.audience.encode()
                        ),
                        deadline=canary_candidate.deadline,
                        status=DeliveryCommandStatus.PREPARED,
                    )
                )
        for advancement in rollouts.advancement_candidates(scope=settings.scope, now=now):
            receipt_value = reader.get_json(
                uri=advancement.receipt_envelope_ref,
                expected_hash=advancement.receipt_envelope_hash,
                max_bytes=128_000,
            )
            receipt = ReleaseEffectReceiptEnvelope.model_validate(receipt_value)
            verify_release_effect_receipt(
                receipt,
                expected=ReleaseEffectReceiptExpected(
                    scope=settings.scope,
                    deployment_rollout_id=advancement.rollout_id,
                    stage_ordinal=advancement.current_stage_ordinal,
                    observation_window_generation=1,
                    verification_profile_hash=advancement.verification_profile_hash,
                    release_health_baseline_hash=advancement.release_health_baseline_hash,
                    predeploy_snapshot_hash=advancement.predeploy_snapshot_hash,
                    intended_effect_hash=advancement.intended_effect_hash,
                    verifier_identity=advancement.verifier_identity,
                    verifier_key_version=advancement.verifier_key_version,
                ),
                signature_ref=advancement.signature_ref,
                signature_hash=advancement.signature_hash,
                evidence=reader,
                kms=GoogleKmsPublicKeyReader(session),
            )
            if receipt.result is not ReleaseVerificationResult.VERIFIED:
                continue
            command_kind = DeliveryCommandKind(advancement.action)
            payload = (
                {"prior_canary_receipt_hash": advancement.receipt_envelope_hash}
                if command_kind is DeliveryCommandKind.PROMOTE_CANARY
                else {"final_verification_receipt_hash": advancement.receipt_envelope_hash}
            )
            command_id = new_identifier("cmd")
            payload_receipt = writer.put_json(
                object_name=(
                    f"{settings.scope.organization_id}/{settings.scope.project_id}/"
                    f"{settings.scope.environment_id}/deployment-rollouts/"
                    f"{advancement.rollout_id}/{command_id}/command.json"
                ),
                value=payload,
            )
            with connection.transaction():
                commands.prepare(
                    PrivateCommandRecord(
                        command_id=command_id,
                        scope=settings.scope,
                        command_kind=command_kind,
                        subject_id=advancement.rollout_id,
                        material_hash=advancement.material_hash,
                        idempotency_key=(
                            f"{advancement.action.lower()}:{advancement.rollout_id}:"
                            f"{advancement.current_stage_ordinal}"
                        ),
                        payload_ref=payload_receipt.uri,
                        payload=payload,
                        payload_hash=payload_receipt.content_hash,
                        payload_schema_hash=payload_schema_hash(command_kind),
                        admitted_caller_identity=settings.coordinator_principal,
                        admitted_audience_hash=sha256_bytes(
                            settings.deployment_controller.audience.encode()
                        ),
                        deadline=advancement.deadline,
                        status=DeliveryCommandStatus.PREPARED,
                    )
                )
        for failure in rollouts.failure_candidates(scope=settings.scope, now=now):
            receipt_value = reader.get_json(
                uri=failure.receipt_envelope_ref,
                expected_hash=failure.receipt_envelope_hash,
                max_bytes=128_000,
            )
            receipt = ReleaseEffectReceiptEnvelope.model_validate(receipt_value)
            verify_release_effect_receipt(
                receipt,
                expected=ReleaseEffectReceiptExpected(
                    scope=settings.scope,
                    deployment_rollout_id=failure.rollout_id,
                    stage_ordinal=failure.current_stage_ordinal,
                    observation_window_generation=1,
                    verification_profile_hash=failure.verification_profile_hash,
                    release_health_baseline_hash=failure.release_health_baseline_hash,
                    predeploy_snapshot_hash=failure.predeploy_snapshot_hash,
                    intended_effect_hash=failure.intended_effect_hash,
                    verifier_identity=failure.verifier_identity,
                    verifier_key_version=failure.verifier_key_version,
                ),
                signature_ref=failure.signature_ref,
                signature_hash=failure.signature_hash,
                evidence=reader,
                kms=GoogleKmsPublicKeyReader(session),
            )
            if receipt.result is ReleaseVerificationResult.VERIFIED:
                continue
            command_id = new_identifier("cmd")
            payload = {"failed_verification_receipt_hash": failure.receipt_envelope_hash}
            payload_receipt = writer.put_json(
                object_name=(
                    f"{settings.scope.organization_id}/{settings.scope.project_id}/"
                    f"{settings.scope.environment_id}/deployment-rollouts/"
                    f"{failure.rollout_id}/{command_id}/command.json"
                ),
                value=payload,
            )
            with connection.transaction():
                commands.prepare(
                    PrivateCommandRecord(
                        command_id=command_id,
                        scope=settings.scope,
                        command_kind=(DeliveryCommandKind.REGISTER_VERIFICATION_FAILURE),
                        subject_id=failure.rollout_id,
                        material_hash=failure.material_hash,
                        idempotency_key=(
                            f"register-verification-failure:{failure.rollout_id}:"
                            f"{failure.current_stage_ordinal}"
                        ),
                        payload_ref=payload_receipt.uri,
                        payload=payload,
                        payload_hash=payload_receipt.content_hash,
                        payload_schema_hash=payload_schema_hash(
                            DeliveryCommandKind.REGISTER_VERIFICATION_FAILURE
                        ),
                        admitted_caller_identity=settings.coordinator_principal,
                        admitted_audience_hash=sha256_bytes(
                            settings.deployment_controller.audience.encode()
                        ),
                        deadline=failure.deadline,
                        status=DeliveryCommandStatus.PREPARED,
                    )
                )
        for rollback in rollouts.rollback_candidates(scope=settings.scope, now=now):
            command_id = new_identifier("cmd")
            payload = {}
            payload_receipt = writer.put_json(
                object_name=(
                    f"{settings.scope.organization_id}/{settings.scope.project_id}/"
                    f"{settings.scope.environment_id}/deployment-rollouts/"
                    f"{rollback.rollout_id}/{command_id}/command.json"
                ),
                value=payload,
            )
            with connection.transaction():
                commands.prepare(
                    PrivateCommandRecord(
                        command_id=command_id,
                        scope=settings.scope,
                        command_kind=DeliveryCommandKind.ROLLBACK_RELEASE,
                        subject_id=rollback.rollout_id,
                        material_hash=rollback.material_hash,
                        idempotency_key=f"rollback-release:{rollback.rollout_id}",
                        payload_ref=payload_receipt.uri,
                        payload=payload,
                        payload_hash=payload_receipt.content_hash,
                        payload_schema_hash=payload_schema_hash(
                            DeliveryCommandKind.ROLLBACK_RELEASE
                        ),
                        admitted_caller_identity=settings.coordinator_principal,
                        admitted_audience_hash=sha256_bytes(
                            settings.deployment_controller.audience.encode()
                        ),
                        deadline=rollback.deadline,
                        status=DeliveryCommandStatus.PREPARED,
                    )
                )
        for final_rollback in rollouts.rollback_finalization_candidates(
            scope=settings.scope, now=now
        ):
            value = reader.get_json(
                uri=final_rollback.receipt_envelope_ref,
                expected_hash=final_rollback.receipt_envelope_hash,
                max_bytes=64_000,
            )
            rollback_receipt = ReleaseRollbackReceiptEnvelope.model_validate(value)
            verify_release_rollback_receipt(
                rollback_receipt,
                scope=settings.scope,
                rollout_id=final_rollback.rollout_id,
                expected_revision=final_rollback.expected_revision,
                verifier_identity=final_rollback.verifier_identity,
                verifier_key_version=final_rollback.verifier_key_version,
                signature_ref=final_rollback.signature_ref,
                signature_hash=final_rollback.signature_hash,
                evidence=reader,
                kms=GoogleKmsPublicKeyReader(session),
            )
            command_id = new_identifier("cmd")
            payload = {"rollback_verification_receipt_hash": final_rollback.receipt_envelope_hash}
            payload_receipt = writer.put_json(
                object_name=(
                    f"{settings.scope.organization_id}/"
                    f"{settings.scope.project_id}/"
                    f"{settings.scope.environment_id}/deployment-rollouts/"
                    f"{final_rollback.rollout_id}/{command_id}/command.json"
                ),
                value=payload,
            )
            with connection.transaction():
                commands.prepare(
                    PrivateCommandRecord(
                        command_id=command_id,
                        scope=settings.scope,
                        command_kind=DeliveryCommandKind.FINALIZE_ROLLBACK,
                        subject_id=final_rollback.rollout_id,
                        material_hash=final_rollback.material_hash,
                        idempotency_key=f"finalize-rollback:{final_rollback.rollout_id}",
                        payload_ref=payload_receipt.uri,
                        payload=payload,
                        payload_hash=payload_receipt.content_hash,
                        payload_schema_hash=payload_schema_hash(
                            DeliveryCommandKind.FINALIZE_ROLLBACK
                        ),
                        admitted_caller_identity=settings.coordinator_principal,
                        admitted_audience_hash=sha256_bytes(
                            settings.deployment_controller.audience.encode()
                        ),
                        deadline=final_rollback.deadline,
                        status=DeliveryCommandStatus.PREPARED,
                    )
                )
    now = datetime.now(UTC)
    sync_generation = int(now.timestamp() // 60)
    for sync_candidate in operations.sync_command_candidates(
        scope=settings.scope,
        generation=sync_generation,
        deadline=now + timedelta(minutes=10),
    ):
        command_id = new_identifier("cmd")
        payload = {}
        payload_receipt = writer.put_json(
            object_name=(
                f"{settings.scope.organization_id}/{settings.scope.project_id}/"
                f"{settings.scope.environment_id}/code-change-requests/"
                f"{sync_candidate.request_id}/{command_id}/command.json"
            ),
            value=payload,
        )
        command = PrivateCommandRecord(
            command_id=command_id,
            scope=settings.scope,
            command_kind=DeliveryCommandKind.SYNC_PR,
            subject_id=sync_candidate.request_id,
            material_hash=sync_candidate.material_hash,
            idempotency_key=(f"sync-pr:{sync_candidate.request_id}:{sync_candidate.generation}"),
            payload_ref=payload_receipt.uri,
            payload=payload,
            payload_hash=payload_receipt.content_hash,
            payload_schema_hash=payload_schema_hash(DeliveryCommandKind.SYNC_PR),
            admitted_caller_identity=settings.coordinator_principal,
            admitted_audience_hash=sha256_bytes(config.audience.encode()),
            deadline=sync_candidate.deadline,
            status=DeliveryCommandStatus.PREPARED,
        )
        with connection.transaction():
            operations.prepare_sync_operation(
                scope=settings.scope,
                candidate=sync_candidate,
                request_ref=payload_receipt.uri,
                request_hash=payload_receipt.content_hash,
            )
            commands.prepare(command)
    with httpx.Client() as transport:
        client = GitHubReleaseProviderClient(
            config=config,
            client=transport,
            token_provider=GoogleIdentityTokenProvider(),
        )
        for command_id in operations.dispatchable_pr_command_ids(scope=settings.scope):
            command = commands.load(command_id=command_id, payload_reader=reader)
            client.execute_private_command(
                PrivateCommandEnvelope(
                    command_id=command.command_id, payload=command.payload
                ).model_dump(mode="json")
            )
        for command_id in operations.dispatchable_sync_command_ids(scope=settings.scope):
            command = commands.load(command_id=command_id, payload_reader=reader)
            client.execute_private_command(
                PrivateCommandEnvelope(
                    command_id=command.command_id, payload=command.payload
                ).model_dump(mode="json")
            )
        for command_id in merges.dispatchable_ids(scope=settings.scope):
            command = commands.load(command_id=command_id, payload_reader=reader)
            client.execute_private_command(
                PrivateCommandEnvelope(
                    command_id=command.command_id, payload=command.payload
                ).model_dump(mode="json")
            )
    if settings.deployment_controller is not None:
        with httpx.Client() as transport:
            deployment = DeploymentControllerClient(
                config=settings.deployment_controller,
                client=transport,
                token_provider=GoogleIdentityTokenProvider(),
            )
            for command_id in targets.dispatchable_ids(scope=settings.scope):
                command = commands.load(command_id=command_id, payload_reader=reader)
                deployment.execute_private_command(
                    PrivateCommandEnvelope(
                        command_id=command.command_id, payload=command.payload
                    ).model_dump(mode="json")
                )
            for command_id in rollouts.dispatchable_ids(scope=settings.scope):
                command = commands.load(command_id=command_id, payload_reader=reader)
                deployment.execute_private_command(
                    PrivateCommandEnvelope(
                        command_id=command.command_id, payload=command.payload
                    ).model_dump(mode="json")
                )
    if settings.release_verifier is not None:
        with httpx.Client() as transport:
            verifier = ReleaseVerifierClient(
                config=settings.release_verifier,
                client=transport,
                token_provider=GoogleIdentityTokenProvider(),
            )
            for command_id in baselines.dispatchable_ids(scope=settings.scope):
                command = commands.load(command_id=command_id, payload_reader=reader)
                verifier.execute_private_command(
                    PrivateCommandEnvelope(
                        command_id=command.command_id, payload=command.payload
                    ).model_dump(mode="json")
                )
            for command_id in verifications.dispatchable_ids(scope=settings.scope):
                command = commands.load(command_id=command_id, payload_reader=reader)
                verifier.execute_private_command(
                    PrivateCommandEnvelope(
                        command_id=command.command_id, payload=command.payload
                    ).model_dump(mode="json")
                )
            rows = connection.execute(
                """SELECT id FROM solvan_delivery.private_command_dispatches
                    WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                      AND command_kind='VERIFY_ROLLBACK_EFFECT'
                      AND status IN ('PREPARED','ISSUED','RECONCILING') AND deadline>now()""",
                tuple(settings.scope.canonical_dict().values()),
            ).fetchall()
            for row in rows:
                command = commands.load(command_id=str(row[0]), payload_reader=reader)
                verifier.execute_private_command(
                    PrivateCommandEnvelope(
                        command_id=command.command_id, payload=command.payload
                    ).model_dump(mode="json")
                )
    for promoted in rollouts.promoted_request_candidates(
        scope=settings.scope, now=datetime.now(UTC)
    ):
        advancement = promoted.advancement
        receipt_value = reader.get_json(
            uri=advancement.receipt_envelope_ref,
            expected_hash=advancement.receipt_envelope_hash,
            max_bytes=128_000,
        )
        receipt = ReleaseEffectReceiptEnvelope.model_validate(receipt_value)
        verify_release_effect_receipt(
            receipt,
            expected=ReleaseEffectReceiptExpected(
                scope=settings.scope,
                deployment_rollout_id=advancement.rollout_id,
                stage_ordinal=advancement.current_stage_ordinal,
                observation_window_generation=1,
                verification_profile_hash=advancement.verification_profile_hash,
                release_health_baseline_hash=advancement.release_health_baseline_hash,
                predeploy_snapshot_hash=advancement.predeploy_snapshot_hash,
                intended_effect_hash=advancement.intended_effect_hash,
                verifier_identity=advancement.verifier_identity,
                verifier_key_version=advancement.verifier_key_version,
            ),
            signature_ref=advancement.signature_ref,
            signature_hash=advancement.signature_hash,
            evidence=reader,
            kms=GoogleKmsPublicKeyReader(session),
        )
        if receipt.result is not ReleaseVerificationResult.VERIFIED:
            continue
        with connection.transaction():
            rollouts.mark_request_promoted(
                scope=settings.scope,
                candidate=promoted,
                receipt_hash=advancement.receipt_envelope_hash,
                coordinator_identity=settings.coordinator_principal,
            )
    for failed in rollouts.failed_request_candidates(scope=settings.scope):
        with connection.transaction():
            rollouts.mark_request_rollback_pending(
                scope=settings.scope,
                candidate=failed,
                coordinator_identity=settings.coordinator_principal,
            )
