"""Durable independent release-effect verification scheduling and receipts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.release_verification import ReleaseEffectReceiptEnvelope
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier


class ReleaseEffectVerificationConflict(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ReleaseEffectVerificationCandidate:
    rollout_id: str
    stage_ordinal: int
    verification_profile_hash: str
    predeploy_snapshot_hash: str
    intended_effect_hash: str
    observation_window_generation: int
    material_hash: str
    deadline: datetime


@dataclass(frozen=True, slots=True)
class ReleaseEffectVerificationMaterial:
    rollout_id: str
    code_change_request_id: str
    release_candidate_id: str
    release_target_profile_id: str
    target_observation_hash: str
    service_resource_name: str
    external_project_id: str
    service_name: str
    runtime_service_account: str
    deployment_manifest_profile_ref: str
    deployment_manifest_profile_hash: str
    build_artifact_ref: str
    candidate_revision: str
    prior_revision: str
    expected_assignment: tuple[tuple[str, int], ...]
    verification_profile_ref: str
    verification_profile_hash: str
    predeploy_snapshot_ref: str
    predeploy_snapshot_hash: str
    intended_effect_hash: str
    release_health_baseline_ref: str
    release_health_baseline_hash: str
    baseline_signature_ref: str
    baseline_signature_hash: str
    baseline_target_version: str
    baseline_assignment_hash: str
    verifier_identity: str
    verifier_key_version: str
    stage_ordinal: int
    observation_window_generation: int
    window_start: datetime
    window_end: datetime


@dataclass(frozen=True, slots=True)
class StoredReleaseEffectReceipt:
    envelope_ref: str
    envelope_hash: str
    signature_ref: str
    signature_hash: str
    observed_at: datetime


class PostgresReleaseEffectVerificationStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    @staticmethod
    def _material_hash(row: Mapping[str, Any]) -> str:
        return canonical_sha256(
            {
                "schema_version": 1,
                "command_kind": "VERIFY_RELEASE_EFFECT",
                "deployment_rollout_id": str(row["rollout_id"]),
                "stage_ordinal": int(row["stage_ordinal"]),
                "operation_material_hash": str(row["operation_material_hash"]),
                "verification_profile_hash": str(row["verification_profile_hash"]),
                "predeploy_snapshot_hash": str(row["predeploy_snapshot_hash"]),
                "intended_effect_hash": str(row["intended_effect_hash"]),
                "release_health_baseline_hash": str(row["release_health_baseline_hash"]),
                "observation_window_generation": 1,
            }
        )

    def candidates(
        self, *, scope: Scope, now: datetime, limit: int = 20
    ) -> tuple[ReleaseEffectVerificationCandidate, ...]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT rollout.id AS rollout_id,rollout.verification_profile_hash,
                          rollout.predeploy_snapshot_hash,rollout.intended_effect_hash,
                          rollout.release_health_baseline_hash,
                          operation.stage_ordinal,
                          operation.material_hash AS operation_material_hash,
                          operation.completed_at,target.observation_windows_seconds,
                          reservation.lease_expires_at
                     FROM solvan_delivery.deployment_rollouts rollout
                     JOIN solvan_delivery.deployment_rollout_operations operation
                       ON operation.organization_id=rollout.organization_id
                      AND operation.project_id=rollout.project_id
                      AND operation.environment_id=rollout.environment_id
                      AND operation.deployment_rollout_id=rollout.id
                      AND operation.status='SUCCEEDED'
                     JOIN solvan_delivery.release_target_profiles target
                       ON target.organization_id=rollout.organization_id
                      AND target.project_id=rollout.project_id
                      AND target.environment_id=rollout.environment_id
                      AND target.id=rollout.release_target_profile_id
                      AND target.profile_hash=rollout.release_target_profile_hash
                      AND target.status='ACTIVE'
                     JOIN solvan_delivery.release_target_reservations reservation
                       ON reservation.organization_id=rollout.organization_id
                      AND reservation.project_id=rollout.project_id
                      AND reservation.environment_id=rollout.environment_id
                      AND reservation.id=rollout.target_reservation_id
                      AND reservation.status IN ('HELD','RECONCILING')
                      AND reservation.lease_expires_at>%(now)s
                    WHERE rollout.organization_id=%(organization_id)s
                      AND rollout.project_id=%(project_id)s
                      AND rollout.environment_id=%(environment_id)s
                      AND rollout.status='CANARY_READY'
                      AND operation.stage_ordinal=(
                        SELECT max(latest.stage_ordinal)
                          FROM solvan_delivery.deployment_rollout_operations latest
                         WHERE latest.organization_id=rollout.organization_id
                           AND latest.project_id=rollout.project_id
                           AND latest.environment_id=rollout.environment_id
                           AND latest.deployment_rollout_id=rollout.id
                           AND latest.status='SUCCEEDED')
                      AND operation.completed_at
                          + make_interval(secs => target.observation_windows_seconds[
                              operation.stage_ordinal])<=%(now)s
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.release_verification_receipts receipt
                         WHERE receipt.organization_id=rollout.organization_id
                           AND receipt.project_id=rollout.project_id
                           AND receipt.environment_id=rollout.environment_id
                           AND receipt.deployment_rollout_id=rollout.id
                           AND receipt.stage_ordinal=operation.stage_ordinal
                           AND receipt.observation_window_generation=1)
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.private_command_dispatches command
                         WHERE command.organization_id=rollout.organization_id
                           AND command.project_id=rollout.project_id
                           AND command.environment_id=rollout.environment_id
                           AND command.command_kind='VERIFY_RELEASE_EFFECT'
                           AND command.subject_id=rollout.id
                           AND command.status IN ('PREPARED','ISSUED','RECONCILING'))
                    ORDER BY operation.completed_at,rollout.id LIMIT %(limit)s""",
                {**scope.canonical_dict(), "now": now, "limit": limit},
            )
            result: list[ReleaseEffectVerificationCandidate] = []
            for row in cursor.fetchall():
                windows = row["observation_windows_seconds"]
                stage = int(row["stage_ordinal"])
                if not isinstance(windows, list) or stage > len(windows):
                    raise ReleaseEffectVerificationConflict("release verification window is absent")
                result.append(
                    ReleaseEffectVerificationCandidate(
                        rollout_id=str(row["rollout_id"]),
                        stage_ordinal=stage,
                        verification_profile_hash=str(row["verification_profile_hash"]),
                        predeploy_snapshot_hash=str(row["predeploy_snapshot_hash"]),
                        intended_effect_hash=str(row["intended_effect_hash"]),
                        observation_window_generation=1,
                        material_hash=self._material_hash(row),
                        deadline=row["lease_expires_at"],
                    )
                )
            return tuple(result)

    def dispatchable_ids(self, *, scope: Scope, limit: int = 20) -> tuple[str, ...]:
        rows = self._connection.execute(
            """SELECT id FROM solvan_delivery.private_command_dispatches
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND command_kind='VERIFY_RELEASE_EFFECT'
                  AND status IN ('PREPARED','ISSUED','RECONCILING') AND deadline>now()
                ORDER BY created_at,id LIMIT %(limit)s""",
            {**scope.canonical_dict(), "limit": limit},
        ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def load(
        self, *, scope: Scope, rollout_id: str, material_hash: str
    ) -> ReleaseEffectVerificationMaterial:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT rollout.id AS rollout_id,candidate.code_change_request_id,
                          candidate.id AS release_candidate_id,candidate.build_artifact_ref,
                          rollout.release_target_profile_id,
                          rollout.predeploy_snapshot_hash AS target_observation_hash,
                          rollout.predeploy_snapshot_ref,rollout.predeploy_snapshot_hash,
                          rollout.intended_effect_hash,rollout.release_health_baseline_ref,
                          rollout.release_health_baseline_hash,
                          rollout.verification_profile_hash,
                          target.service_resource_name,target.external_project_id,
                          target.service_name,target.runtime_service_account,
                          target.deployment_manifest_profile_ref,
                          target.deployment_manifest_profile_hash,
                          target.verification_profile_ref,target.canary_percentages,
                          target.observation_windows_seconds,
                          baseline.signature_ref AS baseline_signature_ref,
                          baseline.signature_hash AS baseline_signature_hash,
                          baseline.target_version AS baseline_target_version,
                          baseline.target_assignment_hash AS baseline_assignment_hash,
                          baseline.verifier_identity,baseline.verifier_key_version,
                          operation.stage_ordinal,
                          operation.material_hash AS operation_material_hash,
                          operation.completed_at,
                          observation.current_revision AS prior_revision
                     FROM solvan_delivery.deployment_rollouts rollout
                     JOIN solvan_delivery.release_candidates candidate
                       ON candidate.organization_id=rollout.organization_id
                      AND candidate.project_id=rollout.project_id
                      AND candidate.environment_id=rollout.environment_id
                      AND candidate.id=rollout.release_candidate_id
                     JOIN solvan_delivery.release_target_profiles target
                       ON target.organization_id=rollout.organization_id
                      AND target.project_id=rollout.project_id
                      AND target.environment_id=rollout.environment_id
                      AND target.id=rollout.release_target_profile_id
                      AND target.profile_hash=rollout.release_target_profile_hash
                      AND target.status='ACTIVE'
                     JOIN solvan_delivery.release_health_baselines baseline
                       ON baseline.organization_id=rollout.organization_id
                      AND baseline.project_id=rollout.project_id
                      AND baseline.environment_id=rollout.environment_id
                      AND baseline.id=rollout.release_health_baseline_id
                      AND baseline.baseline_ref=rollout.release_health_baseline_ref
                      AND baseline.baseline_hash=rollout.release_health_baseline_hash
                     JOIN solvan_delivery.release_verifier_keys verifier_key
                       ON verifier_key.organization_id=baseline.organization_id
                      AND verifier_key.project_id=baseline.project_id
                      AND verifier_key.environment_id=baseline.environment_id
                      AND verifier_key.verifier_identity=baseline.verifier_identity
                      AND verifier_key.key_version=baseline.verifier_key_version
                      AND verifier_key.status='ACTIVE'
                     JOIN solvan_delivery.release_target_observations observation
                       ON observation.organization_id=rollout.organization_id
                      AND observation.project_id=rollout.project_id
                      AND observation.environment_id=rollout.environment_id
                      AND observation.observation_hash=rollout.predeploy_snapshot_hash
                     JOIN solvan_delivery.deployment_rollout_operations operation
                       ON operation.organization_id=rollout.organization_id
                      AND operation.project_id=rollout.project_id
                      AND operation.environment_id=rollout.environment_id
                      AND operation.deployment_rollout_id=rollout.id
                      AND operation.status='SUCCEEDED'
                      AND operation.stage_ordinal=(
                        SELECT max(latest.stage_ordinal)
                          FROM solvan_delivery.deployment_rollout_operations latest
                         WHERE latest.organization_id=rollout.organization_id
                           AND latest.project_id=rollout.project_id
                           AND latest.environment_id=rollout.environment_id
                           AND latest.deployment_rollout_id=rollout.id
                           AND latest.status='SUCCEEDED')
                    WHERE rollout.organization_id=%(organization_id)s
                      AND rollout.project_id=%(project_id)s
                      AND rollout.environment_id=%(environment_id)s
                      AND rollout.id=%(rollout_id)s AND rollout.status='CANARY_READY'
                    FOR SHARE OF rollout,candidate,target,baseline,verifier_key,operation""",
                {**scope.canonical_dict(), "rollout_id": rollout_id},
            )
            row = cursor.fetchone()
        if row is None or self._material_hash(row) != material_hash:
            raise ReleaseEffectVerificationConflict("release verification authority is stale")
        percentages, windows = row["canary_percentages"], row["observation_windows_seconds"]
        stage = int(row["stage_ordinal"])
        if (
            not isinstance(percentages, list)
            or not isinstance(windows, list)
            or stage > len(percentages)
            or stage > len(windows)
        ):
            raise ReleaseEffectVerificationConflict("release verification policy is malformed")
        service_name = str(row["service_name"])
        candidate_id = str(row["release_candidate_id"])
        candidate_revision = f"{service_name[:34]}-sv-{candidate_id[-20:].lower()}"
        percentage = int(percentages[stage - 1])
        expected_assignment = (
            ((candidate_revision, 100),)
            if percentage == 100
            else tuple(
                sorted(
                    (
                        (candidate_revision, percentage),
                        (str(row["prior_revision"]), 100 - percentage),
                    )
                )
            )
        )
        window_start = row["completed_at"]
        return ReleaseEffectVerificationMaterial(
            rollout_id=rollout_id,
            code_change_request_id=str(row["code_change_request_id"]),
            release_candidate_id=candidate_id,
            release_target_profile_id=str(row["release_target_profile_id"]),
            target_observation_hash=str(row["target_observation_hash"]),
            service_resource_name=str(row["service_resource_name"]),
            external_project_id=str(row["external_project_id"]),
            service_name=service_name,
            runtime_service_account=str(row["runtime_service_account"]),
            deployment_manifest_profile_ref=str(row["deployment_manifest_profile_ref"]),
            deployment_manifest_profile_hash=str(row["deployment_manifest_profile_hash"]),
            build_artifact_ref=str(row["build_artifact_ref"]),
            candidate_revision=candidate_revision,
            prior_revision=str(row["prior_revision"]),
            expected_assignment=expected_assignment,
            verification_profile_ref=str(row["verification_profile_ref"]),
            verification_profile_hash=str(row["verification_profile_hash"]),
            predeploy_snapshot_ref=str(row["predeploy_snapshot_ref"]),
            predeploy_snapshot_hash=str(row["predeploy_snapshot_hash"]),
            intended_effect_hash=str(row["intended_effect_hash"]),
            release_health_baseline_ref=str(row["release_health_baseline_ref"]),
            release_health_baseline_hash=str(row["release_health_baseline_hash"]),
            baseline_signature_ref=str(row["baseline_signature_ref"]),
            baseline_signature_hash=str(row["baseline_signature_hash"]),
            baseline_target_version=str(row["baseline_target_version"]),
            baseline_assignment_hash=str(row["baseline_assignment_hash"]),
            verifier_identity=str(row["verifier_identity"]),
            verifier_key_version=str(row["verifier_key_version"]),
            stage_ordinal=stage,
            observation_window_generation=1,
            window_start=window_start,
            window_end=window_start + timedelta(seconds=int(windows[stage - 1])),
        )

    def existing(
        self, *, scope: Scope, material: ReleaseEffectVerificationMaterial
    ) -> StoredReleaseEffectReceipt | None:
        row = self._connection.execute(
            """SELECT receipt_envelope_ref,receipt_envelope_hash,signature_ref,
                      signature_hash,observed_at,verification_profile_hash,
                      predeploy_snapshot_hash,intended_effect_hash,verifier_identity,
                      verifier_key_version,release_health_baseline_hash
                 FROM solvan_delivery.release_verification_receipts
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND deployment_rollout_id=%(rollout_id)s
                  AND stage_ordinal=%(stage)s
                  AND observation_window_generation=%(generation)s""",
            {
                **scope.canonical_dict(),
                "rollout_id": material.rollout_id,
                "stage": material.stage_ordinal,
                "generation": material.observation_window_generation,
            },
        ).fetchone()
        if row is None:
            return None
        if tuple(str(value) for value in row[5:]) != (
            material.verification_profile_hash,
            material.predeploy_snapshot_hash,
            material.intended_effect_hash,
            material.verifier_identity,
            material.verifier_key_version,
            material.release_health_baseline_hash,
        ):
            raise ReleaseEffectVerificationConflict(
                "release verification replay authority conflicts"
            )
        return StoredReleaseEffectReceipt(
            envelope_ref=str(row[0]),
            envelope_hash=str(row[1]),
            signature_ref=str(row[2]),
            signature_hash=str(row[3]),
            observed_at=row[4],
        )

    def record(
        self,
        *,
        scope: Scope,
        material: ReleaseEffectVerificationMaterial,
        envelope: ReleaseEffectReceiptEnvelope,
        receipt_envelope_ref: str,
        receipt_envelope_hash: str,
        signature_ref: str,
        signature_hash: str,
    ) -> str:
        if receipt_envelope_hash != canonical_sha256(envelope.model_dump(mode="json")):
            raise ReleaseEffectVerificationConflict("release receipt envelope hash differs")
        receipt_id = new_identifier("rvr")
        row = self._connection.execute(
            """INSERT INTO solvan_delivery.release_verification_receipts
                 (organization_id,project_id,environment_id,id,deployment_rollout_id,
                  verifier_identity,verification_profile_hash,predeploy_snapshot_ref,
                  predeploy_snapshot_hash,postdeploy_observation_ref,
                  postdeploy_observation_hash,intended_effect_hash,result,signature_ref,
                  signature_hash,observed_at,stage_ordinal,observation_window_generation,
                  window_start,window_end,observed_target_version,
                  observed_assignment_hash,verifier_key_version,receipt_envelope_ref,
                  receipt_envelope_hash,release_health_baseline_ref,
                  release_health_baseline_hash)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(rollout_id)s,%(verifier)s,%(profile_hash)s,%(pre_ref)s,%(pre_hash)s,
                 %(post_ref)s,%(post_hash)s,%(effect_hash)s,%(result)s,%(signature_ref)s,
                 %(signature_hash)s,%(observed_at)s,%(stage)s,%(generation)s,
                 %(window_start)s,%(window_end)s,%(target_version)s,%(assignment_hash)s,
                 %(key_version)s,%(envelope_ref)s,%(envelope_hash)s,%(baseline_ref)s,
                 %(baseline_hash)s)
               ON CONFLICT (organization_id,project_id,environment_id,
                            deployment_rollout_id,stage_ordinal,
                            observation_window_generation) DO NOTHING RETURNING id""",
            {
                **scope.canonical_dict(),
                "id": receipt_id,
                "rollout_id": material.rollout_id,
                "verifier": material.verifier_identity,
                "profile_hash": material.verification_profile_hash,
                "pre_ref": material.predeploy_snapshot_ref,
                "pre_hash": material.predeploy_snapshot_hash,
                "post_ref": envelope.postdeploy_observation_ref,
                "post_hash": envelope.postdeploy_observation_hash,
                "effect_hash": material.intended_effect_hash,
                "result": envelope.result.value,
                "signature_ref": signature_ref,
                "signature_hash": signature_hash,
                "observed_at": envelope.observed_at,
                "stage": material.stage_ordinal,
                "generation": material.observation_window_generation,
                "window_start": material.window_start,
                "window_end": material.window_end,
                "target_version": envelope.observed_target_version,
                "assignment_hash": envelope.observed_assignment_hash,
                "key_version": material.verifier_key_version,
                "envelope_ref": receipt_envelope_ref,
                "envelope_hash": receipt_envelope_hash,
                "baseline_ref": material.release_health_baseline_ref,
                "baseline_hash": material.release_health_baseline_hash,
            },
        ).fetchone()
        if row is not None:
            return str(row[0])
        existing = self._connection.execute(
            """SELECT id,receipt_envelope_hash,signature_hash
                 FROM solvan_delivery.release_verification_receipts
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND deployment_rollout_id=%(rollout_id)s AND stage_ordinal=%(stage)s
                  AND observation_window_generation=%(generation)s""",
            {
                **scope.canonical_dict(),
                "rollout_id": material.rollout_id,
                "stage": material.stage_ordinal,
                "generation": material.observation_window_generation,
            },
        ).fetchone()
        if existing is None or tuple(existing[1:]) != (receipt_envelope_hash, signature_hash):
            raise ReleaseEffectVerificationConflict("release verification replay conflicts")
        return str(existing[0])
