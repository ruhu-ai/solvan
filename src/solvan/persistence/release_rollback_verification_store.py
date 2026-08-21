"""Independent rollback-effect verification authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.release_verification import ReleaseRollbackReceiptEnvelope
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier


@dataclass(frozen=True, slots=True)
class RollbackVerificationMaterial:
    rollout_id: str
    material_hash: str
    deadline: datetime
    service_resource_name: str
    runtime_service_account: str
    deployment_manifest_profile_ref: str
    deployment_manifest_profile_hash: str
    expected_revision: str
    verifier_identity: str
    verifier_key_version: str


@dataclass(frozen=True, slots=True)
class StoredRollbackVerificationReceipt:
    envelope_ref: str
    envelope_hash: str
    signature_ref: str
    signature_hash: str
    observed_at: datetime


class PostgresReleaseRollbackVerificationStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def candidates(
        self, *, scope: Scope, limit: int = 20
    ) -> tuple[RollbackVerificationMaterial, ...]:
        return self._rows(scope=scope, rollout_id=None, material_hash=None, limit=limit)

    def load(
        self, *, scope: Scope, rollout_id: str, material_hash: str
    ) -> RollbackVerificationMaterial:
        rows = self._rows(scope=scope, rollout_id=rollout_id, material_hash=material_hash, limit=2)
        if len(rows) != 1:
            raise ValueError("rollback verification authority is stale")
        return rows[0]

    def _rows(
        self, *, scope: Scope, rollout_id: str | None, material_hash: str | None, limit: int
    ) -> tuple[RollbackVerificationMaterial, ...]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT rollout.id,target.service_resource_name,
                          target.runtime_service_account,
                          target.deployment_manifest_profile_ref,
                          target.deployment_manifest_profile_hash,
                          target.verifier_identity,target.verifier_key_version,
                          observation.current_revision,reservation.lease_expires_at,
                          operation.response_hash
                     FROM solvan_delivery.deployment_rollouts rollout
                     JOIN solvan_delivery.release_target_profiles target
                       ON (target.organization_id,target.project_id,
                           target.environment_id,target.id)=
                          (rollout.organization_id,rollout.project_id,
                           rollout.environment_id,rollout.release_target_profile_id)
                      AND target.status='ACTIVE'
                     JOIN solvan_delivery.release_target_observations observation
                       ON observation.organization_id=rollout.organization_id
                      AND observation.project_id=rollout.project_id
                      AND observation.environment_id=rollout.environment_id
                      AND observation.observation_hash=rollout.predeploy_snapshot_hash
                     JOIN solvan_delivery.release_target_reservations reservation
                       ON reservation.organization_id=rollout.organization_id
                      AND reservation.project_id=rollout.project_id
                      AND reservation.environment_id=rollout.environment_id
                      AND reservation.id=rollout.target_reservation_id
                      AND reservation.status IN ('HELD','RECONCILING')
                      AND reservation.lease_expires_at>now()
                     JOIN solvan_delivery.deployment_rollout_operations operation
                       ON operation.organization_id=rollout.organization_id
                      AND operation.project_id=rollout.project_id
                      AND operation.environment_id=rollout.environment_id
                      AND operation.deployment_rollout_id=rollout.id
                      AND operation.operation_kind='ROLLBACK_RELEASE'
                      AND operation.status='SUCCEEDED'
                    WHERE rollout.organization_id=%(organization_id)s
                      AND rollout.project_id=%(project_id)s
                      AND rollout.environment_id=%(environment_id)s
                      AND rollout.status='ROLLBACK_PENDING'
                      AND (%(rollout_id)s IS NULL OR rollout.id=%(rollout_id)s)
                      AND (%(rollout_id)s IS NOT NULL OR NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.release_rollback_verification_receipts receipt
                         WHERE receipt.organization_id=rollout.organization_id
                           AND receipt.project_id=rollout.project_id
                           AND receipt.environment_id=rollout.environment_id
                           AND receipt.deployment_rollout_id=rollout.id))
                      AND (%(rollout_id)s IS NOT NULL OR NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.private_command_dispatches command
                         WHERE command.organization_id=rollout.organization_id
                           AND command.project_id=rollout.project_id
                           AND command.environment_id=rollout.environment_id
                           AND command.command_kind='VERIFY_ROLLBACK_EFFECT'
                           AND command.subject_id=rollout.id
                           AND command.status IN ('PREPARED','ISSUED','RECONCILING'))
                          )
                    ORDER BY operation.completed_at LIMIT %(limit)s""",
                {**scope.canonical_dict(), "rollout_id": rollout_id, "limit": limit},
            )
            result = []
            for row in cursor.fetchall():
                digest = canonical_sha256(
                    {
                        "schema_version": 1,
                        "command_kind": "VERIFY_ROLLBACK_EFFECT",
                        "deployment_rollout_id": str(row["id"]),
                        "rollback_operation_receipt_hash": str(row["response_hash"]),
                        "expected_revision": str(row["current_revision"]),
                    }
                )
                if material_hash is not None and digest != material_hash:
                    continue
                result.append(
                    RollbackVerificationMaterial(
                        rollout_id=str(row["id"]),
                        material_hash=digest,
                        deadline=row["lease_expires_at"],
                        service_resource_name=str(row["service_resource_name"]),
                        runtime_service_account=str(row["runtime_service_account"]),
                        deployment_manifest_profile_ref=str(row["deployment_manifest_profile_ref"]),
                        deployment_manifest_profile_hash=str(
                            row["deployment_manifest_profile_hash"]
                        ),
                        expected_revision=str(row["current_revision"]),
                        verifier_identity=str(row["verifier_identity"]),
                        verifier_key_version=str(row["verifier_key_version"]),
                    )
                )
            return tuple(result)

    def existing(
        self, *, scope: Scope, material: RollbackVerificationMaterial
    ) -> StoredRollbackVerificationReceipt | None:
        row = self._connection.execute(
            """SELECT receipt_envelope_ref,receipt_envelope_hash,signature_ref,
                      signature_hash,observed_at,expected_revision,
                      verifier_identity,verifier_key_version
                 FROM solvan_delivery.release_rollback_verification_receipts
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND deployment_rollout_id=%(rollout_id)s""",
            {**scope.canonical_dict(), "rollout_id": material.rollout_id},
        ).fetchone()
        if row is None:
            return None
        if tuple(str(value) for value in row[5:]) != (
            material.expected_revision,
            material.verifier_identity,
            material.verifier_key_version,
        ):
            raise ValueError("rollback verification replay authority conflicts")
        return StoredRollbackVerificationReceipt(
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
        material: RollbackVerificationMaterial,
        receipt: ReleaseRollbackReceiptEnvelope,
        envelope_ref: str,
        envelope_hash: str,
        signature_ref: str,
        signature_hash: str,
    ) -> None:
        row = self._connection.execute(
            """INSERT INTO solvan_delivery.release_rollback_verification_receipts
                 (organization_id,project_id,environment_id,id,deployment_rollout_id,
                  expected_revision,observed_target_version,observed_assignment_hash,result,
                  verifier_identity,verifier_key_version,receipt_envelope_ref,
                  receipt_envelope_hash,signature_ref,signature_hash,observed_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(rollout_id)s,%(revision)s,%(version)s,%(assignment)s,%(result)s,%(verifier)s,
                 %(key)s,%(envelope_ref)s,%(envelope_hash)s,%(signature_ref)s,
                 %(signature_hash)s,%(observed_at)s)
               ON CONFLICT (organization_id,project_id,environment_id,
                            deployment_rollout_id) DO NOTHING RETURNING id""",
            {
                **scope.canonical_dict(),
                "id": new_identifier("rrv"),
                "rollout_id": material.rollout_id,
                "revision": material.expected_revision,
                "version": receipt.observed_target_version,
                "assignment": receipt.observed_assignment_hash,
                "result": receipt.result.value,
                "verifier": material.verifier_identity,
                "key": material.verifier_key_version,
                "envelope_ref": envelope_ref,
                "envelope_hash": envelope_hash,
                "signature_ref": signature_ref,
                "signature_hash": signature_hash,
                "observed_at": receipt.observed_at,
            },
        ).fetchone()
        if row is not None:
            return
        existing = self.existing(scope=scope, material=material)
        if existing is None or (
            existing.envelope_ref,
            existing.envelope_hash,
            existing.signature_ref,
            existing.signature_hash,
            existing.observed_at,
        ) != (
            envelope_ref,
            envelope_hash,
            signature_ref,
            signature_hash,
            receipt.observed_at,
        ):
            raise ValueError("rollback verification replay conflicts")
