"""Cloud SQL authority for release signer keys and exact deployment targets."""

from __future__ import annotations

from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.release_authority import (
    CloudRunReleaseTargetInput,
    ReleaseSignerKeyInput,
    ReleaseVerifierKeyInput,
)
from solvan.domain import Scope, new_identifier


class PostgresReleaseAuthorityStore:
    def __init__(self, connection: Connection[Any], *, scope: Scope) -> None:
        self._connection = connection
        self._scope = scope

    def register_signer(
        self, *, value: ReleaseSignerKeyInput, public_key_pem: bytes
    ) -> tuple[str, str]:
        policy_hash = value.policy_hash(public_key_pem=public_key_pem)
        existing = self._connection.execute(
            """SELECT id,signer_policy_hash,status FROM solvan_delivery.release_signer_keys
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND signer_identity=%(identity)s
                  AND key_version=%(key_version)s FOR UPDATE""",
            {
                **self._scope.canonical_dict(),
                "identity": value.signer_identity,
                "key_version": value.key_version,
            },
        ).fetchone()
        if existing is not None:
            if existing[1] != policy_hash or existing[2] != "ACTIVE":
                raise ValueError("RELEASE_SIGNER_KEY_CONFLICT")
            return str(existing[0]), policy_hash
        self._connection.execute(
            """UPDATE solvan_delivery.release_signer_keys
                  SET status='REVOKED',revoked_at=now(),
                      revoked_reason='Superseded by a newly approved release signer key'
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND status='ACTIVE'""",
            self._scope.canonical_dict(),
        )
        signer_id = new_identifier("rsk")
        self._connection.execute(
            """INSERT INTO solvan_delivery.release_signer_keys
                 (organization_id,project_id,environment_id,id,signer_identity,key_version,
                  public_verification_ref,signer_policy_hash,status,activated_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(identity)s,%(key_version)s,%(key_version)s,%(policy_hash)s,'ACTIVE',now())""",
            {
                **self._scope.canonical_dict(),
                "id": signer_id,
                "identity": value.signer_identity,
                "key_version": value.key_version,
                "policy_hash": policy_hash,
            },
        )
        return signer_id, policy_hash

    def register_verifier(
        self, *, value: ReleaseVerifierKeyInput, public_key_pem: bytes
    ) -> tuple[str, str]:
        policy_hash = value.policy_hash(public_key_pem=public_key_pem)
        existing = self._connection.execute(
            """SELECT id,verifier_policy_hash,status
                 FROM solvan_delivery.release_verifier_keys
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND verifier_identity=%(identity)s
                  AND key_version=%(key_version)s FOR UPDATE""",
            {
                **self._scope.canonical_dict(),
                "identity": value.signer_identity,
                "key_version": value.key_version,
            },
        ).fetchone()
        if existing is not None:
            if existing[1] != policy_hash or existing[2] != "ACTIVE":
                raise ValueError("RELEASE_VERIFIER_KEY_CONFLICT")
            return str(existing[0]), policy_hash
        self._connection.execute(
            """UPDATE solvan_delivery.release_verifier_keys
                  SET status='REVOKED',revoked_at=now(),
                      revoked_reason='Superseded by a newly approved release verifier key'
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND status='ACTIVE'""",
            self._scope.canonical_dict(),
        )
        key_id = new_identifier("rvk")
        self._connection.execute(
            """INSERT INTO solvan_delivery.release_verifier_keys
                 (organization_id,project_id,environment_id,id,verifier_identity,key_version,
                  public_verification_ref,verifier_policy_hash,status,activated_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(identity)s,%(key_version)s,%(key_version)s,%(policy_hash)s,'ACTIVE',now())""",
            {
                **self._scope.canonical_dict(),
                "id": key_id,
                "identity": value.signer_identity,
                "key_version": value.key_version,
                "policy_hash": policy_hash,
            },
        )
        return key_id, policy_hash

    def register_target(
        self,
        *,
        value: CloudRunReleaseTargetInput,
        manifest_ref: str,
        manifest_hash: str,
        rollout_ref: str,
        rollout_hash: str,
        verification_ref: str,
        verification_hash: str,
        principal: str,
    ) -> str:
        current = self._connection.execute(
            """SELECT id,profile_hash,expected_target_epoch
                 FROM solvan_delivery.release_target_profiles
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND target_key=%(target_key)s
                  AND status='ACTIVE' FOR UPDATE""",
            {**self._scope.canonical_dict(), "target_key": value.target_key},
        ).fetchone()
        if current is not None and current[1] == value.profile_hash:
            return str(current[0])
        if current is None and value.expected_target_epoch != 1:
            raise ValueError("RELEASE_TARGET_INITIAL_EPOCH_MUST_BE_ONE")
        if current is not None and value.expected_target_epoch != int(current[2]) + 1:
            raise ValueError("RELEASE_TARGET_EPOCH_MUST_INCREMENT_BY_ONE")
        if current is not None:
            self._connection.execute(
                """UPDATE solvan_delivery.release_target_profiles
                      SET status='REVOKED',revoked_at=now(),
                          revoked_reason='Superseded by a newly approved target profile'
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(id)s""",
                {**self._scope.canonical_dict(), "id": current[0]},
            )
        profile_id = new_identifier("rtp")
        self._connection.execute(
            """INSERT INTO solvan_delivery.release_target_profiles
                 (organization_id,project_id,environment_id,id,target_key,provider_kind,
                  service_resource_name,external_project_id,location,service_name,
                  expected_target_epoch,runtime_service_account,
                  deployment_manifest_profile_ref,deployment_manifest_profile_hash,
                  rollout_policy_ref,rollout_policy_hash,canary_percentages,
                  observation_windows_seconds,rollout_deadline_seconds,
                  maximum_concurrent_rollouts,verification_profile_id,
                  verification_profile_version,verification_profile_ref,
                  verification_profile_hash,profile_hash,status,approved_by_principal,approved_at,
                  verifier_identity,verifier_key_version)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(target_key)s,'GCP_CLOUD_RUN_V2',%(resource)s,%(external_project)s,
                 %(location)s,%(service)s,%(epoch)s,%(runtime_identity)s,%(manifest_ref)s,
                 %(manifest_hash)s,%(rollout_ref)s,%(rollout_hash)s,%(percentages)s,
                 %(windows)s,%(deadline)s,1,%(verification_id)s,%(verification_version)s,
                 %(verification_ref)s,%(verification_hash)s,%(profile_hash)s,'ACTIVE',
                 %(principal)s,now(),%(verifier_identity)s,%(verifier_key_version)s)""",
            {
                **self._scope.canonical_dict(),
                "id": profile_id,
                "target_key": value.target_key,
                "resource": value.service_resource_name,
                "external_project": value.external_project_id,
                "location": value.location,
                "service": value.service_name,
                "epoch": value.expected_target_epoch,
                "runtime_identity": value.runtime_service_account,
                "manifest_ref": manifest_ref,
                "manifest_hash": manifest_hash,
                "rollout_ref": rollout_ref,
                "rollout_hash": rollout_hash,
                "percentages": list(value.canary_percentages),
                "windows": list(value.observation_windows_seconds),
                "deadline": value.rollout_deadline_seconds,
                "verification_id": value.verification_profile_id,
                "verification_version": value.verification_profile_version,
                "verification_ref": verification_ref,
                "verification_hash": verification_hash,
                "profile_hash": value.profile_hash,
                "principal": principal,
                "verifier_identity": value.verifier_identity,
                "verifier_key_version": value.verifier_key_version,
            },
        )
        return profile_id

    def list_targets(self) -> list[dict[str, Any]]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,target_key,provider_kind,service_resource_name,
                          expected_target_epoch,runtime_service_account,canary_percentages,
                          verification_profile_id,verification_profile_version,profile_hash,
                          verifier_identity,verifier_key_version,
                          status,approved_by_principal,approved_at,revoked_at,revoked_reason
                     FROM solvan_delivery.release_target_profiles
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                    ORDER BY created_at DESC LIMIT 100""",
                self._scope.canonical_dict(),
            )
            return [dict(row) for row in cursor.fetchall()]

    def list_signers(self) -> list[dict[str, Any]]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,signer_identity,key_version,signer_policy_hash,status,
                          activated_at,revoked_at,revoked_reason
                     FROM solvan_delivery.release_signer_keys
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                    ORDER BY created_at DESC LIMIT 100""",
                self._scope.canonical_dict(),
            )
            return [dict(row) for row in cursor.fetchall()]

    def list_verifiers(self) -> list[dict[str, Any]]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,verifier_identity,key_version,verifier_policy_hash,status,
                          activated_at,revoked_at,revoked_reason
                     FROM solvan_delivery.release_verifier_keys
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                    ORDER BY created_at DESC LIMIT 100""",
                self._scope.canonical_dict(),
            )
            return [dict(row) for row in cursor.fetchall()]
