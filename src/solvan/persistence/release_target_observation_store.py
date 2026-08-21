"""Durable authority for exact predeployment Cloud Run observations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.release_targets import ReleaseTargetObservation
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier


class ReleaseTargetObservationConflict(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ReleaseTargetObservationCandidate:
    request_id: str
    material_hash: str
    sequence_no: int
    deadline: datetime


@dataclass(frozen=True, slots=True)
class ReleaseTargetMaterial:
    request_id: str
    request_sequence_no: int
    release_candidate_id: str
    release_target_profile_id: str
    release_target_profile_hash: str
    target_key: str
    expected_target_epoch: int
    service_resource_name: str
    runtime_service_account: str
    deployment_manifest_profile_ref: str
    deployment_manifest_profile_hash: str


class PostgresReleaseTargetObservationStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def candidates(
        self, *, scope: Scope, limit: int = 20
    ) -> tuple[ReleaseTargetObservationCandidate, ...]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT request.id,request.sequence_no,request.expires_at,
                          candidate.id AS candidate_id,candidate.build_artifact_hash,
                          target.id AS target_id,target.profile_hash,target.expected_target_epoch
                     FROM solvan_delivery.code_change_requests request
                     JOIN solvan_delivery.release_candidates candidate
                       ON candidate.organization_id=request.organization_id
                      AND candidate.project_id=request.project_id
                      AND candidate.environment_id=request.environment_id
                      AND candidate.code_change_request_id=request.id
                     JOIN solvan_delivery.code_delivery_profiles delivery
                       ON delivery.organization_id=request.organization_id
                      AND delivery.project_id=request.project_id
                      AND delivery.environment_id=request.environment_id
                      AND delivery.id=request.code_delivery_profile_id
                     JOIN solvan_delivery.release_target_profiles target
                       ON target.organization_id=delivery.organization_id
                      AND target.project_id=delivery.project_id
                      AND target.environment_id=delivery.environment_id
                      AND target.id=delivery.release_target_profile_id
                      AND target.profile_hash=delivery.release_target_profile_hash
                    WHERE request.organization_id=%(organization_id)s
                      AND request.project_id=%(project_id)s
                      AND request.environment_id=%(environment_id)s
                      AND request.state='RELEASE_CANDIDATE' AND request.expires_at>now()
                      AND delivery.status='ACTIVE' AND target.status='ACTIVE'
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.private_command_dispatches command
                         WHERE command.organization_id=request.organization_id
                           AND command.project_id=request.project_id
                           AND command.environment_id=request.environment_id
                           AND command.command_kind='OBSERVE_RELEASE_TARGET'
                           AND command.subject_id=request.id)
                    ORDER BY request.created_at LIMIT %(limit)s""",
                {**scope.canonical_dict(), "limit": limit},
            )
            result = []
            for row in cursor.fetchall():
                material_hash = canonical_sha256(
                    {
                        "schema_version": 1,
                        "command_kind": "OBSERVE_RELEASE_TARGET",
                        "code_change_request_id": str(row["id"]),
                        "release_candidate_id": str(row["candidate_id"]),
                        "build_artifact_hash": str(row["build_artifact_hash"]),
                        "release_target_profile_id": str(row["target_id"]),
                        "release_target_profile_hash": str(row["profile_hash"]),
                        "expected_target_epoch": int(row["expected_target_epoch"]),
                        "transition_sequence_no": int(row["sequence_no"]),
                    }
                )
                result.append(
                    ReleaseTargetObservationCandidate(
                        str(row["id"]),
                        material_hash,
                        int(row["sequence_no"]),
                        row["expires_at"],
                    )
                )
            return tuple(result)

    def dispatchable_ids(self, *, scope: Scope, limit: int = 20) -> tuple[str, ...]:
        rows = self._connection.execute(
            """SELECT id FROM solvan_delivery.private_command_dispatches
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND command_kind='OBSERVE_RELEASE_TARGET'
                  AND status IN ('PREPARED','ISSUED','RECONCILING') AND deadline>now()
                ORDER BY created_at,id LIMIT %(limit)s""",
            {**scope.canonical_dict(), "limit": limit},
        ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def load(self, *, scope: Scope, request_id: str, material_hash: str) -> ReleaseTargetMaterial:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT request.id,request.sequence_no,candidate.id AS candidate_id,
                          target.id AS target_id,target.profile_hash,target.target_key,
                          target.expected_target_epoch,target.service_resource_name,
                          target.runtime_service_account,target.deployment_manifest_profile_ref,
                          target.deployment_manifest_profile_hash
                     FROM solvan_delivery.code_change_requests request
                     JOIN solvan_delivery.release_candidates candidate
                       ON candidate.organization_id=request.organization_id
                      AND candidate.project_id=request.project_id
                      AND candidate.environment_id=request.environment_id
                      AND candidate.code_change_request_id=request.id
                     JOIN solvan_delivery.code_delivery_profiles delivery
                       ON delivery.organization_id=request.organization_id
                      AND delivery.project_id=request.project_id
                      AND delivery.environment_id=request.environment_id
                      AND delivery.id=request.code_delivery_profile_id
                     JOIN solvan_delivery.release_target_profiles target
                       ON target.organization_id=delivery.organization_id
                      AND target.project_id=delivery.project_id
                      AND target.environment_id=delivery.environment_id
                      AND target.id=delivery.release_target_profile_id
                      AND target.profile_hash=delivery.release_target_profile_hash
                     JOIN solvan_delivery.private_command_dispatches command
                       ON command.organization_id=request.organization_id
                      AND command.project_id=request.project_id
                      AND command.environment_id=request.environment_id
                      AND command.subject_id=request.id
                      AND command.command_kind='OBSERVE_RELEASE_TARGET'
                      AND command.material_hash=%(material_hash)s
                    WHERE request.organization_id=%(organization_id)s
                      AND request.project_id=%(project_id)s
                      AND request.environment_id=%(environment_id)s
                      AND request.id=%(request_id)s AND request.state='RELEASE_CANDIDATE'
                      AND request.expires_at>now() AND delivery.status='ACTIVE'
                      AND target.status='ACTIVE' FOR SHARE OF request,candidate,delivery,target""",
                {
                    **scope.canonical_dict(),
                    "request_id": request_id,
                    "material_hash": material_hash,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise ReleaseTargetObservationConflict("release target authority is stale")
        return ReleaseTargetMaterial(
            request_id=str(row["id"]),
            request_sequence_no=int(row["sequence_no"]),
            release_candidate_id=str(row["candidate_id"]),
            release_target_profile_id=str(row["target_id"]),
            release_target_profile_hash=str(row["profile_hash"]),
            target_key=str(row["target_key"]),
            expected_target_epoch=int(row["expected_target_epoch"]),
            service_resource_name=str(row["service_resource_name"]),
            runtime_service_account=str(row["runtime_service_account"]),
            deployment_manifest_profile_ref=str(row["deployment_manifest_profile_ref"]),
            deployment_manifest_profile_hash=str(row["deployment_manifest_profile_hash"]),
        )

    def record(
        self,
        *,
        scope: Scope,
        material: ReleaseTargetMaterial,
        observation: ReleaseTargetObservation,
        assignment_ref: str,
        assignment_hash: str,
        observation_ref: str,
        observation_hash: str,
        observer_identity: str,
        observer_revision: str,
        observed_at: datetime,
    ) -> str:
        prior = self._connection.execute(
            """SELECT id FROM solvan_delivery.release_candidates
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND build_artifact_ref=%(image)s""",
            {**scope.canonical_dict(), "image": observation.image},
        ).fetchall()
        if len(prior) != 1 or observation.traffic != ((observation.latest_ready_revision, 100),):
            raise ReleaseTargetObservationConflict(
                "automated rollout requires one known fully assigned predeploy release"
            )
        if str(prior[0][0]) == material.release_candidate_id:
            raise ReleaseTargetObservationConflict(
                "release candidate is already fully assigned to the target"
            )
        observation_id = new_identifier("rto")
        self._connection.execute(
            """INSERT INTO solvan_delivery.release_target_observations
                 (organization_id,project_id,environment_id,id,code_change_request_id,
                  release_candidate_id,release_target_profile_id,target_key,target_version,
                  target_epoch,service_generation,service_etag_hash,runtime_service_account,
                  current_release_candidate_id,current_revision,assignment_ref,assignment_hash,
                  observation_ref,observation_hash,observer_identity,observer_service_revision,
                  observed_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                  %(request_id)s,%(candidate_id)s,%(target_id)s,%(target_key)s,%(target_version)s,
                  %(target_epoch)s,%(generation)s,%(etag_hash)s,%(runtime_identity)s,
                  %(prior_candidate_id)s,%(revision)s,%(assignment_ref)s,%(assignment_hash)s,
                  %(observation_ref)s,%(observation_hash)s,%(observer)s,%(observer_revision)s,
                  %(observed_at)s)""",
            {
                **scope.canonical_dict(),
                "id": observation_id,
                "request_id": material.request_id,
                "candidate_id": material.release_candidate_id,
                "target_id": material.release_target_profile_id,
                "target_key": material.target_key,
                "target_version": str(observation.generation),
                "target_epoch": material.expected_target_epoch,
                "generation": observation.generation,
                "etag_hash": canonical_sha256({"etag": observation.etag}),
                "runtime_identity": observation.runtime_service_account,
                "prior_candidate_id": prior[0][0],
                "revision": observation.latest_ready_revision,
                "assignment_ref": assignment_ref,
                "assignment_hash": assignment_hash,
                "observation_ref": observation_ref,
                "observation_hash": observation_hash,
                "observer": observer_identity,
                "observer_revision": observer_revision,
                "observed_at": observed_at,
            },
        )
        sequence = material.request_sequence_no + 1
        self._connection.execute(
            """INSERT INTO solvan_delivery.code_change_transitions
                 (organization_id,project_id,environment_id,id,code_change_request_id,
                  sequence_no,from_state,to_state,expected_sequence_no,input_hash,
                  idempotency_key,actor_kind,actor_identity,receipt_ref,receipt_hash)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(transition_id)s,
                  %(request_id)s,%(sequence)s,'RELEASE_CANDIDATE','DEPLOYMENT_APPROVAL_PENDING',
                  %(expected_sequence)s,%(input_hash)s,%(idempotency_key)s,
                  'DEPLOYMENT_CONTROLLER',%(observer)s,%(observation_ref)s,%(observation_hash)s)""",
            {
                **scope.canonical_dict(),
                "transition_id": new_identifier("cct"),
                "request_id": material.request_id,
                "sequence": sequence,
                "expected_sequence": material.request_sequence_no,
                "input_hash": observation_hash,
                "idempotency_key": f"release-target-observation:{observation_id}",
                "observer": observer_identity,
                "observation_ref": observation_ref,
                "observation_hash": observation_hash,
            },
        )
        return observation_id


def target_observation_document(
    *, material: ReleaseTargetMaterial, observation: ReleaseTargetObservation
) -> Mapping[str, object]:
    return {
        "schema_version": 1,
        "code_change_request_id": material.request_id,
        "release_candidate_id": material.release_candidate_id,
        "release_target_profile_id": material.release_target_profile_id,
        "release_target_profile_hash": material.release_target_profile_hash,
        "target_key": material.target_key,
        "target_epoch": material.expected_target_epoch,
        "resource_name": observation.resource_name,
        "generation": observation.generation,
        "etag_hash": canonical_sha256({"etag": observation.etag}),
        "runtime_service_account": observation.runtime_service_account,
        "container_name": observation.container_name,
        "image": observation.image,
        "latest_ready_revision": observation.latest_ready_revision,
        "traffic": [list(item) for item in observation.traffic],
        "assignment_hash": observation.assignment_hash,
    }
