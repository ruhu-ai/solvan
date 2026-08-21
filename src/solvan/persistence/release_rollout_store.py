"""Target reservations and external-effect fences for approved Cloud Run rollouts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, cast
from uuid import uuid4

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.code_change_decisions import deployment_decision_material
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier


class ReleaseRolloutConflict(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ApprovedRolloutCandidate:
    request_id: str
    request_sequence_no: int
    decision_id: str
    decision_digest: str
    release_candidate_id: str
    release_target_profile_id: str
    target_observation_hash: str
    release_health_baseline_id: str
    release_health_baseline_hash: str
    target_key: str
    target_version: str
    target_epoch: int
    first_canary_percent: int
    material_hash: str
    command_deadline: datetime
    reservation_deadline: datetime


@dataclass(frozen=True, slots=True)
class CreatedRollout:
    rollout_id: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class CompletedRolloutOperation:
    response_ref: str
    response_hash: str


@dataclass(frozen=True, slots=True)
class CanaryCommandCandidate:
    rollout_id: str
    material_hash: str
    deadline: datetime


@dataclass(frozen=True, slots=True)
class RolloutAdvancementCandidate:
    rollout_id: str
    action: str
    current_stage_ordinal: int
    next_stage_ordinal: int | None
    next_percentage: int | None
    material_hash: str
    deadline: datetime
    receipt_envelope_ref: str
    receipt_envelope_hash: str
    signature_ref: str
    signature_hash: str
    verification_profile_hash: str
    release_health_baseline_hash: str
    predeploy_snapshot_hash: str
    intended_effect_hash: str
    verifier_identity: str
    verifier_key_version: str
    receipt_observed_at: datetime


@dataclass(frozen=True, slots=True)
class CanaryProviderMaterial:
    rollout_id: str
    operation_id: str
    operation_status: str
    provider_request_id: str | None
    operation_reconciled_at: datetime | None
    service_resource_name: str
    runtime_service_account: str
    deployment_manifest_profile_ref: str
    deployment_manifest_profile_hash: str
    candidate_envelope_ref: str
    candidate_envelope_hash: str
    code_change_request_id: str
    release_candidate_id: str
    release_target_profile_id: str
    repository_binding_id: str
    merged_commit_sha: str
    source_tree_hash: str
    release_policy_hash: str
    signer_identity: str
    signer_key_version: str
    expected_target_version: str
    expected_target_epoch: int
    predeploy_revision: str
    predeploy_assignment_hash: str
    first_canary_percent: int
    target_profile_hash: str
    release_health_baseline_ref: str
    release_health_baseline_hash: str
    baseline_signature_ref: str
    baseline_signature_hash: str
    verification_profile_hash: str
    verifier_identity: str
    verifier_key_version: str
    target_observation_hash: str


@dataclass(frozen=True, slots=True)
class RolloutAdvancementMaterial:
    candidate: RolloutAdvancementCandidate
    operation_id: str | None
    operation_status: str | None
    provider_request_id: str | None
    operation_reconciled_at: datetime | None
    service_resource_name: str
    runtime_service_account: str
    deployment_manifest_profile_ref: str
    deployment_manifest_profile_hash: str
    build_artifact_ref: str
    candidate_revision: str
    prior_revision: str
    expected_current_assignment: tuple[tuple[str, int], ...]
    expected_next_assignment: tuple[tuple[str, int], ...] | None
    release_target_profile_hash: str


@dataclass(frozen=True, slots=True)
class PromotedRequestCandidate:
    request_id: str
    request_sequence_no: int
    advancement: RolloutAdvancementCandidate


@dataclass(frozen=True, slots=True)
class FailedRequestCandidate:
    request_id: str
    request_sequence_no: int
    rollout_id: str
    receipt_envelope_hash: str


@dataclass(frozen=True, slots=True)
class ApprovedRollbackCandidate:
    request_id: str
    request_sequence_no: int
    rollout_id: str
    decision_id: str
    decision_digest: str
    stage_ordinal: int
    material_hash: str
    deadline: datetime


@dataclass(frozen=True, slots=True)
class RollbackProviderMaterial:
    candidate: ApprovedRollbackCandidate
    operation_id: str
    operation_status: str
    provider_request_id: str | None
    operation_reconciled_at: datetime | None
    service_resource_name: str
    runtime_service_account: str
    deployment_manifest_profile_ref: str
    deployment_manifest_profile_hash: str
    rollback_revision: str
    expected_target_version: str
    expected_assignment_hash: str


@dataclass(frozen=True, slots=True)
class RollbackFinalizationCandidate:
    request_id: str
    request_sequence_no: int
    rollout_id: str
    expected_revision: str
    receipt_envelope_ref: str
    receipt_envelope_hash: str
    signature_ref: str
    signature_hash: str
    verifier_identity: str
    verifier_key_version: str
    material_hash: str
    deadline: datetime
    receipt_observed_at: datetime


class PostgresReleaseRolloutStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def completed_operation(
        self,
        *,
        scope: Scope,
        rollout_id: str,
        operation_kind: str,
        material_hash: str,
    ) -> CompletedRolloutOperation | None:
        """Return the immutable effect receipt after a command-completion crash.

        The provider operation fence is authoritative for whether an external
        effect already completed.  A retry must finish the private command from
        that receipt instead of re-entering the provider mutation path.
        """

        row = self._connection.execute(
            """SELECT response_ref,response_hash
                 FROM solvan_delivery.deployment_rollout_operations
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND deployment_rollout_id=%(rollout_id)s
                  AND operation_kind=%(operation_kind)s
                  AND material_hash=%(material_hash)s
                  AND status='SUCCEEDED'""",
            {
                **scope.canonical_dict(),
                "rollout_id": rollout_id,
                "operation_kind": operation_kind,
                "material_hash": material_hash,
            },
        ).fetchone()
        if row is None:
            return None
        response_ref, response_hash = str(row[0]), str(row[1])
        if not response_ref.startswith("gs://") or not response_hash.startswith("sha256:"):
            raise ReleaseRolloutConflict("completed rollout operation receipt is malformed")
        return CompletedRolloutOperation(response_ref, response_hash)

    def candidates(
        self, *, scope: Scope, now: datetime, include_dispatched: bool = False
    ) -> tuple[ApprovedRolloutCandidate, ...]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT request.*,decision.id AS decision_id,decision.decision_digest,
                          decision.expires_at AS decision_expires_at,
                          decision.release_health_baseline_id,
                          decision.release_health_baseline_hash,
                          candidate.id AS release_candidate_id,candidate.merged_commit_sha,
                          candidate.source_tree_hash,candidate.build_artifact_ref,
                          candidate.build_artifact_hash,candidate.provenance_hash,
                          candidate.release_signature_hash,candidate.signer_identity,
                          candidate.signer_key_version,candidate.deployment_manifest_hash,
                          target.id AS release_target_profile_id,
                          target.profile_hash AS release_target_profile_hash,target.target_key,
                          target.service_resource_name,target.expected_target_epoch,
                          target.rollout_policy_hash,target.canary_percentages,
                          target.rollout_deadline_seconds,target.verification_profile_id,
                          target.verification_profile_version,target.verification_profile_hash,
                          observation.target_version,observation.target_epoch,
                          observation.service_generation,observation.service_etag_hash,
                          observation.current_release_candidate_id,observation.current_revision,
                          observation.assignment_ref,observation.assignment_hash,
                          observation.observation_ref,observation.observation_hash,
                          observation.observed_at,
                          baseline.baseline_ref AS release_health_baseline_ref
                     FROM solvan_delivery.code_change_requests request
                     JOIN solvan_delivery.code_change_decisions decision
                       ON decision.organization_id=request.organization_id
                      AND decision.project_id=request.project_id
                      AND decision.environment_id=request.environment_id
                      AND decision.code_change_request_id=request.id
                      AND decision.stage='DEPLOYMENT' AND decision.decision='APPROVED'
                      AND decision.expires_at>%(now)s
                     JOIN solvan_delivery.release_candidates candidate
                       ON candidate.organization_id=request.organization_id
                      AND candidate.project_id=request.project_id
                      AND candidate.environment_id=request.environment_id
                      AND candidate.id=decision.release_candidate_id
                     JOIN solvan_delivery.release_target_profiles target
                       ON target.organization_id=request.organization_id
                      AND target.project_id=request.project_id
                      AND target.environment_id=request.environment_id
                      AND target.id=decision.release_target_profile_id AND target.status='ACTIVE'
                     JOIN solvan_delivery.release_target_observations observation
                       ON observation.organization_id=request.organization_id
                      AND observation.project_id=request.project_id
                      AND observation.environment_id=request.environment_id
                      AND observation.code_change_request_id=request.id
                      AND observation.release_candidate_id=candidate.id
                      AND observation.release_target_profile_id=target.id
                      AND observation.observation_hash=decision.release_target_observation_hash
                     JOIN solvan_delivery.release_health_baselines baseline
                       ON baseline.organization_id=request.organization_id
                      AND baseline.project_id=request.project_id
                      AND baseline.environment_id=request.environment_id
                      AND baseline.id=decision.release_health_baseline_id
                      AND baseline.baseline_hash=decision.release_health_baseline_hash
                      AND baseline.code_change_request_id=request.id
                      AND baseline.release_candidate_id=candidate.id
                      AND baseline.release_target_profile_id=target.id
                      AND baseline.target_observation_hash=observation.observation_hash
                    WHERE request.organization_id=%(organization_id)s
                      AND request.project_id=%(project_id)s
                      AND request.environment_id=%(environment_id)s
                      AND request.state='DEPLOYMENT_APPROVAL_PENDING'
                      AND request.expires_at>%(now)s
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.code_change_decisions child
                         WHERE child.organization_id=decision.organization_id
                           AND child.project_id=decision.project_id
                           AND child.environment_id=decision.environment_id
                           AND child.supersedes_id=decision.id)
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.deployment_rollouts rollout
                         WHERE rollout.organization_id=request.organization_id
                           AND rollout.project_id=request.project_id
                           AND rollout.environment_id=request.environment_id
                           AND rollout.release_candidate_id=candidate.id
                           AND rollout.target_key=target.target_key)
                      AND (%(include_dispatched)s OR NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.private_command_dispatches command
                         WHERE command.organization_id=request.organization_id
                           AND command.project_id=request.project_id
                           AND command.environment_id=request.environment_id
                           AND command.command_kind='START_ROLLOUT'
                           AND command.subject_id=request.id))
                    ORDER BY decision.decided_at LIMIT 20""",
                {
                    **scope.canonical_dict(),
                    "now": now,
                    "include_dispatched": include_dispatched,
                },
            )
            return tuple(self._candidate(row, now=now) for row in cursor.fetchall())

    def candidate_for_start(
        self, *, scope: Scope, request_id: str, material_hash: str, now: datetime
    ) -> ApprovedRolloutCandidate:
        matches = tuple(
            candidate
            for candidate in self.candidates(scope=scope, now=now, include_dispatched=True)
            if candidate.request_id == request_id and candidate.material_hash == material_hash
        )
        if len(matches) != 1:
            raise ReleaseRolloutConflict("approved rollout start authority is stale")
        return matches[0]

    def started_rollout(
        self, *, scope: Scope, request_id: str, material_hash: str
    ) -> CreatedRollout | None:
        row = self._connection.execute(
            """SELECT rollout.id,rollout.created_at
                 FROM solvan_delivery.deployment_rollouts rollout
                 JOIN solvan_delivery.release_candidates candidate
                   ON candidate.organization_id=rollout.organization_id
                  AND candidate.project_id=rollout.project_id
                  AND candidate.environment_id=rollout.environment_id
                  AND candidate.id=rollout.release_candidate_id
                 JOIN solvan_delivery.code_change_transitions transition
                   ON transition.organization_id=rollout.organization_id
                  AND transition.project_id=rollout.project_id
                  AND transition.environment_id=rollout.environment_id
                  AND transition.code_change_request_id=candidate.code_change_request_id
                  AND transition.to_state='CANARY_DEPLOYING'
                  AND transition.input_hash=%(material_hash)s
                WHERE rollout.organization_id=%(organization_id)s
                  AND rollout.project_id=%(project_id)s
                  AND rollout.environment_id=%(environment_id)s
                  AND candidate.code_change_request_id=%(request_id)s""",
            {
                **scope.canonical_dict(),
                "request_id": request_id,
                "material_hash": material_hash,
            },
        ).fetchall()
        if len(row) > 1:
            raise ReleaseRolloutConflict("rollout start reconciled to multiple records")
        return CreatedRollout(str(row[0][0]), row[0][1]) if row else None

    @staticmethod
    def _candidate(row: Mapping[str, Any], *, now: datetime) -> ApprovedRolloutCandidate:
        decision = deployment_decision_material(
            request=row,
            release=row,
            expires_at=row["decision_expires_at"],
        )
        if decision.digest != row["decision_digest"]:
            raise ReleaseRolloutConflict("deployment decision digest is no longer exact")
        percentages = row["canary_percentages"]
        if not isinstance(percentages, list) or not percentages or type(percentages[0]) is not int:
            raise ReleaseRolloutConflict("rollout percentage policy is malformed")
        command_deadline = row["decision_expires_at"]
        reservation_deadline = now + timedelta(seconds=int(row["rollout_deadline_seconds"]))
        material_hash = canonical_sha256(
            {
                "schema_version": 1,
                "command_kind": "START_ROLLOUT",
                "code_change_request_id": str(row["id"]),
                "decision_id": str(row["decision_id"]),
                "decision_digest": str(row["decision_digest"]),
                "release_candidate_id": str(row["release_candidate_id"]),
                "release_target_profile_id": str(row["release_target_profile_id"]),
                "target_observation_hash": str(row["observation_hash"]),
                "release_health_baseline_id": str(row["release_health_baseline_id"]),
                "release_health_baseline_hash": str(row["release_health_baseline_hash"]),
                "first_canary_percent": percentages[0],
                "request_sequence_no": int(row["sequence_no"]),
            }
        )
        return ApprovedRolloutCandidate(
            request_id=str(row["id"]),
            request_sequence_no=int(row["sequence_no"]),
            decision_id=str(row["decision_id"]),
            decision_digest=str(row["decision_digest"]),
            release_candidate_id=str(row["release_candidate_id"]),
            release_target_profile_id=str(row["release_target_profile_id"]),
            target_observation_hash=str(row["observation_hash"]),
            release_health_baseline_id=str(row["release_health_baseline_id"]),
            release_health_baseline_hash=str(row["release_health_baseline_hash"]),
            target_key=str(row["target_key"]),
            target_version=str(row["target_version"]),
            target_epoch=int(row["target_epoch"]),
            first_canary_percent=int(percentages[0]),
            material_hash=material_hash,
            command_deadline=command_deadline,
            reservation_deadline=reservation_deadline,
        )

    def start(
        self,
        *,
        scope: Scope,
        candidate: ApprovedRolloutCandidate,
        controller_identity: str,
    ) -> CreatedRollout:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT target.*,release.build_artifact_hash,
                          observation.current_release_candidate_id,
                          observation.assignment_ref,observation.assignment_hash,
                          observation.observation_ref,observation.observation_hash,
                          baseline.id AS baseline_id,baseline.baseline_ref,baseline.baseline_hash
                     FROM solvan_delivery.release_target_profiles target
                     JOIN solvan_delivery.release_candidates release
                       ON release.organization_id=target.organization_id
                      AND release.project_id=target.project_id
                      AND release.environment_id=target.environment_id
                      AND release.id=%(candidate_id)s
                     JOIN solvan_delivery.release_target_observations observation
                       ON observation.organization_id=target.organization_id
                      AND observation.project_id=target.project_id
                      AND observation.environment_id=target.environment_id
                      AND observation.release_candidate_id=release.id
                      AND observation.release_target_profile_id=target.id
                      AND observation.observation_hash=%(observation_hash)s
                     JOIN solvan_delivery.release_health_baselines baseline
                       ON baseline.organization_id=target.organization_id
                      AND baseline.project_id=target.project_id
                      AND baseline.environment_id=target.environment_id
                      AND baseline.id=%(baseline_id)s
                      AND baseline.baseline_hash=%(baseline_hash)s
                      AND baseline.release_candidate_id=release.id
                      AND baseline.release_target_profile_id=target.id
                      AND baseline.target_observation_hash=observation.observation_hash
                    WHERE target.organization_id=%(organization_id)s
                      AND target.project_id=%(project_id)s
                      AND target.environment_id=%(environment_id)s
                      AND target.id=%(target_id)s AND target.status='ACTIVE'
                    FOR UPDATE OF target""",
                {
                    **scope.canonical_dict(),
                    "candidate_id": candidate.release_candidate_id,
                    "observation_hash": candidate.target_observation_hash,
                    "target_id": candidate.release_target_profile_id,
                    "baseline_id": candidate.release_health_baseline_id,
                    "baseline_hash": candidate.release_health_baseline_hash,
                },
            )
            row = cursor.fetchone()
            if row is None:
                raise ReleaseRolloutConflict("approved rollout material is stale")
            reservation_id = new_identifier("dtr")
            lease = uuid4()
            reservation_hash = canonical_sha256(
                {
                    "target_key": candidate.target_key,
                    "target_version": candidate.target_version,
                    "target_epoch": candidate.target_epoch,
                    "release_candidate_id": candidate.release_candidate_id,
                    "decision_digest": candidate.decision_digest,
                }
            )
            cursor.execute(
                """INSERT INTO solvan_delivery.release_target_reservations
                     (organization_id,project_id,environment_id,id,target_key,
                      expected_target_version,expected_target_epoch,reservation_material_hash,
                      status,lease_token,lease_expires_at,held_by_identity)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                     %(target_key)s,%(target_version)s,%(target_epoch)s,%(material_hash)s,
                     'HELD',%(lease)s,%(deadline)s,%(identity)s)""",
                {
                    **scope.canonical_dict(),
                    "id": reservation_id,
                    "target_key": candidate.target_key,
                    "target_version": candidate.target_version,
                    "target_epoch": candidate.target_epoch,
                    "material_hash": reservation_hash,
                    "lease": lease,
                    "deadline": candidate.reservation_deadline,
                    "identity": controller_identity,
                },
            )
            effect_inputs_hash = canonical_sha256(
                {
                    "release_candidate_id": candidate.release_candidate_id,
                    "build_artifact_hash": str(row["build_artifact_hash"]),
                    "target_key": candidate.target_key,
                    "verification_profile_hash": str(row["verification_profile_hash"]),
                    "release_health_baseline_hash": candidate.release_health_baseline_hash,
                }
            )
            intended_effect_hash = canonical_sha256(
                {
                    "schema_version": 1,
                    "template_id": "cloud-run-release-health",
                    "template_version": "1",
                    "input_refs_hash": effect_inputs_hash,
                    "predicate": (
                        "candidate revision serves traffic without degrading "
                        "registered health signals"
                    ),
                }
            )
            rollout_id = new_identifier("dro")
            cursor.execute(
                """INSERT INTO solvan_delivery.deployment_rollouts
                     (organization_id,project_id,environment_id,id,release_candidate_id,
                      target_key,target_provider,expected_target_version,expected_target_epoch,
                      target_reservation_id,rollout_policy_hash,approval_digest,
                      predeploy_snapshot_ref,predeploy_snapshot_hash,
                      predeploy_release_candidate_id,predeploy_assignment_ref,
                      rollback_release_candidate_id,rollback_assignment_ref,
                      release_effect_template_id,release_effect_template_version,
                      release_effect_input_refs_hash,intended_effect_hash,
                      verification_profile_id,verification_profile_version,
                      verification_profile_hash,status,release_target_profile_id,
                      release_target_profile_hash,predeploy_assignment_hash,
                      rollback_assignment_hash,release_health_baseline_id,
                      release_health_baseline_ref,
                      release_health_baseline_hash)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                     %(candidate_id)s,%(target_key)s,'GCP_CLOUD_RUN_V2',%(target_version)s,
                     %(target_epoch)s,%(reservation_id)s,%(rollout_policy_hash)s,
                     %(decision_digest)s,%(snapshot_ref)s,%(snapshot_hash)s,
                     %(prior_candidate_id)s,%(assignment_ref)s,%(prior_candidate_id)s,
                     %(assignment_ref)s,'cloud-run-release-health','1',%(effect_inputs_hash)s,
                     %(intended_effect_hash)s,%(verification_id)s,%(verification_version)s,
                     %(verification_hash)s,'CANARY_DEPLOYING',%(target_id)s,
                     %(target_hash)s,%(assignment_hash)s,%(assignment_hash)s,
                      %(baseline_id)s,%(baseline_ref)s,%(baseline_hash)s)
                   RETURNING created_at""",
                {
                    **scope.canonical_dict(),
                    "id": rollout_id,
                    "candidate_id": candidate.release_candidate_id,
                    "target_key": candidate.target_key,
                    "target_version": candidate.target_version,
                    "target_epoch": candidate.target_epoch,
                    "reservation_id": reservation_id,
                    "rollout_policy_hash": row["rollout_policy_hash"],
                    "decision_digest": candidate.decision_digest,
                    "snapshot_ref": row["observation_ref"],
                    "snapshot_hash": row["observation_hash"],
                    "prior_candidate_id": row["current_release_candidate_id"],
                    "assignment_ref": row["assignment_ref"],
                    "effect_inputs_hash": effect_inputs_hash,
                    "intended_effect_hash": intended_effect_hash,
                    "verification_id": row["verification_profile_id"],
                    "verification_version": row["verification_profile_version"],
                    "verification_hash": row["verification_profile_hash"],
                    "target_id": candidate.release_target_profile_id,
                    "target_hash": row["profile_hash"],
                    "assignment_hash": row["assignment_hash"],
                    "baseline_id": row["baseline_id"],
                    "baseline_ref": row["baseline_ref"],
                    "baseline_hash": row["baseline_hash"],
                },
            )
            created_at_row = cursor.fetchone()
            if created_at_row is None:
                raise ReleaseRolloutConflict("rollout creation returned no timestamp")
            cursor.execute(
                """INSERT INTO solvan_delivery.code_change_transitions
                     (organization_id,project_id,environment_id,id,code_change_request_id,
                      sequence_no,from_state,to_state,expected_sequence_no,input_hash,
                      idempotency_key,actor_kind,actor_identity,decision_id,decision_digest)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                     %(request_id)s,%(sequence)s,'DEPLOYMENT_APPROVAL_PENDING','CANARY_DEPLOYING',
                     %(expected_sequence)s,%(input_hash)s,%(idempotency_key)s,
                     'DEPLOYMENT_CONTROLLER',%(identity)s,%(decision_id)s,%(decision_digest)s)""",
                {
                    **scope.canonical_dict(),
                    "id": new_identifier("cct"),
                    "request_id": candidate.request_id,
                    "sequence": candidate.request_sequence_no + 1,
                    "expected_sequence": candidate.request_sequence_no,
                    "input_hash": candidate.material_hash,
                    "idempotency_key": f"deployment-start:{rollout_id}",
                    "identity": controller_identity,
                    "decision_id": candidate.decision_id,
                    "decision_digest": candidate.decision_digest,
                },
            )
        return CreatedRollout(rollout_id=rollout_id, created_at=created_at_row["created_at"])

    def canary_candidates(
        self, *, scope: Scope, now: datetime, limit: int = 20
    ) -> tuple[CanaryCommandCandidate, ...]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT rollout.id,rollout.release_candidate_id,
                          rollout.release_target_profile_hash,rollout.approval_digest,
                          rollout.predeploy_snapshot_hash,target.canary_percentages,
                          reservation.lease_expires_at
                     FROM solvan_delivery.deployment_rollouts rollout
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
                      AND reservation.target_key=rollout.target_key
                      AND reservation.status IN ('HELD','RECONCILING')
                      AND reservation.lease_expires_at>%(now)s
                    WHERE rollout.organization_id=%(organization_id)s
                      AND rollout.project_id=%(project_id)s
                      AND rollout.environment_id=%(environment_id)s
                      AND rollout.status='CANARY_DEPLOYING'
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.deployment_rollout_operations operation
                         WHERE operation.organization_id=rollout.organization_id
                           AND operation.project_id=rollout.project_id
                           AND operation.environment_id=rollout.environment_id
                           AND operation.deployment_rollout_id=rollout.id
                           AND operation.operation_kind='PREPARE_CANARY')
                      AND NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.private_command_dispatches command
                         WHERE command.organization_id=rollout.organization_id
                           AND command.project_id=rollout.project_id
                           AND command.environment_id=rollout.environment_id
                           AND command.command_kind='PREPARE_CANARY'
                           AND command.subject_id=rollout.id)
                    ORDER BY rollout.created_at,rollout.id LIMIT %(limit)s""",
                {**scope.canonical_dict(), "now": now, "limit": limit},
            )
            result: list[CanaryCommandCandidate] = []
            for row in cursor.fetchall():
                percentages = row["canary_percentages"]
                if (
                    not isinstance(percentages, list)
                    or not percentages
                    or type(percentages[0]) is not int
                ):
                    raise ReleaseRolloutConflict("rollout percentage policy is malformed")
                material_hash = canonical_sha256(
                    {
                        "schema_version": 1,
                        "command_kind": "PREPARE_CANARY",
                        "rollout_id": str(row["id"]),
                        "release_candidate_id": str(row["release_candidate_id"]),
                        "target_profile_hash": str(row["release_target_profile_hash"]),
                        "approval_digest": str(row["approval_digest"]),
                        "predeploy_snapshot_hash": str(row["predeploy_snapshot_hash"]),
                        "stage_ordinal": 1,
                        "canary_percent": int(percentages[0]),
                    }
                )
                result.append(
                    CanaryCommandCandidate(
                        rollout_id=str(row["id"]),
                        material_hash=material_hash,
                        deadline=row["lease_expires_at"],
                    )
                )
            return tuple(result)

    def prepare_canary_operation(
        self,
        *,
        scope: Scope,
        rollout_id: str,
        material_hash: str,
        request_ref: str,
        request_hash: str,
    ) -> str:
        operation_id = new_identifier("dgo")
        row = self._connection.execute(
            """INSERT INTO solvan_delivery.deployment_rollout_operations
                 (organization_id,project_id,environment_id,id,deployment_rollout_id,
                  operation_kind,stage_ordinal,material_hash,idempotency_key,status,
                  request_ref,request_hash)
               SELECT %(organization_id)s,%(project_id)s,%(environment_id)s,%(operation_id)s,
                      rollout.id,'PREPARE_CANARY',1,%(material_hash)s,
                      'prepare-canary:'||rollout.id||':1','PREPARED',%(request_ref)s,%(request_hash)s
                 FROM solvan_delivery.deployment_rollouts rollout
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
                  AND reservation.lease_expires_at>now()
                WHERE rollout.organization_id=%(organization_id)s
                  AND rollout.project_id=%(project_id)s
                  AND rollout.environment_id=%(environment_id)s
                  AND rollout.id=%(rollout_id)s AND rollout.status='CANARY_DEPLOYING'
               ON CONFLICT (organization_id,project_id,environment_id,
                            deployment_rollout_id,operation_kind,stage_ordinal,material_hash)
               DO NOTHING RETURNING id""",
            {
                **scope.canonical_dict(),
                "operation_id": operation_id,
                "rollout_id": rollout_id,
                "material_hash": material_hash,
                "request_ref": request_ref,
                "request_hash": request_hash,
            },
        ).fetchone()
        if row is not None:
            return str(row[0])
        existing = self._connection.execute(
            """SELECT id,request_ref,request_hash
                 FROM solvan_delivery.deployment_rollout_operations
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND deployment_rollout_id=%(rollout_id)s
                  AND operation_kind='PREPARE_CANARY' AND stage_ordinal=1
                  AND material_hash=%(material_hash)s""",
            {
                **scope.canonical_dict(),
                "rollout_id": rollout_id,
                "material_hash": material_hash,
            },
        ).fetchone()
        if existing is None or tuple(existing[1:]) != (request_ref, request_hash):
            raise ReleaseRolloutConflict("canary operation command binding conflicts")
        return str(existing[0])

    def advancement_candidates(
        self,
        *,
        scope: Scope,
        now: datetime,
        limit: int = 20,
        include_dispatched: bool = False,
    ) -> tuple[RolloutAdvancementCandidate, ...]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT rollout.id,rollout.verification_profile_hash,
                          rollout.release_health_baseline_hash,
                          rollout.predeploy_snapshot_hash,rollout.intended_effect_hash,
                          target.canary_percentages,reservation.lease_expires_at,
                          receipt.stage_ordinal,receipt.observation_window_generation,
                          receipt.receipt_envelope_ref,receipt.receipt_envelope_hash,
                          receipt.signature_ref,receipt.signature_hash,
                          receipt.verifier_identity,receipt.verifier_key_version,
                          receipt.observed_at AS receipt_observed_at
                     FROM solvan_delivery.deployment_rollouts rollout
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
                     JOIN LATERAL (
                       SELECT item.*
                         FROM solvan_delivery.release_verification_receipts item
                        WHERE item.organization_id=rollout.organization_id
                          AND item.project_id=rollout.project_id
                          AND item.environment_id=rollout.environment_id
                          AND item.deployment_rollout_id=rollout.id
                        ORDER BY item.stage_ordinal DESC,
                                 item.observation_window_generation DESC LIMIT 1
                     ) receipt ON receipt.result='VERIFIED'
                     JOIN solvan_delivery.release_verifier_keys verifier_key
                       ON verifier_key.organization_id=receipt.organization_id
                      AND verifier_key.project_id=receipt.project_id
                      AND verifier_key.environment_id=receipt.environment_id
                      AND verifier_key.verifier_identity=receipt.verifier_identity
                      AND verifier_key.key_version=receipt.verifier_key_version
                      AND verifier_key.status='ACTIVE'
                    WHERE rollout.organization_id=%(organization_id)s
                      AND rollout.project_id=%(project_id)s
                      AND rollout.environment_id=%(environment_id)s
                      AND rollout.status='CANARY_READY'
                      AND (%(include_dispatched)s OR NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.private_command_dispatches command
                         WHERE command.organization_id=rollout.organization_id
                           AND command.project_id=rollout.project_id
                           AND command.environment_id=rollout.environment_id
                           AND command.subject_id=rollout.id
                           AND command.command_kind IN ('PROMOTE_CANARY','FINALIZE_ROLLOUT')
                           AND command.status IN ('PREPARED','ISSUED','RECONCILING')))
                    ORDER BY receipt.observed_at,rollout.id LIMIT %(limit)s""",
                {
                    **scope.canonical_dict(),
                    "now": now,
                    "limit": limit,
                    "include_dispatched": include_dispatched,
                },
            )
            result: list[RolloutAdvancementCandidate] = []
            for row in cursor.fetchall():
                percentages = row["canary_percentages"]
                stage = int(row["stage_ordinal"])
                if (
                    not isinstance(percentages, list)
                    or stage < 1
                    or stage > len(percentages)
                    or int(percentages[-1]) != 100
                ):
                    raise ReleaseRolloutConflict("rollout advancement policy is malformed")
                final = stage == len(percentages)
                action = "FINALIZE_ROLLOUT" if final else "PROMOTE_CANARY"
                next_stage = None if final else stage + 1
                next_percentage = None if final else int(percentages[stage])
                material_hash = canonical_sha256(
                    {
                        "schema_version": 1,
                        "command_kind": action,
                        "deployment_rollout_id": str(row["id"]),
                        "verified_stage_ordinal": stage,
                        "verification_receipt_hash": str(row["receipt_envelope_hash"]),
                        "next_stage_ordinal": next_stage,
                        "next_percentage": next_percentage,
                    }
                )
                result.append(
                    RolloutAdvancementCandidate(
                        rollout_id=str(row["id"]),
                        action=action,
                        current_stage_ordinal=stage,
                        next_stage_ordinal=next_stage,
                        next_percentage=next_percentage,
                        material_hash=material_hash,
                        deadline=row["lease_expires_at"],
                        receipt_envelope_ref=str(row["receipt_envelope_ref"]),
                        receipt_envelope_hash=str(row["receipt_envelope_hash"]),
                        signature_ref=str(row["signature_ref"]),
                        signature_hash=str(row["signature_hash"]),
                        verification_profile_hash=str(row["verification_profile_hash"]),
                        release_health_baseline_hash=str(row["release_health_baseline_hash"]),
                        predeploy_snapshot_hash=str(row["predeploy_snapshot_hash"]),
                        intended_effect_hash=str(row["intended_effect_hash"]),
                        verifier_identity=str(row["verifier_identity"]),
                        verifier_key_version=str(row["verifier_key_version"]),
                        receipt_observed_at=row["receipt_observed_at"],
                    )
                )
            return tuple(result)

    def failure_candidates(
        self,
        *,
        scope: Scope,
        now: datetime,
        limit: int = 20,
        include_dispatched: bool = False,
    ) -> tuple[RolloutAdvancementCandidate, ...]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT rollout.id,rollout.verification_profile_hash,
                          rollout.release_health_baseline_hash,
                          rollout.predeploy_snapshot_hash,rollout.intended_effect_hash,
                          reservation.lease_expires_at,receipt.stage_ordinal,
                          receipt.receipt_envelope_ref,receipt.receipt_envelope_hash,
                          receipt.signature_ref,receipt.signature_hash,
                          receipt.verifier_identity,receipt.verifier_key_version,
                          receipt.observed_at AS receipt_observed_at
                     FROM solvan_delivery.deployment_rollouts rollout
                     JOIN solvan_delivery.release_target_reservations reservation
                       ON reservation.organization_id=rollout.organization_id
                      AND reservation.project_id=rollout.project_id
                      AND reservation.environment_id=rollout.environment_id
                      AND reservation.id=rollout.target_reservation_id
                      AND reservation.status IN ('HELD','RECONCILING')
                      AND reservation.lease_expires_at>%(now)s
                     JOIN LATERAL (
                       SELECT item.* FROM solvan_delivery.release_verification_receipts item
                        WHERE item.organization_id=rollout.organization_id
                          AND item.project_id=rollout.project_id
                          AND item.environment_id=rollout.environment_id
                          AND item.deployment_rollout_id=rollout.id
                        ORDER BY item.stage_ordinal DESC,
                                 item.observation_window_generation DESC LIMIT 1
                     ) receipt ON receipt.result IN ('FAILED','INCONCLUSIVE')
                    WHERE rollout.organization_id=%(organization_id)s
                      AND rollout.project_id=%(project_id)s
                      AND rollout.environment_id=%(environment_id)s
                      AND rollout.status='CANARY_READY'
                      AND (%(include_dispatched)s OR NOT EXISTS (
                        SELECT 1 FROM solvan_delivery.private_command_dispatches command
                         WHERE command.organization_id=rollout.organization_id
                           AND command.project_id=rollout.project_id
                           AND command.environment_id=rollout.environment_id
                           AND command.subject_id=rollout.id
                           AND command.command_kind='REGISTER_VERIFICATION_FAILURE'
                           AND command.status IN ('PREPARED','ISSUED','RECONCILING')))
                    ORDER BY receipt.observed_at,rollout.id LIMIT %(limit)s""",
                {
                    **scope.canonical_dict(),
                    "now": now,
                    "limit": limit,
                    "include_dispatched": include_dispatched,
                },
            )
            result: list[RolloutAdvancementCandidate] = []
            for row in cursor.fetchall():
                stage = int(row["stage_ordinal"])
                receipt_hash = str(row["receipt_envelope_hash"])
                result.append(
                    RolloutAdvancementCandidate(
                        rollout_id=str(row["id"]),
                        action="REGISTER_VERIFICATION_FAILURE",
                        current_stage_ordinal=stage,
                        next_stage_ordinal=None,
                        next_percentage=None,
                        material_hash=canonical_sha256(
                            {
                                "schema_version": 1,
                                "command_kind": "REGISTER_VERIFICATION_FAILURE",
                                "deployment_rollout_id": str(row["id"]),
                                "failed_stage_ordinal": stage,
                                "verification_receipt_hash": receipt_hash,
                            }
                        ),
                        deadline=row["lease_expires_at"],
                        receipt_envelope_ref=str(row["receipt_envelope_ref"]),
                        receipt_envelope_hash=receipt_hash,
                        signature_ref=str(row["signature_ref"]),
                        signature_hash=str(row["signature_hash"]),
                        verification_profile_hash=str(row["verification_profile_hash"]),
                        release_health_baseline_hash=str(row["release_health_baseline_hash"]),
                        predeploy_snapshot_hash=str(row["predeploy_snapshot_hash"]),
                        intended_effect_hash=str(row["intended_effect_hash"]),
                        verifier_identity=str(row["verifier_identity"]),
                        verifier_key_version=str(row["verifier_key_version"]),
                        receipt_observed_at=row["receipt_observed_at"],
                    )
                )
            return tuple(result)

    def register_verification_failure(
        self,
        *,
        scope: Scope,
        candidate: RolloutAdvancementCandidate,
    ) -> None:
        if candidate.action != "REGISTER_VERIFICATION_FAILURE":
            raise ReleaseRolloutConflict("verification failure candidate is malformed")
        row = self._connection.execute(
            """UPDATE solvan_delivery.deployment_rollouts
                  SET status='VERIFICATION_FAILED'
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(rollout_id)s
                  AND status='CANARY_READY' RETURNING id""",
            {**scope.canonical_dict(), "rollout_id": candidate.rollout_id},
        ).fetchone()
        if row is None:
            state = self._connection.execute(
                """SELECT status FROM solvan_delivery.deployment_rollouts
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(rollout_id)s""",
                {**scope.canonical_dict(), "rollout_id": candidate.rollout_id},
            ).fetchone()
            if state is None or str(state[0]) != "VERIFICATION_FAILED":
                raise ReleaseRolloutConflict("verification failure state conflicts")

    def candidate_for_advancement(
        self, *, scope: Scope, rollout_id: str, material_hash: str, now: datetime
    ) -> RolloutAdvancementCandidate:
        matches = tuple(
            candidate
            for candidate in self.advancement_candidates(
                scope=scope, now=now, include_dispatched=True
            )
            if candidate.rollout_id == rollout_id and candidate.material_hash == material_hash
        )
        if len(matches) != 1:
            raise ReleaseRolloutConflict("rollout advancement authority is stale")
        return matches[0]

    def prepare_promotion_operation(
        self,
        *,
        scope: Scope,
        candidate: RolloutAdvancementCandidate,
        request_ref: str,
        request_hash: str,
    ) -> str:
        if (
            candidate.action != "PROMOTE_CANARY"
            or candidate.next_stage_ordinal is None
            or candidate.next_percentage is None
        ):
            raise ReleaseRolloutConflict("promotion candidate is malformed")
        operation_id = new_identifier("dgo")
        row = self._connection.execute(
            """INSERT INTO solvan_delivery.deployment_rollout_operations
                 (organization_id,project_id,environment_id,id,deployment_rollout_id,
                  operation_kind,stage_ordinal,material_hash,idempotency_key,status,
                  request_ref,request_hash)
               SELECT %(organization_id)s,%(project_id)s,%(environment_id)s,%(operation_id)s,
                      rollout.id,'PROMOTE_CANARY',%(stage)s,%(material_hash)s,
                      'promote-canary:'||rollout.id||':'||%(stage)s,'PREPARED',
                      %(request_ref)s,%(request_hash)s
                 FROM solvan_delivery.deployment_rollouts rollout
                WHERE rollout.organization_id=%(organization_id)s
                  AND rollout.project_id=%(project_id)s
                  AND rollout.environment_id=%(environment_id)s
                  AND rollout.id=%(rollout_id)s AND rollout.status='CANARY_READY'
               ON CONFLICT (organization_id,project_id,environment_id,
                            deployment_rollout_id,operation_kind,stage_ordinal,material_hash)
               DO NOTHING RETURNING id""",
            {
                **scope.canonical_dict(),
                "operation_id": operation_id,
                "rollout_id": candidate.rollout_id,
                "stage": candidate.next_stage_ordinal,
                "material_hash": candidate.material_hash,
                "request_ref": request_ref,
                "request_hash": request_hash,
            },
        ).fetchone()
        if row is None:
            existing = self._connection.execute(
                """SELECT id,request_ref,request_hash
                     FROM solvan_delivery.deployment_rollout_operations
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND deployment_rollout_id=%(rollout_id)s
                      AND operation_kind='PROMOTE_CANARY' AND stage_ordinal=%(stage)s
                      AND material_hash=%(material_hash)s""",
                {
                    **scope.canonical_dict(),
                    "rollout_id": candidate.rollout_id,
                    "stage": candidate.next_stage_ordinal,
                    "material_hash": candidate.material_hash,
                },
            ).fetchone()
            if existing is None or tuple(existing[1:]) != (request_ref, request_hash):
                raise ReleaseRolloutConflict("promotion operation command binding conflicts")
            operation_id = str(existing[0])
        else:
            operation_id = str(row[0])
        updated = self._connection.execute(
            """UPDATE solvan_delivery.deployment_rollouts SET status='PROMOTING'
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(rollout_id)s
                  AND status='CANARY_READY' RETURNING id""",
            {**scope.canonical_dict(), "rollout_id": candidate.rollout_id},
        ).fetchone()
        if updated is None:
            state = self._connection.execute(
                """SELECT status FROM solvan_delivery.deployment_rollouts
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(rollout_id)s""",
                {**scope.canonical_dict(), "rollout_id": candidate.rollout_id},
            ).fetchone()
            if state is None or str(state[0]) != "PROMOTING":
                raise ReleaseRolloutConflict("rollout promotion state conflicts")
        return operation_id

    def load_promotion(
        self, *, scope: Scope, rollout_id: str, material_hash: str
    ) -> RolloutAdvancementMaterial:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT rollout.id,rollout.verification_profile_hash,
                          rollout.release_health_baseline_hash,
                          rollout.predeploy_snapshot_hash,rollout.intended_effect_hash,
                          rollout.release_target_profile_hash,target.canary_percentages,
                          target.service_resource_name,target.runtime_service_account,
                          target.deployment_manifest_profile_ref,
                          target.deployment_manifest_profile_hash,target.service_name,
                          candidate.id AS candidate_id,candidate.build_artifact_ref,
                          observation.current_revision AS prior_revision,
                          receipt.stage_ordinal AS verified_stage,
                          receipt.observation_window_generation,
                          receipt.receipt_envelope_ref,receipt.receipt_envelope_hash,
                          receipt.signature_ref,receipt.signature_hash,
                          receipt.verifier_identity,receipt.verifier_key_version,
                          receipt.observed_at AS receipt_observed_at,
                          operation.id AS operation_id,operation.stage_ordinal,
                          operation.status AS operation_status,operation.provider_request_id,
                          operation.reconciled_at AS operation_reconciled_at,
                          reservation.lease_expires_at
                     FROM solvan_delivery.deployment_rollouts rollout
                     JOIN solvan_delivery.release_target_profiles target
                       ON target.organization_id=rollout.organization_id
                      AND target.project_id=rollout.project_id
                      AND target.environment_id=rollout.environment_id
                      AND target.id=rollout.release_target_profile_id
                      AND target.profile_hash=rollout.release_target_profile_hash
                      AND target.status='ACTIVE'
                     JOIN solvan_delivery.release_candidates candidate
                       ON candidate.organization_id=rollout.organization_id
                      AND candidate.project_id=rollout.project_id
                      AND candidate.environment_id=rollout.environment_id
                      AND candidate.id=rollout.release_candidate_id
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
                      AND operation.operation_kind='PROMOTE_CANARY'
                      AND operation.material_hash=%(material_hash)s
                     JOIN solvan_delivery.release_verification_receipts receipt
                       ON receipt.organization_id=rollout.organization_id
                      AND receipt.project_id=rollout.project_id
                      AND receipt.environment_id=rollout.environment_id
                      AND receipt.deployment_rollout_id=rollout.id
                      AND receipt.stage_ordinal=operation.stage_ordinal-1
                      AND receipt.result='VERIFIED'
                     JOIN solvan_delivery.release_verifier_keys verifier_key
                       ON verifier_key.organization_id=receipt.organization_id
                      AND verifier_key.project_id=receipt.project_id
                      AND verifier_key.environment_id=receipt.environment_id
                      AND verifier_key.verifier_identity=receipt.verifier_identity
                      AND verifier_key.key_version=receipt.verifier_key_version
                      AND verifier_key.status='ACTIVE'
                     JOIN solvan_delivery.release_target_reservations reservation
                       ON reservation.organization_id=rollout.organization_id
                      AND reservation.project_id=rollout.project_id
                      AND reservation.environment_id=rollout.environment_id
                      AND reservation.id=rollout.target_reservation_id
                      AND reservation.status IN ('HELD','RECONCILING')
                      AND reservation.lease_expires_at>now()
                    WHERE rollout.organization_id=%(organization_id)s
                      AND rollout.project_id=%(project_id)s
                      AND rollout.environment_id=%(environment_id)s
                      AND rollout.id=%(rollout_id)s AND rollout.status='PROMOTING'
                    FOR UPDATE OF rollout,operation,target,verifier_key""",
                {
                    **scope.canonical_dict(),
                    "rollout_id": rollout_id,
                    "material_hash": material_hash,
                },
            )
            row = cursor.fetchone()
        percentages = row["canary_percentages"] if row is not None else None
        if row is None or not isinstance(percentages, list):
            raise ReleaseRolloutConflict("promotion rollout authority is stale")
        verified_stage = int(row["verified_stage"])
        next_stage = int(row["stage_ordinal"])
        if next_stage != verified_stage + 1 or next_stage > len(percentages):
            raise ReleaseRolloutConflict("promotion stage is not sequential")
        candidate = RolloutAdvancementCandidate(
            rollout_id=rollout_id,
            action="PROMOTE_CANARY",
            current_stage_ordinal=verified_stage,
            next_stage_ordinal=next_stage,
            next_percentage=int(percentages[next_stage - 1]),
            material_hash=material_hash,
            deadline=row["lease_expires_at"],
            receipt_envelope_ref=str(row["receipt_envelope_ref"]),
            receipt_envelope_hash=str(row["receipt_envelope_hash"]),
            signature_ref=str(row["signature_ref"]),
            signature_hash=str(row["signature_hash"]),
            verification_profile_hash=str(row["verification_profile_hash"]),
            release_health_baseline_hash=str(row["release_health_baseline_hash"]),
            predeploy_snapshot_hash=str(row["predeploy_snapshot_hash"]),
            intended_effect_hash=str(row["intended_effect_hash"]),
            verifier_identity=str(row["verifier_identity"]),
            verifier_key_version=str(row["verifier_key_version"]),
            receipt_observed_at=row["receipt_observed_at"],
        )
        expected_hash = canonical_sha256(
            {
                "schema_version": 1,
                "command_kind": "PROMOTE_CANARY",
                "deployment_rollout_id": rollout_id,
                "verified_stage_ordinal": verified_stage,
                "verification_receipt_hash": candidate.receipt_envelope_hash,
                "next_stage_ordinal": next_stage,
                "next_percentage": candidate.next_percentage,
            }
        )
        if expected_hash != material_hash:
            raise ReleaseRolloutConflict("promotion command material is not exact")
        service_name = str(row["service_name"])
        candidate_revision = f"{service_name[:34]}-sv-{str(row['candidate_id'])[-20:].lower()}"
        current_percent = int(percentages[verified_stage - 1])
        next_percent = int(percentages[next_stage - 1])
        prior_revision = str(row["prior_revision"])

        def assignment(percent: int) -> tuple[tuple[str, int], ...]:
            return (
                ((candidate_revision, 100),)
                if percent == 100
                else tuple(sorted(((candidate_revision, percent), (prior_revision, 100 - percent))))
            )

        return RolloutAdvancementMaterial(
            candidate=candidate,
            operation_id=str(row["operation_id"]),
            operation_status=str(row["operation_status"]),
            provider_request_id=(
                str(row["provider_request_id"]) if row["provider_request_id"] is not None else None
            ),
            operation_reconciled_at=row["operation_reconciled_at"],
            service_resource_name=str(row["service_resource_name"]),
            runtime_service_account=str(row["runtime_service_account"]),
            deployment_manifest_profile_ref=str(row["deployment_manifest_profile_ref"]),
            deployment_manifest_profile_hash=str(row["deployment_manifest_profile_hash"]),
            build_artifact_ref=str(row["build_artifact_ref"]),
            candidate_revision=candidate_revision,
            prior_revision=prior_revision,
            expected_current_assignment=assignment(current_percent),
            expected_next_assignment=assignment(next_percent),
            release_target_profile_hash=str(row["release_target_profile_hash"]),
        )

    def finalize_rollout(
        self,
        *,
        scope: Scope,
        candidate: RolloutAdvancementCandidate,
    ) -> None:
        if candidate.action != "FINALIZE_ROLLOUT":
            raise ReleaseRolloutConflict("rollout finalization candidate is malformed")
        prior = self._connection.execute(
            """SELECT rollout.status,reservation.status
                 FROM solvan_delivery.deployment_rollouts rollout
                 JOIN solvan_delivery.release_target_reservations reservation
                   ON reservation.organization_id=rollout.organization_id
                  AND reservation.project_id=rollout.project_id
                  AND reservation.environment_id=rollout.environment_id
                  AND reservation.id=rollout.target_reservation_id
                WHERE rollout.organization_id=%(organization_id)s
                  AND rollout.project_id=%(project_id)s
                  AND rollout.environment_id=%(environment_id)s
                  AND rollout.id=%(rollout_id)s""",
            {**scope.canonical_dict(), "rollout_id": candidate.rollout_id},
        ).fetchone()
        if prior is not None and tuple(prior) == ("PROMOTED", "RELEASED"):
            return
        row = self._connection.execute(
            """UPDATE solvan_delivery.deployment_rollouts rollout SET status='PROMOTED'
                FROM solvan_delivery.release_target_profiles target
               WHERE rollout.organization_id=%(organization_id)s
                 AND rollout.project_id=%(project_id)s
                 AND rollout.environment_id=%(environment_id)s
                 AND rollout.id=%(rollout_id)s AND rollout.status='CANARY_READY'
                 AND target.organization_id=rollout.organization_id
                 AND target.project_id=rollout.project_id
                 AND target.environment_id=rollout.environment_id
                 AND target.id=rollout.release_target_profile_id
                 AND target.profile_hash=rollout.release_target_profile_hash
                 AND target.status='ACTIVE'
                 AND target.canary_percentages[
                       cardinality(target.canary_percentages)]=100
                 AND cardinality(target.canary_percentages)=%(stage)s
              RETURNING rollout.target_reservation_id""",
            {
                **scope.canonical_dict(),
                "rollout_id": candidate.rollout_id,
                "stage": candidate.current_stage_ordinal,
            },
        ).fetchone()
        if row is None:
            raise ReleaseRolloutConflict("rollout finalization authority is stale")
        released = self._connection.execute(
            """UPDATE solvan_delivery.release_target_reservations
                  SET status='RELEASED'
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(reservation_id)s
                  AND status IN ('HELD','RECONCILING') RETURNING id""",
            {**scope.canonical_dict(), "reservation_id": str(row[0])},
        ).fetchone()
        if released is None:
            raise ReleaseRolloutConflict("rollout reservation could not be released")

    def load_finalization(
        self, *, scope: Scope, rollout_id: str, material_hash: str, now: datetime
    ) -> RolloutAdvancementMaterial:
        try:
            candidate = self.candidate_for_advancement(
                scope=scope, rollout_id=rollout_id, material_hash=material_hash, now=now
            )
        except ReleaseRolloutConflict:
            matches = tuple(
                item.advancement
                for item in self.promoted_request_candidates(scope=scope, now=now)
                if item.advancement.rollout_id == rollout_id
                and item.advancement.material_hash == material_hash
            )
            if len(matches) != 1:
                raise
            candidate = matches[0]
        if candidate.action != "FINALIZE_ROLLOUT":
            raise ReleaseRolloutConflict("rollout is not ready for finalization")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT rollout.release_target_profile_hash,
                          target.service_resource_name,target.runtime_service_account,
                          target.deployment_manifest_profile_ref,
                          target.deployment_manifest_profile_hash,target.service_name,
                          candidate.id AS candidate_id,candidate.build_artifact_ref,
                          observation.current_revision AS prior_revision
                     FROM solvan_delivery.deployment_rollouts rollout
                     JOIN solvan_delivery.release_target_profiles target
                       ON target.organization_id=rollout.organization_id
                      AND target.project_id=rollout.project_id
                      AND target.environment_id=rollout.environment_id
                      AND target.id=rollout.release_target_profile_id
                      AND target.profile_hash=rollout.release_target_profile_hash
                      AND target.status='ACTIVE'
                     JOIN solvan_delivery.release_candidates candidate
                       ON candidate.organization_id=rollout.organization_id
                      AND candidate.project_id=rollout.project_id
                      AND candidate.environment_id=rollout.environment_id
                      AND candidate.id=rollout.release_candidate_id
                     JOIN solvan_delivery.release_target_observations observation
                       ON observation.organization_id=rollout.organization_id
                      AND observation.project_id=rollout.project_id
                      AND observation.environment_id=rollout.environment_id
                      AND observation.observation_hash=rollout.predeploy_snapshot_hash
                    WHERE rollout.organization_id=%(organization_id)s
                      AND rollout.project_id=%(project_id)s
                      AND rollout.environment_id=%(environment_id)s
                      AND rollout.id=%(rollout_id)s
                      AND rollout.status IN ('CANARY_READY','PROMOTED')
                    FOR UPDATE OF rollout,target""",
                {**scope.canonical_dict(), "rollout_id": rollout_id},
            )
            row = cursor.fetchone()
        if row is None:
            raise ReleaseRolloutConflict("rollout finalization target is stale")
        service_name = str(row["service_name"])
        revision = f"{service_name[:34]}-sv-{str(row['candidate_id'])[-20:].lower()}"
        return RolloutAdvancementMaterial(
            candidate=candidate,
            operation_id=None,
            operation_status=None,
            provider_request_id=None,
            operation_reconciled_at=None,
            service_resource_name=str(row["service_resource_name"]),
            runtime_service_account=str(row["runtime_service_account"]),
            deployment_manifest_profile_ref=str(row["deployment_manifest_profile_ref"]),
            deployment_manifest_profile_hash=str(row["deployment_manifest_profile_hash"]),
            build_artifact_ref=str(row["build_artifact_ref"]),
            candidate_revision=revision,
            prior_revision=str(row["prior_revision"]),
            expected_current_assignment=((revision, 100),),
            expected_next_assignment=None,
            release_target_profile_hash=str(row["release_target_profile_hash"]),
        )

    def promoted_request_candidates(
        self, *, scope: Scope, now: datetime, limit: int = 20
    ) -> tuple[PromotedRequestCandidate, ...]:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT request.id AS request_id,request.sequence_no,rollout.id,
                          rollout.verification_profile_hash,
                          rollout.release_health_baseline_hash,
                          rollout.predeploy_snapshot_hash,rollout.intended_effect_hash,
                          target.canary_percentages,receipt.stage_ordinal,
                          receipt.receipt_envelope_ref,receipt.receipt_envelope_hash,
                          receipt.signature_ref,receipt.signature_hash,
                          receipt.verifier_identity,receipt.verifier_key_version,
                          receipt.observed_at AS receipt_observed_at
                     FROM solvan_delivery.deployment_rollouts rollout
                     JOIN solvan_delivery.release_candidates candidate
                       ON candidate.organization_id=rollout.organization_id
                      AND candidate.project_id=rollout.project_id
                      AND candidate.environment_id=rollout.environment_id
                      AND candidate.id=rollout.release_candidate_id
                     JOIN solvan_delivery.code_change_requests request
                       ON request.organization_id=candidate.organization_id
                      AND request.project_id=candidate.project_id
                      AND request.environment_id=candidate.environment_id
                      AND request.id=candidate.code_change_request_id
                      AND request.state='VERIFYING'
                     JOIN solvan_delivery.release_target_profiles target
                       ON target.organization_id=rollout.organization_id
                      AND target.project_id=rollout.project_id
                      AND target.environment_id=rollout.environment_id
                      AND target.id=rollout.release_target_profile_id
                      AND target.profile_hash=rollout.release_target_profile_hash
                     JOIN LATERAL (
                       SELECT item.* FROM solvan_delivery.release_verification_receipts item
                        WHERE item.organization_id=rollout.organization_id
                          AND item.project_id=rollout.project_id
                          AND item.environment_id=rollout.environment_id
                          AND item.deployment_rollout_id=rollout.id
                        ORDER BY item.stage_ordinal DESC LIMIT 1
                     ) receipt ON receipt.result='VERIFIED'
                    WHERE rollout.organization_id=%(organization_id)s
                      AND rollout.project_id=%(project_id)s
                      AND rollout.environment_id=%(environment_id)s
                      AND rollout.status='PROMOTED'
                      AND receipt.stage_ordinal=cardinality(target.canary_percentages)
                    ORDER BY receipt.observed_at,rollout.id LIMIT %(limit)s""",
                {**scope.canonical_dict(), "now": now, "limit": limit},
            )
            result: list[PromotedRequestCandidate] = []
            for row in cursor.fetchall():
                stage = int(row["stage_ordinal"])
                result.append(
                    PromotedRequestCandidate(
                        request_id=str(row["request_id"]),
                        request_sequence_no=int(row["sequence_no"]),
                        advancement=RolloutAdvancementCandidate(
                            rollout_id=str(row["id"]),
                            action="FINALIZE_ROLLOUT",
                            current_stage_ordinal=stage,
                            next_stage_ordinal=None,
                            next_percentage=None,
                            material_hash=canonical_sha256(
                                {
                                    "schema_version": 1,
                                    "command_kind": "FINALIZE_ROLLOUT",
                                    "deployment_rollout_id": str(row["id"]),
                                    "verified_stage_ordinal": stage,
                                    "verification_receipt_hash": str(row["receipt_envelope_hash"]),
                                    "next_stage_ordinal": None,
                                    "next_percentage": None,
                                }
                            ),
                            deadline=now + timedelta(minutes=1),
                            receipt_envelope_ref=str(row["receipt_envelope_ref"]),
                            receipt_envelope_hash=str(row["receipt_envelope_hash"]),
                            signature_ref=str(row["signature_ref"]),
                            signature_hash=str(row["signature_hash"]),
                            verification_profile_hash=str(row["verification_profile_hash"]),
                            release_health_baseline_hash=str(row["release_health_baseline_hash"]),
                            predeploy_snapshot_hash=str(row["predeploy_snapshot_hash"]),
                            intended_effect_hash=str(row["intended_effect_hash"]),
                            verifier_identity=str(row["verifier_identity"]),
                            verifier_key_version=str(row["verifier_key_version"]),
                            receipt_observed_at=row["receipt_observed_at"],
                        ),
                    )
                )
            return tuple(result)

    def mark_request_promoted(
        self,
        *,
        scope: Scope,
        candidate: PromotedRequestCandidate,
        receipt_hash: str,
        coordinator_identity: str,
    ) -> None:
        self._connection.execute(
            """INSERT INTO solvan_delivery.code_change_transitions
                 (organization_id,project_id,environment_id,id,code_change_request_id,
                  sequence_no,from_state,to_state,expected_sequence_no,input_hash,
                  idempotency_key,actor_kind,actor_identity)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(request_id)s,%(sequence)s,'VERIFYING','PROMOTED',%(expected_sequence)s,
                 %(input_hash)s,%(idempotency_key)s,'COORDINATOR',%(identity)s)""",
            {
                **scope.canonical_dict(),
                "id": new_identifier("cct"),
                "request_id": candidate.request_id,
                "sequence": candidate.request_sequence_no + 1,
                "expected_sequence": candidate.request_sequence_no,
                "input_hash": receipt_hash,
                "idempotency_key": (f"release-promoted:{candidate.advancement.rollout_id}"),
                "identity": coordinator_identity,
            },
        )

    def failed_request_candidates(
        self, *, scope: Scope, limit: int = 20
    ) -> tuple[FailedRequestCandidate, ...]:
        rows = self._connection.execute(
            """SELECT request.id,request.sequence_no,rollout.id,
                      receipt.receipt_envelope_hash
                 FROM solvan_delivery.deployment_rollouts rollout
                 JOIN solvan_delivery.release_candidates candidate
                   ON candidate.organization_id=rollout.organization_id
                  AND candidate.project_id=rollout.project_id
                  AND candidate.environment_id=rollout.environment_id
                  AND candidate.id=rollout.release_candidate_id
                 JOIN solvan_delivery.code_change_requests request
                   ON request.organization_id=candidate.organization_id
                  AND request.project_id=candidate.project_id
                  AND request.environment_id=candidate.environment_id
                  AND request.id=candidate.code_change_request_id
                  AND request.state='VERIFYING'
                 JOIN LATERAL (
                   SELECT item.* FROM solvan_delivery.release_verification_receipts item
                    WHERE item.organization_id=rollout.organization_id
                      AND item.project_id=rollout.project_id
                      AND item.environment_id=rollout.environment_id
                      AND item.deployment_rollout_id=rollout.id
                    ORDER BY item.stage_ordinal DESC,
                             item.observation_window_generation DESC LIMIT 1
                 ) receipt ON receipt.result IN ('FAILED','INCONCLUSIVE')
                WHERE rollout.organization_id=%(organization_id)s
                  AND rollout.project_id=%(project_id)s
                  AND rollout.environment_id=%(environment_id)s
                  AND rollout.status='VERIFICATION_FAILED'
                ORDER BY receipt.observed_at,rollout.id LIMIT %(limit)s""",
            {**scope.canonical_dict(), "limit": limit},
        ).fetchall()
        return tuple(
            FailedRequestCandidate(str(row[0]), int(row[1]), str(row[2]), str(row[3]))
            for row in rows
        )

    def mark_request_rollback_pending(
        self,
        *,
        scope: Scope,
        candidate: FailedRequestCandidate,
        coordinator_identity: str,
    ) -> None:
        first_id = new_identifier("cct")
        self._connection.execute(
            """INSERT INTO solvan_delivery.code_change_transitions
                 (organization_id,project_id,environment_id,id,code_change_request_id,
                  sequence_no,from_state,to_state,expected_sequence_no,input_hash,
                  idempotency_key,actor_kind,actor_identity)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(request_id)s,%(sequence)s,'VERIFYING','VERIFICATION_FAILED',
                 %(expected_sequence)s,%(input_hash)s,%(idempotency_key)s,
                 'COORDINATOR',%(identity)s)""",
            {
                **scope.canonical_dict(),
                "id": first_id,
                "request_id": candidate.request_id,
                "sequence": candidate.request_sequence_no + 1,
                "expected_sequence": candidate.request_sequence_no,
                "input_hash": candidate.receipt_envelope_hash,
                "idempotency_key": f"verification-failed:{candidate.rollout_id}",
                "identity": coordinator_identity,
            },
        )
        self._connection.execute(
            """INSERT INTO solvan_delivery.code_change_transitions
                 (organization_id,project_id,environment_id,id,code_change_request_id,
                  sequence_no,from_state,to_state,expected_sequence_no,input_hash,
                  idempotency_key,actor_kind,actor_identity)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(request_id)s,%(sequence)s,'VERIFICATION_FAILED',
                 'ROLLBACK_APPROVAL_PENDING',%(expected_sequence)s,%(input_hash)s,
                 %(idempotency_key)s,'COORDINATOR',%(identity)s)""",
            {
                **scope.canonical_dict(),
                "id": new_identifier("cct"),
                "request_id": candidate.request_id,
                "sequence": candidate.request_sequence_no + 2,
                "expected_sequence": candidate.request_sequence_no + 1,
                "input_hash": candidate.receipt_envelope_hash,
                "idempotency_key": f"rollback-proposed:{candidate.rollout_id}",
                "identity": coordinator_identity,
            },
        )

    def dispatchable_ids(self, *, scope: Scope, limit: int = 20) -> tuple[str, ...]:
        rows = self._connection.execute(
            """SELECT id FROM solvan_delivery.private_command_dispatches
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND command_kind IN ('START_ROLLOUT','PREPARE_CANARY','PROMOTE_CANARY',
                                       'FINALIZE_ROLLOUT','REGISTER_VERIFICATION_FAILURE',
                                       'ROLLBACK_RELEASE','FINALIZE_ROLLBACK')
                  AND status IN ('PREPARED','ISSUED','RECONCILING') AND deadline>now()
                ORDER BY created_at,id LIMIT %(limit)s""",
            {**scope.canonical_dict(), "limit": limit},
        ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def rollback_candidates(
        self,
        *,
        scope: Scope,
        now: datetime,
        limit: int = 20,
        include_dispatched: bool = False,
    ) -> tuple[ApprovedRollbackCandidate, ...]:
        rows = self._connection.execute(
            """SELECT request.id,request.sequence_no,decision.id,decision.decision_digest,
                      decision.expires_at,rollout.id,receipt.stage_ordinal,
                      receipt.receipt_envelope_hash,rollout.rollback_assignment_hash,
                      rollout.rollback_release_candidate_id
                 FROM solvan_delivery.code_change_requests request
                 JOIN solvan_delivery.code_change_decisions decision
                   ON decision.organization_id=request.organization_id
                  AND decision.project_id=request.project_id
                  AND decision.environment_id=request.environment_id
                  AND decision.code_change_request_id=request.id
                  AND decision.stage='ROLLBACK' AND decision.decision='APPROVED'
                  AND decision.expires_at>%(now)s
                 JOIN solvan_delivery.deployment_rollouts rollout
                   ON rollout.organization_id=request.organization_id
                  AND rollout.project_id=request.project_id
                  AND rollout.environment_id=request.environment_id
                  AND rollout.id=decision.deployment_rollout_id
                  AND rollout.status='VERIFICATION_FAILED'
                 JOIN LATERAL (
                   SELECT item.* FROM solvan_delivery.release_verification_receipts item
                    WHERE item.organization_id=rollout.organization_id
                      AND item.project_id=rollout.project_id
                      AND item.environment_id=rollout.environment_id
                      AND item.deployment_rollout_id=rollout.id
                    ORDER BY item.stage_ordinal DESC,
                             item.observation_window_generation DESC LIMIT 1
                 ) receipt ON receipt.receipt_envelope_hash=
                                  decision.release_verification_receipt_hash
                              AND receipt.result IN ('FAILED','INCONCLUSIVE')
                WHERE request.organization_id=%(organization_id)s
                  AND request.project_id=%(project_id)s
                  AND request.environment_id=%(environment_id)s
                  AND request.state='ROLLBACK_APPROVAL_PENDING'
                  AND (%(include_dispatched)s OR NOT EXISTS (
                    SELECT 1 FROM solvan_delivery.private_command_dispatches command
                     WHERE command.organization_id=request.organization_id
                       AND command.project_id=request.project_id
                       AND command.environment_id=request.environment_id
                       AND command.command_kind='ROLLBACK_RELEASE'
                       AND command.subject_id=rollout.id))
                ORDER BY decision.decided_at LIMIT %(limit)s""",
            {
                **scope.canonical_dict(),
                "now": now,
                "limit": limit,
                "include_dispatched": include_dispatched,
            },
        ).fetchall()
        result: list[ApprovedRollbackCandidate] = []
        for row in rows:
            material_hash = canonical_sha256(
                {
                    "schema_version": 1,
                    "command_kind": "ROLLBACK_RELEASE",
                    "code_change_request_id": str(row[0]),
                    "deployment_rollout_id": str(row[5]),
                    "decision_id": str(row[2]),
                    "decision_digest": str(row[3]),
                    "failed_verification_receipt_hash": str(row[7]),
                    "rollback_release_candidate_id": str(row[9]),
                    "rollback_assignment_hash": str(row[8]),
                }
            )
            result.append(
                ApprovedRollbackCandidate(
                    request_id=str(row[0]),
                    request_sequence_no=int(row[1]),
                    rollout_id=str(row[5]),
                    decision_id=str(row[2]),
                    decision_digest=str(row[3]),
                    stage_ordinal=int(row[6]),
                    material_hash=material_hash,
                    deadline=row[4],
                )
            )
        return tuple(result)

    def prepare_rollback_operation(
        self,
        *,
        scope: Scope,
        candidate: ApprovedRollbackCandidate,
        request_ref: str,
        request_hash: str,
        controller_identity: str,
    ) -> str:
        operation_id = new_identifier("dgo")
        row = self._connection.execute(
            """INSERT INTO solvan_delivery.deployment_rollout_operations
                 (organization_id,project_id,environment_id,id,deployment_rollout_id,
                  operation_kind,stage_ordinal,material_hash,idempotency_key,status,
                  request_ref,request_hash)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(rollout_id)s,'ROLLBACK_RELEASE',%(stage)s,%(material_hash)s,
                 %(idempotency_key)s,'PREPARED',%(request_ref)s,%(request_hash)s)
               RETURNING id""",
            {
                **scope.canonical_dict(),
                "id": operation_id,
                "rollout_id": candidate.rollout_id,
                "stage": candidate.stage_ordinal,
                "material_hash": candidate.material_hash,
                "idempotency_key": f"rollback-release:{candidate.rollout_id}",
                "request_ref": request_ref,
                "request_hash": request_hash,
            },
        ).fetchone()
        if row is None:
            raise ReleaseRolloutConflict("rollback operation was not prepared")
        updated = self._connection.execute(
            """UPDATE solvan_delivery.deployment_rollouts SET status='ROLLING_BACK'
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(rollout_id)s
                  AND status='VERIFICATION_FAILED' RETURNING id""",
            {**scope.canonical_dict(), "rollout_id": candidate.rollout_id},
        ).fetchone()
        if updated is None:
            raise ReleaseRolloutConflict("rollback rollout state is stale")
        self._connection.execute(
            """INSERT INTO solvan_delivery.code_change_transitions
                 (organization_id,project_id,environment_id,id,code_change_request_id,
                  sequence_no,from_state,to_state,expected_sequence_no,input_hash,
                  idempotency_key,actor_kind,actor_identity,decision_id,decision_digest)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(request_id)s,%(sequence)s,'ROLLBACK_APPROVAL_PENDING','ROLLING_BACK',
                 %(expected_sequence)s,%(input_hash)s,%(idempotency_key)s,
                 'DEPLOYMENT_CONTROLLER',%(identity)s,%(decision_id)s,%(decision_digest)s)""",
            {
                **scope.canonical_dict(),
                "id": new_identifier("cct"),
                "request_id": candidate.request_id,
                "sequence": candidate.request_sequence_no + 1,
                "expected_sequence": candidate.request_sequence_no,
                "input_hash": candidate.material_hash,
                "idempotency_key": f"rollback-start:{candidate.rollout_id}",
                "identity": controller_identity,
                "decision_id": candidate.decision_id,
                "decision_digest": candidate.decision_digest,
            },
        )
        return operation_id

    def load_rollback(
        self, *, scope: Scope, rollout_id: str, material_hash: str
    ) -> RollbackProviderMaterial:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT request.id AS request_id,request.sequence_no,
                          decision.id AS decision_id,decision.decision_digest,
                          decision.expires_at,rollout.id AS rollout_id,
                          rollout.rollback_release_candidate_id,
                          rollout.rollback_assignment_hash,
                          target.service_resource_name,target.runtime_service_account,
                          target.deployment_manifest_profile_ref,
                          target.deployment_manifest_profile_hash,
                          observation.current_revision AS rollback_revision,
                          receipt.stage_ordinal,receipt.receipt_envelope_hash,
                          receipt.observed_target_version,
                          receipt.observed_assignment_hash,
                          operation.id AS operation_id,operation.status AS operation_status,
                          operation.provider_request_id,
                          operation.reconciled_at AS operation_reconciled_at
                     FROM solvan_delivery.deployment_rollouts rollout
                     JOIN solvan_delivery.release_candidates candidate
                       ON candidate.organization_id=rollout.organization_id
                      AND candidate.project_id=rollout.project_id
                      AND candidate.environment_id=rollout.environment_id
                      AND candidate.id=rollout.release_candidate_id
                     JOIN solvan_delivery.code_change_requests request
                       ON request.organization_id=candidate.organization_id
                      AND request.project_id=candidate.project_id
                      AND request.environment_id=candidate.environment_id
                      AND request.id=candidate.code_change_request_id
                      AND request.state='ROLLING_BACK'
                     JOIN solvan_delivery.code_change_decisions decision
                       ON decision.organization_id=request.organization_id
                      AND decision.project_id=request.project_id
                      AND decision.environment_id=request.environment_id
                      AND decision.code_change_request_id=request.id
                      AND decision.deployment_rollout_id=rollout.id
                      AND decision.stage='ROLLBACK' AND decision.decision='APPROVED'
                     JOIN solvan_delivery.release_target_profiles target
                       ON target.organization_id=rollout.organization_id
                      AND target.project_id=rollout.project_id
                      AND target.environment_id=rollout.environment_id
                      AND target.id=rollout.release_target_profile_id
                      AND target.profile_hash=rollout.release_target_profile_hash
                      AND target.status='ACTIVE'
                     JOIN solvan_delivery.release_target_observations observation
                       ON observation.organization_id=rollout.organization_id
                      AND observation.project_id=rollout.project_id
                      AND observation.environment_id=rollout.environment_id
                      AND observation.observation_hash=rollout.predeploy_snapshot_hash
                     JOIN solvan_delivery.release_verification_receipts receipt
                       ON receipt.organization_id=rollout.organization_id
                      AND receipt.project_id=rollout.project_id
                      AND receipt.environment_id=rollout.environment_id
                      AND receipt.deployment_rollout_id=rollout.id
                      AND receipt.receipt_envelope_hash=
                          decision.release_verification_receipt_hash
                     JOIN solvan_delivery.deployment_rollout_operations operation
                       ON operation.organization_id=rollout.organization_id
                      AND operation.project_id=rollout.project_id
                      AND operation.environment_id=rollout.environment_id
                      AND operation.deployment_rollout_id=rollout.id
                      AND operation.operation_kind='ROLLBACK_RELEASE'
                      AND operation.material_hash=%(material_hash)s
                    WHERE rollout.organization_id=%(organization_id)s
                      AND rollout.project_id=%(project_id)s
                      AND rollout.environment_id=%(environment_id)s
                      AND rollout.id=%(rollout_id)s AND rollout.status='ROLLING_BACK'
                    FOR UPDATE OF rollout,operation,target""",
                {
                    **scope.canonical_dict(),
                    "rollout_id": rollout_id,
                    "material_hash": material_hash,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise ReleaseRolloutConflict("rollback authority is stale")
        candidate = ApprovedRollbackCandidate(
            request_id=str(row["request_id"]),
            request_sequence_no=int(row["sequence_no"]),
            rollout_id=rollout_id,
            decision_id=str(row["decision_id"]),
            decision_digest=str(row["decision_digest"]),
            stage_ordinal=int(row["stage_ordinal"]),
            material_hash=material_hash,
            deadline=row["expires_at"],
        )
        expected = canonical_sha256(
            {
                "schema_version": 1,
                "command_kind": "ROLLBACK_RELEASE",
                "code_change_request_id": candidate.request_id,
                "deployment_rollout_id": rollout_id,
                "decision_id": candidate.decision_id,
                "decision_digest": candidate.decision_digest,
                "failed_verification_receipt_hash": str(row["receipt_envelope_hash"]),
                "rollback_release_candidate_id": str(row["rollback_release_candidate_id"]),
                "rollback_assignment_hash": str(row["rollback_assignment_hash"]),
            }
        )
        if expected != material_hash:
            raise ReleaseRolloutConflict("rollback command material is not exact")
        return RollbackProviderMaterial(
            candidate=candidate,
            operation_id=str(row["operation_id"]),
            operation_status=str(row["operation_status"]),
            provider_request_id=(
                str(row["provider_request_id"]) if row["provider_request_id"] is not None else None
            ),
            operation_reconciled_at=row["operation_reconciled_at"],
            service_resource_name=str(row["service_resource_name"]),
            runtime_service_account=str(row["runtime_service_account"]),
            deployment_manifest_profile_ref=str(row["deployment_manifest_profile_ref"]),
            deployment_manifest_profile_hash=str(row["deployment_manifest_profile_hash"]),
            rollback_revision=str(row["rollback_revision"]),
            expected_target_version=str(row["observed_target_version"]),
            expected_assignment_hash=str(row["observed_assignment_hash"]),
        )

    def complete_rollback_effect(
        self,
        *,
        scope: Scope,
        operation_id: str,
        response_ref: str,
        response_hash: str,
    ) -> None:
        row = self._connection.execute(
            """UPDATE solvan_delivery.deployment_rollout_operations
                  SET status='SUCCEEDED',response_ref=%(response_ref)s,
                      response_hash=%(response_hash)s,reconciled_at=now(),completed_at=now()
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(operation_id)s
                  AND operation_kind='ROLLBACK_RELEASE' AND status='RECONCILING'
              RETURNING deployment_rollout_id""",
            {
                **scope.canonical_dict(),
                "operation_id": operation_id,
                "response_ref": response_ref,
                "response_hash": response_hash,
            },
        ).fetchone()
        if row is None:
            raise ReleaseRolloutConflict("rollback completion fence is stale")
        updated = self._connection.execute(
            """UPDATE solvan_delivery.deployment_rollouts SET status='ROLLBACK_PENDING'
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(rollout_id)s
                  AND status='ROLLING_BACK' RETURNING id""",
            {**scope.canonical_dict(), "rollout_id": str(row[0])},
        ).fetchone()
        if updated is None:
            raise ReleaseRolloutConflict("rollback cannot enter independent verification")

    def rollback_finalization_candidates(
        self,
        *,
        scope: Scope,
        now: datetime,
        limit: int = 20,
        include_dispatched: bool = False,
    ) -> tuple[RollbackFinalizationCandidate, ...]:
        rows = self._connection.execute(
            """SELECT request.id,request.sequence_no,rollout.id,receipt.expected_revision,
                      receipt.receipt_envelope_ref,receipt.receipt_envelope_hash,
                      receipt.signature_ref,receipt.signature_hash,
                      receipt.verifier_identity,receipt.verifier_key_version,
                      reservation.lease_expires_at,receipt.observed_at
                 FROM solvan_delivery.deployment_rollouts rollout
                 JOIN solvan_delivery.release_candidates candidate
                   ON (candidate.organization_id,candidate.project_id,
                       candidate.environment_id,candidate.id)=
                      (rollout.organization_id,rollout.project_id,
                       rollout.environment_id,rollout.release_candidate_id)
                 JOIN solvan_delivery.code_change_requests request
                   ON (request.organization_id,request.project_id,
                       request.environment_id,request.id)=
                      (candidate.organization_id,candidate.project_id,
                       candidate.environment_id,candidate.code_change_request_id)
                 JOIN solvan_delivery.release_rollback_verification_receipts receipt
                   ON receipt.organization_id=rollout.organization_id
                  AND receipt.project_id=rollout.project_id
                  AND receipt.environment_id=rollout.environment_id
                  AND receipt.deployment_rollout_id=rollout.id AND receipt.result='VERIFIED'
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
                  AND rollout.status='ROLLBACK_PENDING' AND request.state='ROLLING_BACK'
                  AND (%(include_dispatched)s OR NOT EXISTS (
                    SELECT 1 FROM solvan_delivery.private_command_dispatches command
                     WHERE command.organization_id=rollout.organization_id
                       AND command.project_id=rollout.project_id
                       AND command.environment_id=rollout.environment_id
                       AND command.command_kind='FINALIZE_ROLLBACK'
                       AND command.subject_id=rollout.id))
                ORDER BY receipt.observed_at LIMIT %(limit)s""",
            {
                **scope.canonical_dict(),
                "now": now,
                "limit": limit,
                "include_dispatched": include_dispatched,
            },
        ).fetchall()
        return tuple(
            RollbackFinalizationCandidate(
                request_id=str(row[0]),
                request_sequence_no=int(row[1]),
                rollout_id=str(row[2]),
                expected_revision=str(row[3]),
                receipt_envelope_ref=str(row[4]),
                receipt_envelope_hash=str(row[5]),
                signature_ref=str(row[6]),
                signature_hash=str(row[7]),
                verifier_identity=str(row[8]),
                verifier_key_version=str(row[9]),
                material_hash=canonical_sha256(
                    {
                        "schema_version": 1,
                        "command_kind": "FINALIZE_ROLLBACK",
                        "deployment_rollout_id": str(row[2]),
                        "rollback_verification_receipt_hash": str(row[5]),
                    }
                ),
                deadline=row[10],
                receipt_observed_at=row[11],
            )
            for row in rows
        )

    def finalize_rollback(
        self,
        *,
        scope: Scope,
        candidate: RollbackFinalizationCandidate,
        controller_identity: str,
    ) -> None:
        row = self._connection.execute(
            """UPDATE solvan_delivery.deployment_rollouts SET status='ROLLED_BACK'
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(rollout_id)s
                  AND status='ROLLBACK_PENDING' RETURNING target_reservation_id""",
            {**scope.canonical_dict(), "rollout_id": candidate.rollout_id},
        ).fetchone()
        if row is None:
            raise ReleaseRolloutConflict("rollback finalization is stale")
        self._connection.execute(
            """UPDATE solvan_delivery.release_target_reservations SET status='RELEASED'
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(reservation_id)s
                  AND status IN ('HELD','RECONCILING')""",
            {**scope.canonical_dict(), "reservation_id": str(row[0])},
        )
        self._connection.execute(
            """INSERT INTO solvan_delivery.code_change_transitions
                 (organization_id,project_id,environment_id,id,code_change_request_id,
                  sequence_no,from_state,to_state,expected_sequence_no,input_hash,
                  idempotency_key,actor_kind,actor_identity)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 %(request_id)s,%(sequence)s,'ROLLING_BACK','ROLLED_BACK',
                 %(expected_sequence)s,%(input_hash)s,%(idempotency_key)s,
                 'DEPLOYMENT_CONTROLLER',%(identity)s)""",
            {
                **scope.canonical_dict(),
                "id": new_identifier("cct"),
                "request_id": candidate.request_id,
                "sequence": candidate.request_sequence_no + 1,
                "expected_sequence": candidate.request_sequence_no,
                "input_hash": candidate.receipt_envelope_hash,
                "idempotency_key": f"rollback-finalized:{candidate.rollout_id}",
                "identity": controller_identity,
            },
        )

    def load_canary(
        self, *, scope: Scope, rollout_id: str, material_hash: str
    ) -> CanaryProviderMaterial:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT rollout.id,rollout.approval_digest,
                          rollout.predeploy_snapshot_hash,
                          rollout.release_target_profile_id,
                          operation.id AS operation_id,
                          operation.status AS operation_status,operation.provider_request_id,
                          operation.reconciled_at AS operation_reconciled_at,
                          target.service_resource_name,target.runtime_service_account,
                          target.deployment_manifest_profile_ref,
                          target.deployment_manifest_profile_hash,target.canary_percentages,
                          target.profile_hash,candidate.candidate_envelope_ref,
                          candidate.candidate_envelope_hash,candidate.id AS candidate_id,
                          candidate.code_change_request_id,
                          candidate.repository_binding_id,candidate.merged_commit_sha,
                          candidate.source_tree_hash,candidate.release_policy_hash,
                          candidate.signer_identity,candidate.signer_key_version,
                          rollout.expected_target_version,
                          rollout.expected_target_epoch,observation.current_revision,
                          observation.assignment_hash,observation.observation_hash,
                          rollout.release_health_baseline_ref,
                          rollout.release_health_baseline_hash,
                          rollout.verification_profile_hash,
                          baseline.signature_ref AS baseline_signature_ref,
                          baseline.signature_hash AS baseline_signature_hash,
                          baseline.verifier_identity,baseline.verifier_key_version
                     FROM solvan_delivery.deployment_rollouts rollout
                     JOIN solvan_delivery.deployment_rollout_operations operation
                       ON operation.organization_id=rollout.organization_id
                      AND operation.project_id=rollout.project_id
                      AND operation.environment_id=rollout.environment_id
                      AND operation.deployment_rollout_id=rollout.id
                      AND operation.operation_kind='PREPARE_CANARY'
                      AND operation.stage_ordinal=1 AND operation.material_hash=%(material_hash)s
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
                     JOIN solvan_delivery.release_signer_keys signer
                       ON signer.organization_id=candidate.organization_id
                      AND signer.project_id=candidate.project_id
                      AND signer.environment_id=candidate.environment_id
                      AND signer.signer_identity=candidate.signer_identity
                      AND signer.key_version=candidate.signer_key_version
                      AND signer.status='ACTIVE'
                     JOIN solvan_delivery.release_target_observations observation
                       ON observation.organization_id=rollout.organization_id
                      AND observation.project_id=rollout.project_id
                      AND observation.environment_id=rollout.environment_id
                      AND observation.observation_hash=rollout.predeploy_snapshot_hash
                     JOIN solvan_delivery.release_health_baselines baseline
                       ON baseline.organization_id=rollout.organization_id
                      AND baseline.project_id=rollout.project_id
                      AND baseline.environment_id=rollout.environment_id
                      AND baseline.id=rollout.release_health_baseline_id
                      AND baseline.baseline_ref=rollout.release_health_baseline_ref
                      AND baseline.baseline_hash=rollout.release_health_baseline_hash
                      AND baseline.release_candidate_id=rollout.release_candidate_id
                      AND baseline.release_target_profile_id=rollout.release_target_profile_id
                      AND baseline.target_observation_hash=observation.observation_hash
                     JOIN solvan_delivery.release_verifier_keys verifier_key
                       ON verifier_key.organization_id=baseline.organization_id
                      AND verifier_key.project_id=baseline.project_id
                      AND verifier_key.environment_id=baseline.environment_id
                      AND verifier_key.verifier_identity=baseline.verifier_identity
                      AND verifier_key.key_version=baseline.verifier_key_version
                      AND verifier_key.status='ACTIVE'
                    WHERE rollout.organization_id=%(organization_id)s
                      AND rollout.project_id=%(project_id)s
                      AND rollout.environment_id=%(environment_id)s AND rollout.id=%(rollout_id)s
                      AND rollout.status='CANARY_DEPLOYING' AND target.status='ACTIVE'
                    FOR UPDATE OF rollout,operation,target,signer,verifier_key""",
                {
                    **scope.canonical_dict(),
                    "rollout_id": rollout_id,
                    "material_hash": material_hash,
                },
            )
            row = cursor.fetchone()
        percentages = row["canary_percentages"] if row is not None else None
        if (
            row is None
            or not isinstance(percentages, list)
            or not percentages
            or type(percentages[0]) is not int
        ):
            raise ReleaseRolloutConflict("canary rollout authority is stale")
        expected_material_hash = canonical_sha256(
            {
                "schema_version": 1,
                "command_kind": "PREPARE_CANARY",
                "rollout_id": str(row["id"]),
                "release_candidate_id": str(row["candidate_id"]),
                "target_profile_hash": str(row["profile_hash"]),
                "approval_digest": str(row["approval_digest"]),
                "predeploy_snapshot_hash": str(row["predeploy_snapshot_hash"]),
                "stage_ordinal": 1,
                "canary_percent": int(percentages[0]),
            }
        )
        if expected_material_hash != material_hash:
            raise ReleaseRolloutConflict("canary command material is not exact")
        return CanaryProviderMaterial(
            rollout_id=str(row["id"]),
            operation_id=str(row["operation_id"]),
            operation_status=str(row["operation_status"]),
            provider_request_id=(
                str(row["provider_request_id"]) if row["provider_request_id"] is not None else None
            ),
            operation_reconciled_at=row["operation_reconciled_at"],
            service_resource_name=str(row["service_resource_name"]),
            runtime_service_account=str(row["runtime_service_account"]),
            deployment_manifest_profile_ref=str(row["deployment_manifest_profile_ref"]),
            deployment_manifest_profile_hash=str(row["deployment_manifest_profile_hash"]),
            candidate_envelope_ref=str(row["candidate_envelope_ref"]),
            candidate_envelope_hash=str(row["candidate_envelope_hash"]),
            code_change_request_id=str(row["code_change_request_id"]),
            release_candidate_id=str(row["candidate_id"]),
            release_target_profile_id=str(row["release_target_profile_id"]),
            repository_binding_id=str(row["repository_binding_id"]),
            merged_commit_sha=str(row["merged_commit_sha"]),
            source_tree_hash=str(row["source_tree_hash"]),
            release_policy_hash=str(row["release_policy_hash"]),
            signer_identity=str(row["signer_identity"]),
            signer_key_version=str(row["signer_key_version"]),
            expected_target_version=str(row["expected_target_version"]),
            expected_target_epoch=int(row["expected_target_epoch"]),
            predeploy_revision=str(row["current_revision"]),
            predeploy_assignment_hash=str(row["assignment_hash"]),
            first_canary_percent=int(percentages[0]),
            target_profile_hash=str(row["profile_hash"]),
            release_health_baseline_ref=str(row["release_health_baseline_ref"]),
            release_health_baseline_hash=str(row["release_health_baseline_hash"]),
            baseline_signature_ref=str(row["baseline_signature_ref"]),
            baseline_signature_hash=str(row["baseline_signature_hash"]),
            verification_profile_hash=str(row["verification_profile_hash"]),
            verifier_identity=str(row["verifier_identity"]),
            verifier_key_version=str(row["verifier_key_version"]),
            target_observation_hash=str(row["observation_hash"]),
        )

    def claim_canary(self, *, scope: Scope, operation_id: str) -> bool:
        row = self._connection.execute(
            """UPDATE solvan_delivery.deployment_rollout_operations
                  SET status='ISSUED',issued_at=now()
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(operation_id)s
                  AND status='PREPARED' RETURNING id""",
            {**scope.canonical_dict(), "operation_id": operation_id},
        ).fetchone()
        return row is not None

    def record_provider_operation(
        self, *, scope: Scope, operation_id: str, provider_request_id: str
    ) -> None:
        row = self._connection.execute(
            """UPDATE solvan_delivery.deployment_rollout_operations
                  SET status='RECONCILING',provider_request_id=%(provider_request_id)s,
                      reconciled_at=now()
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(operation_id)s
                  AND status='ISSUED' AND provider_request_id IS NULL RETURNING id""",
            {
                **scope.canonical_dict(),
                "operation_id": operation_id,
                "provider_request_id": provider_request_id,
            },
        ).fetchone()
        if row is None:
            raise ReleaseRolloutConflict("canary provider operation fence is stale")

    def begin_reconciliation_without_provider_handle(
        self, *, scope: Scope, operation_id: str
    ) -> datetime:
        """Fence authoritative state reconciliation after the issue/record gap.

        Cloud Run does not provide a caller idempotency key for Service PATCH.
        If the request succeeded but the process died before persisting its LRO
        name, only an exact authoritative target read may establish success; a
        second mutation is never issued.
        """

        row = self._connection.execute(
            """UPDATE solvan_delivery.deployment_rollout_operations
                  SET status='RECONCILING',reconciled_at=coalesce(reconciled_at,now())
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND id=%(operation_id)s AND status='ISSUED'
                  AND provider_request_id IS NULL
              RETURNING reconciled_at""",
            {**scope.canonical_dict(), "operation_id": operation_id},
        ).fetchone()
        if row is None:
            raise ReleaseRolloutConflict("provider-handle reconciliation fence is stale")
        return cast(datetime, row[0])

    def mark_operation_ambiguous(
        self,
        *,
        scope: Scope,
        operation_id: str,
        response_ref: str,
        response_hash: str,
        error_class: str,
        controller_identity: str,
    ) -> None:
        """Close an issued but unknowable provider effect without permitting retry."""

        if not response_ref.startswith("gs://") or not response_hash.startswith("sha256:"):
            raise ReleaseRolloutConflict("ambiguous rollout receipt is malformed")
        if not error_class or len(error_class) > 120:
            raise ReleaseRolloutConflict("ambiguous rollout error class is invalid")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT operation.deployment_rollout_id,operation.operation_kind,
                          rollout.target_reservation_id,candidate.code_change_request_id,
                          request.sequence_no,request.state
                     FROM solvan_delivery.deployment_rollout_operations operation
                     JOIN solvan_delivery.deployment_rollouts rollout
                       ON rollout.organization_id=operation.organization_id
                      AND rollout.project_id=operation.project_id
                      AND rollout.environment_id=operation.environment_id
                      AND rollout.id=operation.deployment_rollout_id
                     JOIN solvan_delivery.release_candidates candidate
                       ON candidate.organization_id=rollout.organization_id
                      AND candidate.project_id=rollout.project_id
                      AND candidate.environment_id=rollout.environment_id
                      AND candidate.id=rollout.release_candidate_id
                     JOIN solvan_delivery.code_change_requests request
                       ON request.organization_id=candidate.organization_id
                      AND request.project_id=candidate.project_id
                      AND request.environment_id=candidate.environment_id
                      AND request.id=candidate.code_change_request_id
                    WHERE operation.organization_id=%(organization_id)s
                      AND operation.project_id=%(project_id)s
                      AND operation.environment_id=%(environment_id)s
                      AND operation.id=%(operation_id)s
                      AND operation.status IN ('ISSUED','RECONCILING')
                    FOR UPDATE OF operation,rollout,request""",
                {**scope.canonical_dict(), "operation_id": operation_id},
            )
            material = cursor.fetchone()
            if material is None:
                raise ReleaseRolloutConflict("rollout ambiguity fence is stale")
            cursor.execute(
                """UPDATE solvan_delivery.release_target_reservations
                      SET status='RECONCILING'
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND id=%(reservation_id)s
                      AND status IN ('HELD','RECONCILING')""",
                {
                    **scope.canonical_dict(),
                    "reservation_id": str(material["target_reservation_id"]),
                },
            )
            if cursor.rowcount != 1:
                raise ReleaseRolloutConflict("ambiguous rollout reservation is unavailable")
            cursor.execute(
                """UPDATE solvan_delivery.deployment_rollout_operations
                      SET status='AMBIGUOUS',response_ref=%(response_ref)s,
                          response_hash=%(response_hash)s,error_class=%(error_class)s,
                          reconciled_at=coalesce(reconciled_at,now()),completed_at=now()
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND id=%(operation_id)s
                      AND status IN ('ISSUED','RECONCILING')""",
                {
                    **scope.canonical_dict(),
                    "operation_id": operation_id,
                    "response_ref": response_ref,
                    "response_hash": response_hash,
                    "error_class": error_class,
                },
            )
            if cursor.rowcount != 1:
                raise ReleaseRolloutConflict("rollout ambiguity operation was replaced")
            rollout_id = str(material["deployment_rollout_id"])
            cursor.execute(
                """UPDATE solvan_delivery.deployment_rollouts SET status='AMBIGUOUS'
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(rollout_id)s""",
                {**scope.canonical_dict(), "rollout_id": rollout_id},
            )
            if cursor.rowcount != 1:
                raise ReleaseRolloutConflict("ambiguous rollout is unavailable")
            from_state = str(material["state"])
            to_state = "ROLLBACK_AMBIGUOUS" if from_state == "ROLLING_BACK" else "BLOCKED"
            if from_state not in {"CANARY_DEPLOYING", "VERIFYING", "ROLLING_BACK"}:
                raise ReleaseRolloutConflict("request cannot record rollout ambiguity")
            cursor.execute(
                """INSERT INTO solvan_delivery.code_change_transitions
                     (organization_id,project_id,environment_id,id,code_change_request_id,
                      sequence_no,from_state,to_state,expected_sequence_no,input_hash,
                      idempotency_key,actor_kind,actor_identity)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                     %(request_id)s,%(sequence)s,%(from_state)s,%(to_state)s,
                     %(expected_sequence)s,%(input_hash)s,%(idempotency_key)s,
                     'DEPLOYMENT_CONTROLLER',%(identity)s)""",
                {
                    **scope.canonical_dict(),
                    "id": new_identifier("cct"),
                    "request_id": str(material["code_change_request_id"]),
                    "sequence": int(material["sequence_no"]) + 1,
                    "expected_sequence": int(material["sequence_no"]),
                    "from_state": from_state,
                    "to_state": to_state,
                    "input_hash": response_hash,
                    "idempotency_key": f"rollout-ambiguous:{operation_id}",
                    "identity": controller_identity,
                },
            )

    def complete_canary(
        self,
        *,
        scope: Scope,
        operation_id: str,
        response_ref: str,
        response_hash: str,
        controller_identity: str,
    ) -> None:
        row = self._connection.execute(
            """UPDATE solvan_delivery.deployment_rollout_operations
                  SET status='SUCCEEDED',response_ref=%(response_ref)s,
                      response_hash=%(response_hash)s,reconciled_at=now(),completed_at=now()
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(operation_id)s
                  AND status='RECONCILING' RETURNING deployment_rollout_id""",
            {
                **scope.canonical_dict(),
                "operation_id": operation_id,
                "response_ref": response_ref,
                "response_hash": response_hash,
            },
        ).fetchone()
        if row is None:
            raise ReleaseRolloutConflict("canary completion fence is stale")
        rollout_id = str(row[0])
        rollout = self._connection.execute(
            """UPDATE solvan_delivery.deployment_rollouts
                  SET status='CANARY_READY'
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(rollout_id)s
                  AND status IN ('CANARY_DEPLOYING','PROMOTING')
              RETURNING release_candidate_id""",
            {**scope.canonical_dict(), "rollout_id": rollout_id},
        ).fetchone()
        if rollout is None:
            raise ReleaseRolloutConflict("rollout cannot enter verification")
        request = self._connection.execute(
            """SELECT request.id,request.sequence_no,request.state
                 FROM solvan_delivery.release_candidates candidate
                 JOIN solvan_delivery.code_change_requests request
                   ON request.organization_id=candidate.organization_id
                  AND request.project_id=candidate.project_id
                  AND request.environment_id=candidate.environment_id
                  AND request.id=candidate.code_change_request_id
                WHERE candidate.organization_id=%(organization_id)s
                  AND candidate.project_id=%(project_id)s
                  AND candidate.environment_id=%(environment_id)s
                  AND candidate.id=%(candidate_id)s FOR UPDATE OF request""",
            {**scope.canonical_dict(), "candidate_id": str(rollout[0])},
        ).fetchone()
        if request is None:
            raise ReleaseRolloutConflict("rollout request is absent")
        if str(request[2]) == "CANARY_DEPLOYING":
            self._connection.execute(
                """INSERT INTO solvan_delivery.code_change_transitions
                     (organization_id,project_id,environment_id,id,code_change_request_id,
                      sequence_no,from_state,to_state,expected_sequence_no,input_hash,
                      idempotency_key,actor_kind,actor_identity)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                     %(request_id)s,%(sequence)s,'CANARY_DEPLOYING','VERIFYING',
                     %(expected_sequence)s,%(input_hash)s,%(idempotency_key)s,
                     'DEPLOYMENT_CONTROLLER',%(identity)s)""",
                {
                    **scope.canonical_dict(),
                    "id": new_identifier("cct"),
                    "request_id": str(request[0]),
                    "sequence": int(request[1]) + 1,
                    "expected_sequence": int(request[1]),
                    "input_hash": response_hash,
                    "idempotency_key": f"canary-ready:{rollout_id}",
                    "identity": controller_identity,
                },
            )
        elif str(request[2]) != "VERIFYING":
            raise ReleaseRolloutConflict("request cannot enter release verification")
