"""Cloud SQL authority for review challenges and code-change stage decisions."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol, cast

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.code_change_decisions import (
    CodeChangeDecisionError,
    CodeChangeDecisionStage,
    CodeChangeDecisionValue,
    DecisionMaterial,
    deployment_decision_material,
    merge_decision_material,
    pr_creation_decision_material,
    required_role,
    rollback_decision_material,
)
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier


class CodeChangeDecisionConflict(CodeChangeDecisionError):
    """The reviewed decision material or authority changed."""


class EvidenceReceipt(Protocol):
    @property
    def uri(self) -> str: ...

    @property
    def content_hash(self) -> str: ...


@dataclass(frozen=True, slots=True)
class DecisionChallengeDraft:
    decision: DecisionMaterial
    principal: str
    authenticated_session_hash: str
    authenticated_at: datetime
    authorization_snapshot: Mapping[str, object]
    authorization_snapshot_hash: str


@dataclass(frozen=True, slots=True)
class DecisionChallenge:
    challenge_id: str
    decision_digest: str
    stage: CodeChangeDecisionStage
    required_role: str
    material_ref: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class RecordedDecision:
    decision_id: str
    decision_digest: str
    decision: CodeChangeDecisionValue
    expires_at: datetime
    created: bool


class PostgresCodeChangeDecisionStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def draft_challenge(
        self,
        *,
        scope: Scope,
        request_id: str,
        stage: CodeChangeDecisionStage,
        principal: str,
        authenticated_session_hash: str,
        authenticated_at: datetime,
        now: datetime,
    ) -> DecisionChallengeDraft:
        """Read current request/role material without creating authority."""

        _aware(authenticated_at)
        _aware(now)
        if now - authenticated_at > timedelta(minutes=5) or authenticated_at > now:
            raise CodeChangeDecisionConflict("fresh authenticated session is required")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            request = self._request(cursor, scope=scope, request_id=request_id, lock=False)
            authorization = self._authorization_snapshot(
                cursor,
                scope=scope,
                principal=principal,
                role=required_role(stage),
                now=now,
            )
            expires_at = min(_datetime(request["expires_at"]), now + timedelta(minutes=10))
            decision = self._current_material(
                cursor=cursor,
                scope=scope,
                request=request,
                stage=stage,
                principal=principal,
                expires_at=expires_at,
                now=now,
            )
        return DecisionChallengeDraft(
            decision=decision,
            principal=principal,
            authenticated_session_hash=authenticated_session_hash,
            authenticated_at=authenticated_at,
            authorization_snapshot=authorization,
            authorization_snapshot_hash=canonical_sha256(authorization),
        )

    def record_challenge(
        self,
        *,
        scope: Scope,
        draft: DecisionChallengeDraft,
        material_receipt: EvidenceReceipt,
        authorization_receipt: EvidenceReceipt,
        now: datetime,
    ) -> DecisionChallenge:
        """Persist a review challenge only if its request and role remain exact."""

        if material_receipt.content_hash != draft.decision.digest:
            raise CodeChangeDecisionConflict("decision material receipt differs")
        if authorization_receipt.content_hash != draft.authorization_snapshot_hash:
            raise CodeChangeDecisionConflict("authorization snapshot receipt differs")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            request = self._request(
                cursor,
                scope=scope,
                request_id=draft.decision.code_change_request_id,
                lock=True,
            )
            authorization = self._authorization_snapshot(
                cursor,
                scope=scope,
                principal=draft.principal,
                role=draft.decision.required_role,
                now=now,
            )
            current = self._current_material(
                cursor=cursor,
                scope=scope,
                request=request,
                stage=draft.decision.stage,
                principal=draft.principal,
                expires_at=draft.decision.expires_at,
                now=now,
            )
            if (
                current.digest != draft.decision.digest
                or canonical_sha256(authorization) != draft.authorization_snapshot_hash
            ):
                raise CodeChangeDecisionConflict("decision material changed before review")
            cursor.execute(
                """SELECT * FROM solvan_delivery.code_change_decision_challenges
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND code_change_request_id=%(request_id)s AND stage=%(stage)s
                      AND principal=%(principal)s AND status='PENDING'
                    FOR UPDATE""",
                {
                    **scope.canonical_dict(),
                    "request_id": current.code_change_request_id,
                    "stage": current.stage.value,
                    "principal": draft.principal,
                },
            )
            existing = cursor.fetchone()
            if existing is not None and existing["expires_at"] <= now:
                cursor.execute(
                    """UPDATE solvan_delivery.code_change_decision_challenges
                          SET status='EXPIRED',consumed_at=%(now)s
                        WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s AND id=%(id)s""",
                    {**scope.canonical_dict(), "id": existing["id"], "now": now},
                )
                existing = None
            if existing is not None:
                if (
                    existing["decision_digest"] != current.digest
                    or existing["authenticated_session_hash"] != draft.authenticated_session_hash
                ):
                    raise CodeChangeDecisionConflict("another current review challenge exists")
                return self._challenge(existing)
            challenge_id = new_identifier("dch")
            cursor.execute(
                """INSERT INTO solvan_delivery.code_change_decision_challenges
                    (organization_id,project_id,environment_id,id,code_change_request_id,
                     stage,principal,decision_digest,material_ref,material_hash,
                     authorization_snapshot_ref,authorization_snapshot_hash,
                     authenticated_session_hash,authenticated_at,expires_at,status)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                     %(request_id)s,%(stage)s,%(principal)s,%(decision_digest)s,
                     %(material_ref)s,%(material_hash)s,%(authorization_ref)s,
                     %(authorization_hash)s,%(session_hash)s,%(authenticated_at)s,
                     %(expires_at)s,'PENDING') RETURNING *""",
                {
                    **scope.canonical_dict(),
                    "id": challenge_id,
                    "request_id": current.code_change_request_id,
                    "stage": current.stage.value,
                    "principal": draft.principal,
                    "decision_digest": current.digest,
                    "material_ref": material_receipt.uri,
                    "material_hash": material_receipt.content_hash,
                    "authorization_ref": authorization_receipt.uri,
                    "authorization_hash": authorization_receipt.content_hash,
                    "session_hash": draft.authenticated_session_hash,
                    "authenticated_at": draft.authenticated_at,
                    "expires_at": current.expires_at,
                },
            )
            inserted = cursor.fetchone()
        if inserted is None:
            raise CodeChangeDecisionConflict("decision challenge was not persisted")
        return self._challenge(inserted)

    def decide(
        self,
        *,
        scope: Scope,
        challenge_id: str,
        expected_request_id: str,
        principal: str,
        decision_request_id: str,
        expected_digest: str,
        decision: CodeChangeDecisionValue,
        reason: str,
        step_up_receipt: EvidenceReceipt,
        now: datetime,
    ) -> RecordedDecision:
        """Consume one exact challenge and append one non-forking decision."""

        _aware(now)
        if not 8 <= len(decision_request_id) <= 255:
            raise CodeChangeDecisionConflict("decision request ID is invalid")
        if not 8 <= len(reason.strip()) <= 2_000:
            raise CodeChangeDecisionConflict("decision reason is invalid")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT * FROM solvan_delivery.code_change_decisions
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND decision_request_id=%(decision_request_id)s""",
                {**scope.canonical_dict(), "decision_request_id": decision_request_id},
            )
            replay = cursor.fetchone()
            if replay is not None:
                return self._decision_replay(
                    replay,
                    principal=principal,
                    expected_digest=expected_digest,
                    decision=decision,
                )
            cursor.execute(
                """SELECT * FROM solvan_delivery.code_change_decision_challenges
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(challenge_id)s
                    FOR UPDATE""",
                {**scope.canonical_dict(), "challenge_id": challenge_id},
            )
            challenge = cursor.fetchone()
            if (
                challenge is None
                or challenge["status"] != "PENDING"
                or challenge["code_change_request_id"] != expected_request_id
                or challenge["principal"] != principal
                or challenge["decision_digest"] != expected_digest
                or challenge["expires_at"] <= now
            ):
                raise CodeChangeDecisionConflict("decision challenge is stale or unavailable")
            stage = CodeChangeDecisionStage(str(challenge["stage"]))
            request = self._request(
                cursor,
                scope=scope,
                request_id=str(challenge["code_change_request_id"]),
                lock=True,
            )
            current = self._current_material(
                cursor=cursor,
                scope=scope,
                request=request,
                stage=stage,
                principal=principal,
                expires_at=_datetime(challenge["expires_at"]),
                now=now,
            )
            authorization = self._authorization_snapshot(
                cursor,
                scope=scope,
                principal=principal,
                role=required_role(stage),
                now=now,
            )
            if (
                current.digest != expected_digest
                or canonical_sha256(authorization) != challenge["authorization_snapshot_hash"]
            ):
                raise CodeChangeDecisionConflict("decision material or role changed")
            cursor.execute(
                """SELECT * FROM solvan_delivery.code_change_decisions
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND code_change_request_id=%(request_id)s AND stage=%(stage)s
                    ORDER BY sequence_no DESC LIMIT 1 FOR UPDATE""",
                {
                    **scope.canonical_dict(),
                    "request_id": current.code_change_request_id,
                    "stage": stage.value,
                },
            )
            predecessor = cursor.fetchone()
            sequence = 1 if predecessor is None else int(predecessor["sequence_no"]) + 1
            decision_id = new_identifier("ccd")
            cursor.execute(
                """INSERT INTO solvan_delivery.code_change_decisions
                    (organization_id,project_id,environment_id,id,code_change_request_id,
                     stage,sequence_no,decision_digest,principal,
                     github_reviewer_binding_id,github_review_state_hash,
                     release_candidate_id,release_target_profile_id,
                     release_target_observation_hash,release_health_baseline_id,
                     release_health_baseline_hash,deployment_rollout_id,
                     release_verification_receipt_hash,decision,reason,
                     expires_at,supersedes_id,authorization_snapshot_hash,
                     step_up_receipt_hash,decision_request_id,authenticated_session_hash,
                     authenticated_at,authorization_snapshot_ref,step_up_receipt_ref)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                     %(request_id)s,%(stage)s,%(sequence)s,%(digest)s,%(principal)s,
                     %(github_binding_id)s,%(github_review_hash)s,
                     %(release_candidate_id)s,%(release_target_profile_id)s,
                     %(release_target_observation_hash)s,%(release_health_baseline_id)s,
                     %(release_health_baseline_hash)s,%(deployment_rollout_id)s,
                     %(release_verification_receipt_hash)s,
                     %(decision)s,%(reason)s,%(expires_at)s,%(supersedes_id)s,
                     %(authorization_hash)s,%(step_up_hash)s,%(decision_request_id)s,
                     %(session_hash)s,%(authenticated_at)s,%(authorization_ref)s,
                     %(step_up_ref)s)""",
                {
                    **scope.canonical_dict(),
                    "id": decision_id,
                    "request_id": current.code_change_request_id,
                    "stage": stage.value,
                    "sequence": sequence,
                    "digest": current.digest,
                    "principal": principal,
                    "github_binding_id": (
                        current.github_reviewer_binding_id
                        if decision is CodeChangeDecisionValue.APPROVED
                        else None
                    ),
                    "github_review_hash": (
                        current.github_review_state_hash
                        if decision is CodeChangeDecisionValue.APPROVED
                        else None
                    ),
                    "release_candidate_id": (
                        current.release_candidate_id
                        if decision is CodeChangeDecisionValue.APPROVED
                        else None
                    ),
                    "release_target_profile_id": (
                        current.release_target_profile_id
                        if decision is CodeChangeDecisionValue.APPROVED
                        else None
                    ),
                    "release_target_observation_hash": (
                        current.release_target_observation_hash
                        if decision is CodeChangeDecisionValue.APPROVED
                        else None
                    ),
                    "release_health_baseline_id": (
                        current.release_health_baseline_id
                        if decision is CodeChangeDecisionValue.APPROVED
                        else None
                    ),
                    "release_health_baseline_hash": (
                        current.release_health_baseline_hash
                        if decision is CodeChangeDecisionValue.APPROVED
                        else None
                    ),
                    "deployment_rollout_id": (
                        current.deployment_rollout_id
                        if decision is CodeChangeDecisionValue.APPROVED
                        else None
                    ),
                    "release_verification_receipt_hash": (
                        current.release_verification_receipt_hash
                        if decision is CodeChangeDecisionValue.APPROVED
                        else None
                    ),
                    "decision": decision.value,
                    "reason": reason.strip(),
                    "expires_at": current.expires_at,
                    "supersedes_id": None if predecessor is None else predecessor["id"],
                    "authorization_hash": challenge["authorization_snapshot_hash"],
                    "step_up_hash": step_up_receipt.content_hash,
                    "decision_request_id": decision_request_id,
                    "session_hash": challenge["authenticated_session_hash"],
                    "authenticated_at": challenge["authenticated_at"],
                    "authorization_ref": challenge["authorization_snapshot_ref"],
                    "step_up_ref": step_up_receipt.uri,
                },
            )
            cursor.execute(
                """UPDATE solvan_delivery.code_change_decision_challenges
                      SET status='CONSUMED',decision_id=%(decision_id)s,consumed_at=%(now)s
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(challenge_id)s""",
                {
                    **scope.canonical_dict(),
                    "decision_id": decision_id,
                    "now": now,
                    "challenge_id": challenge_id,
                },
            )
        return RecordedDecision(decision_id, current.digest, decision, current.expires_at, True)

    @staticmethod
    def _current_material(
        *,
        cursor: Any,
        scope: Scope,
        request: Mapping[str, object],
        stage: CodeChangeDecisionStage,
        principal: str,
        expires_at: datetime,
        now: datetime,
    ) -> DecisionMaterial:
        if stage is CodeChangeDecisionStage.PR_CREATION:
            return pr_creation_decision_material(request=request, expires_at=expires_at)
        if stage is CodeChangeDecisionStage.MERGE:
            github = PostgresCodeChangeDecisionStore._merge_source(
                cursor,
                scope=scope,
                request_id=str(request["id"]),
                principal=principal,
                now=now,
            )
            return merge_decision_material(request=request, github=github, expires_at=expires_at)
        if stage is CodeChangeDecisionStage.DEPLOYMENT:
            release = PostgresCodeChangeDecisionStore._deployment_source(
                cursor, scope=scope, request_id=str(request["id"]), now=now
            )
            return deployment_decision_material(
                request=request, release=release, expires_at=expires_at
            )
        if stage is CodeChangeDecisionStage.ROLLBACK:
            rollback = PostgresCodeChangeDecisionStore._rollback_source(
                cursor, scope=scope, request_id=str(request["id"]), now=now
            )
            return rollback_decision_material(
                request=request, rollback=rollback, expires_at=expires_at
            )
        raise CodeChangeDecisionConflict("stage material is not yet available")

    @staticmethod
    def _rollback_source(
        cursor: Any, *, scope: Scope, request_id: str, now: datetime
    ) -> Mapping[str, object]:
        cursor.execute(
            """SELECT rollout.id AS deployment_rollout_id,rollout.release_candidate_id,
                      rollout.target_key,rollout.release_target_profile_id,
                      rollout.release_target_profile_hash,rollout.target_reservation_id,
                      rollout.rollback_release_candidate_id,
                      observation.current_revision AS rollback_revision,
                      rollout.rollback_assignment_hash,receipt.result,
                      receipt.stage_ordinal,receipt.receipt_envelope_hash,
                      receipt.observed_target_version,receipt.observed_assignment_hash,
                      receipt.observed_at
                 FROM solvan_delivery.code_change_requests request
                 JOIN solvan_delivery.release_candidates candidate
                   ON candidate.organization_id=request.organization_id
                  AND candidate.project_id=request.project_id
                  AND candidate.environment_id=request.environment_id
                  AND candidate.code_change_request_id=request.id
                 JOIN solvan_delivery.deployment_rollouts rollout
                   ON rollout.organization_id=request.organization_id
                  AND rollout.project_id=request.project_id
                  AND rollout.environment_id=request.environment_id
                  AND rollout.release_candidate_id=candidate.id
                  AND rollout.status='VERIFICATION_FAILED'
                 JOIN solvan_delivery.release_target_observations observation
                   ON observation.organization_id=rollout.organization_id
                  AND observation.project_id=rollout.project_id
                  AND observation.environment_id=rollout.environment_id
                  AND observation.observation_hash=rollout.predeploy_snapshot_hash
                 JOIN LATERAL (
                   SELECT item.* FROM solvan_delivery.release_verification_receipts item
                    WHERE item.organization_id=rollout.organization_id
                      AND item.project_id=rollout.project_id
                      AND item.environment_id=rollout.environment_id
                      AND item.deployment_rollout_id=rollout.id
                    ORDER BY item.stage_ordinal DESC,
                             item.observation_window_generation DESC LIMIT 1
                 ) receipt ON receipt.result IN ('FAILED','INCONCLUSIVE')
                                AND receipt.observed_at>%(fresh_after)s
                WHERE request.organization_id=%(organization_id)s
                  AND request.project_id=%(project_id)s
                  AND request.environment_id=%(environment_id)s
                  AND request.id=%(request_id)s
                FOR SHARE OF rollout,observation,receipt""",
            {
                **scope.canonical_dict(),
                "request_id": request_id,
                "fresh_after": now - timedelta(minutes=10),
            },
        )
        row = cursor.fetchone()
        if row is None:
            raise CodeChangeDecisionConflict(
                "fresh failed verification and exact rollback lineage are required"
            )
        return cast("Mapping[str, object]", row)

    @staticmethod
    def _merge_source(
        cursor: Any, *, scope: Scope, request_id: str, principal: str, now: datetime
    ) -> Mapping[str, object]:
        cursor.execute(
            """SELECT observation.sequence_no AS observation_sequence_no,
                      observation.pull_request_number,observation.pull_request_url,
                      observation.base_commit_sha,observation.head_commit_sha,
                      observation.head_tree_hash,observation.diff_hash,
                      observation.required_check_state,observation.required_checks_hash,
                      observation.branch_rule_hash,observation.review_state,
                      observation.review_state_hash,
                      observation.required_check_definitions_hash,
                      observation.observation_hash,observation.observed_at,
                      binding.id AS github_reviewer_binding_id,
                      binding.github_account_node_id,binding.binding_proof_hash,
                      binding.expires_at AS binding_expires_at
                 FROM solvan_delivery.code_change_github_observations observation
                 JOIN solvan_delivery.code_change_requests request
                   ON (request.organization_id,request.project_id,
                       request.environment_id,request.id)=
                      (observation.organization_id,observation.project_id,
                       observation.environment_id,observation.code_change_request_id)
                 JOIN solvan_delivery.github_reviewer_bindings binding
                   ON binding.organization_id=request.organization_id
                  AND binding.project_id=request.project_id
                  AND binding.environment_id=request.environment_id
                  AND binding.repository_binding_id=request.repository_binding_id
                  AND binding.solvan_principal=%(principal)s
                  AND binding.github_account_node_id=
                    ANY(observation.approved_account_node_ids)
                WHERE observation.organization_id=%(organization_id)s
                  AND observation.project_id=%(project_id)s
                  AND observation.environment_id=%(environment_id)s
                  AND observation.code_change_request_id=%(request_id)s
                  AND observation.observation_kind='PR_SYNC'
                  AND observation.required_check_state='PASSING'
                  AND observation.review_state='APPROVED'
                  AND observation.repository_policy_hash=request.repository_policy_hash
                  AND observation.required_check_definitions_hash=
                    request.base_required_check_definitions_hash
                  AND observation.observed_at>%(fresh_after)s
                  AND binding.status='ACTIVE' AND binding.expires_at>%(now)s
                  AND binding.reviewer_policy_hash=request.reviewer_policy_hash
                  AND NOT EXISTS (
                    SELECT 1 FROM solvan_delivery.code_change_github_observations newer
                     WHERE newer.organization_id=observation.organization_id
                       AND newer.project_id=observation.project_id
                       AND newer.environment_id=observation.environment_id
                       AND newer.code_change_request_id=observation.code_change_request_id
                       AND newer.sequence_no>observation.sequence_no)
                FOR SHARE OF observation,binding""",
            {
                **scope.canonical_dict(),
                "request_id": request_id,
                "principal": principal,
                "now": now,
                "fresh_after": now - timedelta(minutes=5),
            },
        )
        row = cursor.fetchone()
        if row is None:
            raise CodeChangeDecisionConflict(
                "fresh passing GitHub state and the approver's active reviewer link are required"
            )
        return cast("Mapping[str, object]", row)

    @staticmethod
    def _deployment_source(
        cursor: Any, *, scope: Scope, request_id: str, now: datetime
    ) -> Mapping[str, object]:
        cursor.execute(
            """SELECT candidate.id AS release_candidate_id,candidate.merged_commit_sha,
                      candidate.source_tree_hash,candidate.build_artifact_ref,
                      candidate.build_artifact_hash,candidate.provenance_hash,
                      candidate.release_signature_hash,candidate.signer_identity,
                      candidate.signer_key_version,candidate.deployment_manifest_hash,
                      target.id AS release_target_profile_id,
                      target.profile_hash AS release_target_profile_hash,target.target_key,
                      target.service_resource_name,target.rollout_policy_hash,
                      target.verification_profile_id,target.verification_profile_version,
                      target.verification_profile_hash,observation.target_version,
                      observation.target_epoch,observation.service_generation,
                      observation.service_etag_hash,observation.current_release_candidate_id,
                      observation.current_revision,observation.assignment_hash,
                      observation.observation_hash,observation.observed_at,
                      baseline.id AS release_health_baseline_id,
                      baseline.baseline_ref AS release_health_baseline_ref,
                      baseline.baseline_hash AS release_health_baseline_hash
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
                  AND delivery.id=request.code_delivery_profile_id AND delivery.status='ACTIVE'
                 JOIN solvan_delivery.release_target_profiles target
                   ON target.organization_id=delivery.organization_id
                  AND target.project_id=delivery.project_id
                  AND target.environment_id=delivery.environment_id
                  AND target.id=delivery.release_target_profile_id
                  AND target.profile_hash=delivery.release_target_profile_hash
                  AND target.status='ACTIVE'
                 JOIN LATERAL (
                   SELECT * FROM solvan_delivery.release_target_observations item
                    WHERE item.organization_id=request.organization_id
                      AND item.project_id=request.project_id
                      AND item.environment_id=request.environment_id
                      AND item.code_change_request_id=request.id
                      AND item.release_candidate_id=candidate.id
                      AND item.release_target_profile_id=target.id
                    ORDER BY item.observed_at DESC,item.id DESC LIMIT 1
                 ) observation ON observation.observed_at>%(fresh_after)s
                 JOIN LATERAL (
                   SELECT * FROM solvan_delivery.release_health_baselines item
                    WHERE item.organization_id=request.organization_id
                      AND item.project_id=request.project_id
                      AND item.environment_id=request.environment_id
                      AND item.code_change_request_id=request.id
                      AND item.release_candidate_id=candidate.id
                      AND item.release_target_profile_id=target.id
                      AND item.target_observation_hash=observation.observation_hash
                      AND item.verification_profile_hash=target.verification_profile_hash
                    ORDER BY item.observed_at DESC,item.id DESC LIMIT 1
                 ) baseline ON baseline.observed_at>%(baseline_fresh_after)s
                WHERE request.organization_id=%(organization_id)s
                  AND request.project_id=%(project_id)s
                  AND request.environment_id=%(environment_id)s AND request.id=%(request_id)s
                FOR SHARE OF candidate,delivery,target,observation""",
            {
                **scope.canonical_dict(),
                "request_id": request_id,
                "fresh_after": now - timedelta(minutes=5),
                "baseline_fresh_after": now - timedelta(minutes=15),
            },
        )
        row = cursor.fetchone()
        if row is None:
            raise CodeChangeDecisionConflict(
                "fresh release target observation and active target profile are required"
            )
        return cast("Mapping[str, object]", row)

    @staticmethod
    def _request(cursor: Any, *, scope: Scope, request_id: str, lock: bool) -> Mapping[str, object]:
        cursor.execute(
            """SELECT * FROM solvan_delivery.code_change_requests
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(request_id)s"""
            + (" FOR UPDATE" if lock else ""),
            {**scope.canonical_dict(), "request_id": request_id},
        )
        row = cursor.fetchone()
        if row is None:
            raise CodeChangeDecisionConflict("code-change request does not exist")
        return cast("Mapping[str, object]", row)

    @staticmethod
    def _authorization_snapshot(
        cursor: Any, *, scope: Scope, principal: str, role: str, now: datetime
    ) -> Mapping[str, object]:
        cursor.execute(
            """SELECT role,granted_by,granted_at,expires_at
                 FROM solvan.actor_role_bindings
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND principal=%(principal)s
                  AND role=%(role)s AND (expires_at IS NULL OR expires_at>%(now)s)
                FOR SHARE""",
            {**scope.canonical_dict(), "principal": principal, "role": role, "now": now},
        )
        row = cursor.fetchone()
        if row is None:
            raise CodeChangeDecisionConflict(f"current {role} role is required")
        return {
            "schema_version": 1,
            "scope": scope.canonical_dict(),
            "principal": principal,
            "role": str(row["role"]),
            "granted_by": str(row["granted_by"]),
            "granted_at": _datetime(row["granted_at"]).isoformat(),
            "expires_at": (_datetime(row["expires_at"]).isoformat() if row["expires_at"] else None),
        }

    @staticmethod
    def _challenge(row: Mapping[str, object]) -> DecisionChallenge:
        return DecisionChallenge(
            challenge_id=str(row["id"]),
            decision_digest=str(row["decision_digest"]),
            stage=CodeChangeDecisionStage(str(row["stage"])),
            required_role=required_role(CodeChangeDecisionStage(str(row["stage"]))),
            material_ref=str(row["material_ref"]),
            expires_at=_datetime(row["expires_at"]),
        )

    @staticmethod
    def _decision_replay(
        row: Mapping[str, object],
        *,
        principal: str,
        expected_digest: str,
        decision: CodeChangeDecisionValue,
    ) -> RecordedDecision:
        if (
            row["principal"] != principal
            or row["decision_digest"] != expected_digest
            or row["decision"] != decision.value
        ):
            raise CodeChangeDecisionConflict("decision request replay differs")
        return RecordedDecision(
            str(row["id"]),
            str(row["decision_digest"]),
            decision,
            _datetime(row["expires_at"]),
            False,
        )


def _datetime(value: object) -> datetime:
    if not isinstance(value, datetime):
        raise CodeChangeDecisionConflict("decision timestamp is malformed")
    _aware(value)
    return value


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CodeChangeDecisionConflict("decision timestamp must include a timezone")
