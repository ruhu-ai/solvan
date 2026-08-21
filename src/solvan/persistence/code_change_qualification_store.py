"""Cloud SQL authority for provider-qualified Code Change Request material."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier


class QualificationConflict(ValueError):
    """Qualification material is stale, mismatched, or already differs."""


class EvidenceReceipt(Protocol):
    @property
    def uri(self) -> str: ...

    @property
    def content_hash(self) -> str: ...


@dataclass(frozen=True, slots=True)
class QualificationIntent:
    intent_id: str
    request_hash: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class PendingQualification:
    patch_artifact_id: str
    requested_by_principal: str


@dataclass(frozen=True, slots=True)
class PatchAdjudicationMaterial:
    candidate_generation_id: str
    base_tree_hash: str
    candidate_tree_hash: str
    command_definitions_hash: str
    sandbox_resource: str
    sandbox_image_hash: str
    reproduction_exit_code: int
    test_exit_code: int
    coordinator_service_revision: str


@dataclass(frozen=True, slots=True)
class QualificationMaterial:
    intent_id: str
    reliability_case_id: str
    patch_artifact_id: str
    candidate_generation_id: str
    candidate_manifest_ref: str
    candidate_manifest_hash: str
    candidate_tree_hash: str
    curated_base_tree_hash: str
    expected_base_commit_sha: str
    repository_snapshot_ref: str
    repository_snapshot_hash: str
    repair_allowed_paths: tuple[str, ...]
    repository_binding_id: str
    installation_id: int
    owner: str
    name: str
    configured_default_branch: str
    repository_policy_hash: str
    code_delivery_profile_id: str
    code_delivery_profile_hash: str
    delivery_allowed_paths: tuple[str, ...]
    required_check_definition_paths: tuple[str, ...]
    adjudication_receipt_ref: str
    adjudication_receipt_hash: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class QualifiedRepositoryReceipt:
    outcome: str
    reason_code: str
    repository_binding_id: str
    repository_policy_hash: str
    code_delivery_profile_id: str
    code_delivery_profile_hash: str
    default_branch: str | None
    base_commit_sha: str | None
    base_tree_ref: str | None
    base_tree_hash: str | None
    patch_transform_version: str | None
    patch_transform_ref: str | None
    patch_transform_hash: str | None
    proposed_tree_hash: str | None
    base_required_check_definitions_ref: str | None
    base_required_check_definitions_hash: str | None
    attributes_evaluation_ref: str | None
    attributes_evaluation_hash: str | None
    provider_observation_ref: str
    provider_observation_hash: str
    provider_service_revision: str
    observed_at: datetime


class PostgresCodeChangeQualificationStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def pending_approved_patches(
        self, *, scope: Scope, limit: int = 20
    ) -> tuple[PendingQualification, ...]:
        """Find approved, independently adjudicated patches lacking an intent."""

        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT pa.id,review.reviewer_principal
                     FROM solvan.patch_artifacts pa
                     JOIN solvan.patch_reviews review
                       ON (review.organization_id,review.project_id,review.environment_id,
                           review.patch_artifact_id)=
                          (pa.organization_id,pa.project_id,pa.environment_id,pa.id)
                     JOIN solvan_delivery.patch_adjudication_receipts adjudication
                       ON (adjudication.organization_id,adjudication.project_id,
                           adjudication.environment_id,adjudication.patch_artifact_id)=
                          (pa.organization_id,pa.project_id,pa.environment_id,pa.id)
                     LEFT JOIN solvan_delivery.code_change_qualification_intents intent
                       ON (intent.organization_id,intent.project_id,intent.environment_id,
                           intent.patch_artifact_id)=
                          (pa.organization_id,pa.project_id,pa.environment_id,pa.id)
                    WHERE pa.organization_id=%(organization_id)s
                      AND pa.project_id=%(project_id)s AND pa.environment_id=%(environment_id)s
                      AND pa.status='TESTS_PASSED' AND review.decision='APPROVE'
                      AND review.applied_at IS NOT NULL AND intent.id IS NULL
                    ORDER BY review.applied_at,review.id LIMIT %(limit)s""",
                {**scope.canonical_dict(), "limit": limit},
            )
            return tuple(
                PendingQualification(str(row[0]), str(row[1])) for row in cursor.fetchall()
            )

    def dispatchable_intents(
        self, *, scope: Scope, limit: int = 20
    ) -> tuple[QualificationIntent, ...]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT intent.id,intent.request_hash,intent.expires_at
                     FROM solvan_delivery.code_change_qualification_intents intent
                     LEFT JOIN solvan_delivery.code_change_qualification_receipts receipt
                       ON (receipt.organization_id,receipt.project_id,receipt.environment_id,
                           receipt.qualification_intent_id)=
                          (intent.organization_id,intent.project_id,intent.environment_id,intent.id)
                    WHERE intent.organization_id=%(organization_id)s
                      AND intent.project_id=%(project_id)s
                      AND intent.environment_id=%(environment_id)s
                      AND intent.expires_at>now() AND receipt.id IS NULL
                    ORDER BY intent.created_at,intent.id LIMIT %(limit)s""",
                {**scope.canonical_dict(), "limit": limit},
            )
            return tuple(
                QualificationIntent(str(row[0]), str(row[1]), row[2]) for row in cursor.fetchall()
            )

    def create_qualified_requests(
        self, *, scope: Scope, coordinator_identity: str, limit: int = 20
    ) -> tuple[str, ...]:
        """Create CCR roots and open their first approval stage atomically."""

        created: list[str] = []
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT i.*,q.id AS qualification_receipt_id,q.repository_policy_hash,
                          q.default_branch,q.base_commit_sha,q.base_tree_hash,
                          q.patch_transform_version,q.patch_transform_ref,q.patch_transform_hash,
                          q.proposed_tree_hash,q.base_required_check_definitions_ref,
                          q.base_required_check_definitions_hash,
                          review.patch_digest,
                          review.reviewer_principal,
                          d.profile_hash AS code_delivery_profile_hash,
                          d.allowed_paths_hash,d.required_checks_policy_ref,
                          d.required_checks_policy_hash,d.required_check_definition_paths_hash,
                          d.reviewer_policy_ref,d.reviewer_policy_hash,
                          d.pr_creation_policy_ref,d.pr_creation_policy_hash,
                          d.merge_policy_ref,d.merge_policy_hash,
                          d.deployment_policy_ref,d.deployment_policy_hash
                     FROM solvan_delivery.code_change_qualification_receipts q
                     JOIN solvan_delivery.code_change_qualification_intents i
                       ON (i.organization_id,i.project_id,i.environment_id,i.id)=
                          (q.organization_id,q.project_id,q.environment_id,
                           q.qualification_intent_id)
                     JOIN solvan.patch_artifacts p
                       ON (p.organization_id,p.project_id,p.environment_id,p.id)=
                          (i.organization_id,i.project_id,i.environment_id,i.patch_artifact_id)
                     JOIN solvan.patch_reviews review
                       ON (review.organization_id,review.project_id,review.environment_id,
                           review.patch_artifact_id)=
                          (p.organization_id,p.project_id,p.environment_id,p.id)
                      AND review.decision='APPROVE' AND review.applied_at IS NOT NULL
                     JOIN solvan_delivery.code_delivery_profiles d
                       ON (d.organization_id,d.project_id,d.environment_id,d.id)=
                          (i.organization_id,i.project_id,i.environment_id,
                           i.code_delivery_profile_id)
                     LEFT JOIN solvan_delivery.code_change_requests request
                       ON (request.organization_id,request.project_id,request.environment_id,
                           request.qualification_receipt_id)=
                          (q.organization_id,q.project_id,q.environment_id,q.id)
                    WHERE q.organization_id=%(organization_id)s
                      AND q.project_id=%(project_id)s AND q.environment_id=%(environment_id)s
                      AND q.outcome='QUALIFIED' AND i.expires_at>now()
                      AND d.status='ACTIVE' AND request.id IS NULL
                    ORDER BY q.observed_at,q.id LIMIT %(limit)s
                    FOR UPDATE OF q,d""",
                {**scope.canonical_dict(), "limit": limit},
            )
            rows = cursor.fetchall()
            for row in rows:
                request_id = new_identifier("ccr")
                immutable_material = {
                    "qualification_receipt_id": str(row["qualification_receipt_id"]),
                    "patch_artifact_id": str(row["patch_artifact_id"]),
                    "patch_digest": str(row["patch_digest"]),
                    "repository_binding_id": str(row["repository_binding_id"]),
                    "repository_policy_hash": str(row["repository_policy_hash"]),
                    "base_commit_sha": str(row["base_commit_sha"]),
                    "base_tree_hash": str(row["base_tree_hash"]),
                    "proposed_tree_hash": str(row["proposed_tree_hash"]),
                    "patch_transform_hash": str(row["patch_transform_hash"]),
                    "code_delivery_profile_id": str(row["code_delivery_profile_id"]),
                    "code_delivery_profile_hash": str(row["code_delivery_profile_hash"]),
                    "allowed_paths_hash": str(row["allowed_paths_hash"]),
                    "adjudication_receipt_ref": str(row["adjudication_receipt_ref"]),
                    "adjudication_receipt_hash": str(row["adjudication_receipt_hash"]),
                    "required_checks_policy_ref": str(row["required_checks_policy_ref"]),
                    "required_checks_policy_hash": str(row["required_checks_policy_hash"]),
                    "required_check_definition_paths_hash": str(
                        row["required_check_definition_paths_hash"]
                    ),
                    "base_required_check_definitions_ref": str(
                        row["base_required_check_definitions_ref"]
                    ),
                    "base_required_check_definitions_hash": str(
                        row["base_required_check_definitions_hash"]
                    ),
                    "reviewer_policy_ref": str(row["reviewer_policy_ref"]),
                    "reviewer_policy_hash": str(row["reviewer_policy_hash"]),
                    "pr_creation_policy_ref": str(row["pr_creation_policy_ref"]),
                    "pr_creation_policy_hash": str(row["pr_creation_policy_hash"]),
                    "merge_policy_ref": str(row["merge_policy_ref"]),
                    "merge_policy_hash": str(row["merge_policy_hash"]),
                    "deployment_policy_ref": str(row["deployment_policy_ref"]),
                    "deployment_policy_hash": str(row["deployment_policy_hash"]),
                    "expires_at": row["expires_at"].isoformat(),
                    "requested_by_principal": str(row["requested_by_principal"]),
                }
                cursor.execute(
                    """INSERT INTO solvan_delivery.code_change_requests
                        (organization_id,project_id,environment_id,id,
                         qualification_receipt_id,code_delivery_profile_id,
                         reliability_case_id,patch_artifact_id,patch_digest,
                         patch_transform_version,patch_transform_ref,patch_transform_hash,
                         proposed_tree_hash,repository_binding_id,repository_policy_hash,
                         default_branch,base_commit_sha,base_tree_hash,allowed_paths_hash,
                         adjudication_receipt_ref,adjudication_receipt_hash,
                         required_checks_policy_ref,required_checks_policy_hash,
                         required_check_definition_paths_hash,
                         base_required_check_definitions_ref,
                         base_required_check_definitions_hash,reviewer_policy_ref,
                         reviewer_policy_hash,pr_creation_policy_ref,pr_creation_policy_hash,
                         merge_policy_ref,merge_policy_hash,deployment_policy_ref,
                         deployment_policy_hash,immutable_request_hash,state,sequence_no,
                         expires_at,created_by_principal)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                         %(qualification_receipt_id)s,%(code_delivery_profile_id)s,
                         %(reliability_case_id)s,%(patch_artifact_id)s,%(patch_digest)s,
                         %(patch_transform_version)s,%(patch_transform_ref)s,
                         %(patch_transform_hash)s,%(proposed_tree_hash)s,
                         %(repository_binding_id)s,%(repository_policy_hash)s,
                         %(default_branch)s,%(base_commit_sha)s,%(base_tree_hash)s,
                         %(allowed_paths_hash)s,%(adjudication_receipt_ref)s,
                         %(adjudication_receipt_hash)s,%(required_checks_policy_ref)s,
                         %(required_checks_policy_hash)s,
                         %(required_check_definition_paths_hash)s,
                         %(base_required_check_definitions_ref)s,
                         %(base_required_check_definitions_hash)s,%(reviewer_policy_ref)s,
                         %(reviewer_policy_hash)s,%(pr_creation_policy_ref)s,
                         %(pr_creation_policy_hash)s,%(merge_policy_ref)s,%(merge_policy_hash)s,
                         %(deployment_policy_ref)s,%(deployment_policy_hash)s,
                         %(immutable_request_hash)s,'PATCH_VALIDATED',0,%(expires_at)s,
                         %(requested_by_principal)s)""",
                    {
                        **scope.canonical_dict(),
                        **dict(row),
                        "id": request_id,
                        "immutable_request_hash": canonical_sha256(immutable_material),
                    },
                )
                transition_material = {
                    "schema_version": 1,
                    "code_change_request_id": request_id,
                    "immutable_request_hash": canonical_sha256(immutable_material),
                    "from_state": "PATCH_VALIDATED",
                    "to_state": "PR_CREATION_APPROVAL_PENDING",
                    "expected_sequence_no": 0,
                }
                cursor.execute(
                    """INSERT INTO solvan_delivery.code_change_transitions
                        (organization_id,project_id,environment_id,id,
                         code_change_request_id,sequence_no,from_state,to_state,
                         expected_sequence_no,input_hash,idempotency_key,
                         actor_kind,actor_identity)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                         %(transition_id)s,%(request_id)s,1,'PATCH_VALIDATED',
                         'PR_CREATION_APPROVAL_PENDING',0,%(input_hash)s,
                         %(idempotency_key)s,'COORDINATOR',%(actor_identity)s)""",
                    {
                        **scope.canonical_dict(),
                        "transition_id": new_identifier("cct"),
                        "request_id": request_id,
                        "input_hash": canonical_sha256(transition_material),
                        "idempotency_key": f"open-pr-creation-approval:{request_id}",
                        "actor_identity": coordinator_identity,
                    },
                )
                created.append(request_id)
        return tuple(created)

    def prepare_intent(
        self,
        *,
        scope: Scope,
        patch_artifact_id: str,
        requested_by_principal: str,
        now: datetime,
    ) -> QualificationIntent:
        """Freeze the current candidate and active profile after patch review."""

        if now.tzinfo is None or now.utcoffset() is None:
            raise QualificationConflict("qualification time must be timezone-aware")
        with (
            self._connection.transaction(),
            self._connection.cursor(row_factory=dict_row) as cursor,
        ):
            cursor.execute(
                """SELECT pa.reliability_case_id,pa.agent_run_id,pa.base_commit_sha,
                          pa.status AS patch_status,pn.attributes_json,
                          g.id AS generation_id,g.candidate_manifest_ref,
                          g.candidate_manifest_hash,g.candidate_tree_hash,
                          d.id AS profile_id,d.profile_hash,d.profile_version,
                          d.maximum_request_lifetime_minutes,
                          d.repository_binding_id,d.status AS profile_status,
                          d.deployment_policy_ref,
                          r.policy_hash AS repository_policy_hash,
                          a.id AS adjudication_receipt_id,
                          a.receipt_ref AS adjudication_receipt_ref,
                          a.receipt_hash AS adjudication_receipt_hash
                     FROM solvan.patch_artifacts pa
                     JOIN solvan.repair_plans rp
                       ON (rp.organization_id,rp.project_id,rp.environment_id,rp.id)=
                          (pa.organization_id,pa.project_id,pa.environment_id,pa.repair_plan_id)
                     JOIN solvan.production_graph_nodes pn
                       ON (pn.organization_id,pn.project_id,pn.environment_id,pn.id)=
                          (rp.organization_id,rp.project_id,rp.environment_id,rp.repository_node_id)
                     JOIN LATERAL (
                       SELECT candidate.id,candidate.candidate_manifest_ref,
                              candidate.candidate_manifest_hash,candidate.candidate_tree_hash
                         FROM solvan_delivery.workspace_candidate_generations candidate
                        WHERE candidate.organization_id=pa.organization_id
                          AND candidate.project_id=pa.project_id
                          AND candidate.environment_id=pa.environment_id
                          AND candidate.agent_run_id=pa.agent_run_id
                        ORDER BY candidate.generation_ordinal DESC LIMIT 1
                     ) g ON true
                     JOIN solvan_delivery.code_delivery_profiles d
                       ON d.organization_id=pa.organization_id
                      AND d.project_id=pa.project_id
                      AND d.environment_id=pa.environment_id
                      AND d.repository_binding_id=pn.attributes_json->>'repository_binding_id'
                      AND d.status='ACTIVE'
                     JOIN solvan_delivery.patch_adjudication_receipts a
                       ON (a.organization_id,a.project_id,a.environment_id,
                           a.patch_artifact_id,a.candidate_generation_id)=
                          (pa.organization_id,pa.project_id,pa.environment_id,pa.id,g.id)
                     JOIN solvan.github_repositories r
                       ON (r.organization_id,r.project_id,r.environment_id,r.id)=
                          (d.organization_id,d.project_id,d.environment_id,
                           d.repository_binding_id)
                      AND r.status='ACTIVE'
                    WHERE pa.organization_id=%(organization_id)s
                      AND pa.project_id=%(project_id)s
                      AND pa.environment_id=%(environment_id)s
                      AND pa.id=%(patch_artifact_id)s
                    FOR UPDATE OF pa,d""",
                {**scope.canonical_dict(), "patch_artifact_id": patch_artifact_id},
            )
            source = cursor.fetchone()
            if source is None or source["patch_status"] != "TESTS_PASSED":
                raise QualificationConflict("patch is not eligible for code-change qualification")
            attributes = source["attributes_json"]
            if (
                not isinstance(attributes, dict)
                or attributes.get("repository_binding_id") != source["repository_binding_id"]
                or source["profile_status"] != "ACTIVE"
            ):
                raise QualificationConflict("active repository delivery profile is unavailable")
            lifetime = int(source["maximum_request_lifetime_minutes"])
            expires_at = now.astimezone(UTC) + timedelta(minutes=lifetime)
            request_material = {
                "schema_version": 1,
                "reliability_case_id": str(source["reliability_case_id"]),
                "patch_artifact_id": patch_artifact_id,
                "candidate_generation_id": str(source["generation_id"]),
                "candidate_manifest_hash": str(source["candidate_manifest_hash"]),
                "candidate_tree_hash": str(source["candidate_tree_hash"]),
                "code_delivery_profile_id": str(source["profile_id"]),
                "code_delivery_profile_hash": str(source["profile_hash"]),
                "repository_binding_id": str(source["repository_binding_id"]),
                "repository_policy_hash": str(source["repository_policy_hash"]),
                "adjudication_receipt_hash": str(source["adjudication_receipt_hash"]),
                "requested_by_principal": requested_by_principal,
                "expires_at": expires_at.isoformat(),
            }
            request_hash = canonical_sha256(request_material)
            cursor.execute(
                """SELECT id,request_hash,expires_at
                     FROM solvan_delivery.code_change_qualification_intents
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND candidate_generation_id=%(generation_id)s
                      AND code_delivery_profile_id=%(profile_id)s""",
                {
                    **scope.canonical_dict(),
                    "generation_id": source["generation_id"],
                    "profile_id": source["profile_id"],
                },
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing["request_hash"] != request_hash:
                    raise QualificationConflict("qualification intent replay material differs")
                return QualificationIntent(
                    str(existing["id"]), str(existing["request_hash"]), existing["expires_at"]
                )
            intent_id = new_identifier("cqi")
            cursor.execute(
                """INSERT INTO solvan_delivery.code_change_qualification_intents
                    (organization_id,project_id,environment_id,id,reliability_case_id,
                     patch_artifact_id,candidate_generation_id,code_delivery_profile_id,
                     repository_binding_id,repository_policy_hash,adjudication_receipt_id,
                     adjudication_receipt_ref,
                     adjudication_receipt_hash,request_hash,requested_by_principal,expires_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                     %(reliability_case_id)s,%(patch_artifact_id)s,%(generation_id)s,
                     %(profile_id)s,%(repository_binding_id)s,%(repository_policy_hash)s,
                     %(adjudication_receipt_id)s,
                     %(adjudication_ref)s,
                     %(adjudication_hash)s,%(request_hash)s,%(principal)s,%(expires_at)s)""",
                {
                    **scope.canonical_dict(),
                    "id": intent_id,
                    "reliability_case_id": source["reliability_case_id"],
                    "patch_artifact_id": patch_artifact_id,
                    "generation_id": source["generation_id"],
                    "profile_id": source["profile_id"],
                    "repository_binding_id": source["repository_binding_id"],
                    "repository_policy_hash": source["repository_policy_hash"],
                    "adjudication_receipt_id": source["adjudication_receipt_id"],
                    "adjudication_ref": source["adjudication_receipt_ref"],
                    "adjudication_hash": source["adjudication_receipt_hash"],
                    "request_hash": request_hash,
                    "principal": requested_by_principal,
                    "expires_at": expires_at,
                },
            )
            return QualificationIntent(intent_id, request_hash, expires_at)

    def record_patch_adjudication(
        self,
        *,
        scope: Scope,
        patch_artifact_id: str,
        material: PatchAdjudicationMaterial,
        receipt: EvidenceReceipt,
    ) -> str:
        """Bind one independent sandbox result to one persisted patch artifact."""

        values = {
            **scope.canonical_dict(),
            "id": new_identifier("adr"),
            "patch_artifact_id": patch_artifact_id,
            "candidate_generation_id": material.candidate_generation_id,
            "base_tree_hash": material.base_tree_hash,
            "candidate_tree_hash": material.candidate_tree_hash,
            "command_definitions_hash": material.command_definitions_hash,
            "sandbox_resource": material.sandbox_resource,
            "sandbox_image_hash": material.sandbox_image_hash,
            "reproduction_exit_code": material.reproduction_exit_code,
            "test_exit_code": material.test_exit_code,
            "receipt_ref": receipt.uri,
            "receipt_hash": receipt.content_hash,
            "coordinator_service_revision": material.coordinator_service_revision,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """INSERT INTO solvan_delivery.patch_adjudication_receipts
                    (organization_id,project_id,environment_id,id,patch_artifact_id,
                     candidate_generation_id,base_tree_hash,candidate_tree_hash,
                     command_definitions_hash,sandbox_resource,sandbox_image_hash,
                     reproduction_exit_code,test_exit_code,receipt_ref,receipt_hash,
                     coordinator_service_revision)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                     %(patch_artifact_id)s,%(candidate_generation_id)s,%(base_tree_hash)s,
                     %(candidate_tree_hash)s,%(command_definitions_hash)s,
                     %(sandbox_resource)s,%(sandbox_image_hash)s,%(reproduction_exit_code)s,
                     %(test_exit_code)s,%(receipt_ref)s,%(receipt_hash)s,
                     %(coordinator_service_revision)s)
                   ON CONFLICT DO NOTHING""",
                values,
            )
            if cursor.rowcount == 1:
                return str(values["id"])
            cursor.execute(
                """SELECT * FROM solvan_delivery.patch_adjudication_receipts
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND patch_artifact_id=%(patch_artifact_id)s""",
                values,
            )
            existing = cursor.fetchone()
        compare = tuple(
            key
            for key in values
            if key not in {"id", "organization_id", "project_id", "environment_id"}
        )
        if existing is None or any(existing[key] != values[key] for key in compare):
            raise QualificationConflict("patch adjudication receipt replay material differs")
        return str(existing["id"])

    def load_material(
        self, *, scope: Scope, intent_id: str, now: datetime
    ) -> QualificationMaterial:
        """Load one unexpired exact intent for the GitHub Provider."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT i.id,i.reliability_case_id,i.patch_artifact_id,
                          i.candidate_generation_id,i.repository_binding_id,
                          i.code_delivery_profile_id,i.adjudication_receipt_ref,
                          i.adjudication_receipt_hash,i.expires_at,
                          g.candidate_manifest_ref,g.candidate_manifest_hash,
                          g.candidate_tree_hash,g.base_tree_hash AS curated_base_tree_hash,
                          rp.repository_snapshot_uri,rp.repository_snapshot_hash,
                          rp.base_commit_sha AS expected_base_commit_sha,
                          rp.allowed_file_globs_json,
                          r.installation_id,r.owner,r.name,r.default_branch,
                          r.policy_hash,r.status AS repository_status,
                          d.profile_hash,d.allowed_paths_json,
                          d.required_check_definition_paths_json,d.status AS profile_status
                     FROM solvan_delivery.code_change_qualification_intents i
                     JOIN solvan.patch_artifacts pa
                       ON (pa.organization_id,pa.project_id,pa.environment_id,pa.id)=
                          (i.organization_id,i.project_id,i.environment_id,i.patch_artifact_id)
                     JOIN solvan.repair_plans rp
                       ON (rp.organization_id,rp.project_id,rp.environment_id,rp.id)=
                          (pa.organization_id,pa.project_id,pa.environment_id,pa.repair_plan_id)
                     JOIN solvan_delivery.workspace_candidate_generations g
                       ON (g.organization_id,g.project_id,g.environment_id,g.id)=
                          (i.organization_id,i.project_id,i.environment_id,i.candidate_generation_id)
                     JOIN solvan.github_repositories r
                       ON (r.organization_id,r.project_id,r.environment_id,r.id)=
                          (i.organization_id,i.project_id,i.environment_id,i.repository_binding_id)
                      AND r.policy_hash=i.repository_policy_hash
                     JOIN solvan_delivery.code_delivery_profiles d
                       ON (d.organization_id,d.project_id,d.environment_id,d.id)=
                          (i.organization_id,i.project_id,i.environment_id,i.code_delivery_profile_id)
                    WHERE i.organization_id=%(organization_id)s
                      AND i.project_id=%(project_id)s AND i.environment_id=%(environment_id)s
                      AND i.id=%(intent_id)s""",
                {**scope.canonical_dict(), "intent_id": intent_id},
            )
            row = cursor.fetchone()
        if (
            row is None
            or row["repository_status"] != "ACTIVE"
            or row["profile_status"] != "ACTIVE"
            or row["expires_at"] <= now
        ):
            raise QualificationConflict("qualification intent is unavailable or expired")
        return QualificationMaterial(
            intent_id=str(row["id"]),
            reliability_case_id=str(row["reliability_case_id"]),
            patch_artifact_id=str(row["patch_artifact_id"]),
            candidate_generation_id=str(row["candidate_generation_id"]),
            candidate_manifest_ref=str(row["candidate_manifest_ref"]),
            candidate_manifest_hash=str(row["candidate_manifest_hash"]),
            candidate_tree_hash=str(row["candidate_tree_hash"]),
            curated_base_tree_hash=str(row["curated_base_tree_hash"]),
            expected_base_commit_sha=str(row["expected_base_commit_sha"]),
            repository_snapshot_ref=str(row["repository_snapshot_uri"]),
            repository_snapshot_hash=str(row["repository_snapshot_hash"]),
            repair_allowed_paths=_string_tuple(row["allowed_file_globs_json"]),
            repository_binding_id=str(row["repository_binding_id"]),
            installation_id=int(row["installation_id"]),
            owner=str(row["owner"]),
            name=str(row["name"]),
            configured_default_branch=str(row["default_branch"]),
            repository_policy_hash=str(row["policy_hash"]),
            code_delivery_profile_id=str(row["code_delivery_profile_id"]),
            code_delivery_profile_hash=str(row["profile_hash"]),
            delivery_allowed_paths=_string_tuple(row["allowed_paths_json"]),
            required_check_definition_paths=_string_tuple(
                row["required_check_definition_paths_json"]
            ),
            adjudication_receipt_ref=str(row["adjudication_receipt_ref"]),
            adjudication_receipt_hash=str(row["adjudication_receipt_hash"]),
            expires_at=row["expires_at"],
        )

    def record_receipt(
        self,
        *,
        scope: Scope,
        intent_id: str,
        receipt: QualifiedRepositoryReceipt,
    ) -> str:
        """Append one provider result; exact duplicates return the first ID."""

        values = {
            **scope.canonical_dict(),
            "id": new_identifier("cqr"),
            "intent_id": intent_id,
            "outcome": receipt.outcome,
            "reason_code": receipt.reason_code,
            "repository_binding_id": receipt.repository_binding_id,
            "repository_policy_hash": receipt.repository_policy_hash,
            "code_delivery_profile_id": receipt.code_delivery_profile_id,
            "code_delivery_profile_hash": receipt.code_delivery_profile_hash,
            "default_branch": receipt.default_branch,
            "base_commit_sha": receipt.base_commit_sha,
            "base_tree_ref": receipt.base_tree_ref,
            "base_tree_hash": receipt.base_tree_hash,
            "patch_transform_version": receipt.patch_transform_version,
            "patch_transform_ref": receipt.patch_transform_ref,
            "patch_transform_hash": receipt.patch_transform_hash,
            "proposed_tree_hash": receipt.proposed_tree_hash,
            "base_required_check_definitions_ref": receipt.base_required_check_definitions_ref,
            "base_required_check_definitions_hash": receipt.base_required_check_definitions_hash,
            "attributes_evaluation_ref": receipt.attributes_evaluation_ref,
            "attributes_evaluation_hash": receipt.attributes_evaluation_hash,
            "provider_observation_ref": receipt.provider_observation_ref,
            "provider_observation_hash": receipt.provider_observation_hash,
            "provider_service_revision": receipt.provider_service_revision,
            "observed_at": receipt.observed_at,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """INSERT INTO solvan_delivery.code_change_qualification_receipts
                    (organization_id,project_id,environment_id,id,qualification_intent_id,
                     outcome,reason_code,repository_binding_id,repository_policy_hash,
                     code_delivery_profile_id,
                     code_delivery_profile_hash,default_branch,base_commit_sha,base_tree_ref,
                     base_tree_hash,patch_transform_version,patch_transform_ref,
                     patch_transform_hash,proposed_tree_hash,
                     base_required_check_definitions_ref,
                     base_required_check_definitions_hash,attributes_evaluation_ref,
                     attributes_evaluation_hash,provider_observation_ref,
                     provider_observation_hash,provider_service_revision,observed_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                     %(intent_id)s,%(outcome)s,%(reason_code)s,%(repository_binding_id)s,
                     %(repository_policy_hash)s,
                     %(code_delivery_profile_id)s,%(code_delivery_profile_hash)s,
                     %(default_branch)s,%(base_commit_sha)s,%(base_tree_ref)s,%(base_tree_hash)s,
                     %(patch_transform_version)s,%(patch_transform_ref)s,
                     %(patch_transform_hash)s,%(proposed_tree_hash)s,
                     %(base_required_check_definitions_ref)s,
                     %(base_required_check_definitions_hash)s,%(attributes_evaluation_ref)s,
                     %(attributes_evaluation_hash)s,%(provider_observation_ref)s,
                     %(provider_observation_hash)s,%(provider_service_revision)s,%(observed_at)s)
                   ON CONFLICT DO NOTHING""",
                values,
            )
            if cursor.rowcount == 1:
                return str(values["id"])
            cursor.execute(
                """SELECT * FROM solvan_delivery.code_change_qualification_receipts
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND qualification_intent_id=%(intent_id)s""",
                values,
            )
            existing = cursor.fetchone()
        compare_columns = tuple(values.keys() - {"id", "intent_id", *scope.canonical_dict()})
        if existing is None or any(existing[name] != values[name] for name in compare_columns):
            raise QualificationConflict("qualification receipt replay material differs")
        return str(existing["id"])


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise QualificationConflict("qualification policy list is malformed")
    return tuple(value)
