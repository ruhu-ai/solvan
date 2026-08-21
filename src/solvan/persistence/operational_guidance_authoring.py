"""Immutable Operational Guidance authoring, ingestion, and evaluation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.operational_guidance import (
    GuidanceError,
    GuidanceLifecycle,
    GuidanceRevision,
)
from solvan.domain import Scope, new_identifier
from solvan.persistence.operational_guidance_base import OperationalGuidanceStoreBase
from solvan.persistence.operational_guidance_types import GuidanceLifecycleCommit


class OperationalGuidanceAuthoringMixin(OperationalGuidanceStoreBase):
    def create_draft(
        self, *, scope: Scope, revision: GuidanceRevision, decision_request_id: str
    ) -> GuidanceLifecycleCommit:
        """Persist one authorized immutable draft and its eligibility graph."""

        if revision.lifecycle is not GuidanceLifecycle.DRAFT:
            raise GuidanceError("new guidance must enter as a DRAFT")
        if revision.approval_ref or revision.approved_by_principal or revision.approved_at:
            raise GuidanceError("a draft cannot carry approval material")
        self._require_role(
            scope=scope,
            principal=revision.author_principal,
            roles=("GUIDANCE_AUTHOR", "OPERABILITY_ADMIN"),
            department=revision.owner_department,
        )

        params = scope.canonical_dict()
        with self._connection.cursor(row_factory=dict_row) as cursor:
            existing = self._audit_by_request(
                cursor=cursor, scope=scope, decision_request_id=decision_request_id
            )
            if existing is not None:
                self._require_same_audit(
                    existing=existing,
                    entity_ref=f"guidance:{revision.revision_ref}",
                    digest=revision.approval_digest,
                    principal=revision.author_principal,
                    event_type="GUIDANCE_DRAFT_CREATED",
                )
                return GuidanceLifecycleCommit(
                    revision.guidance_key,
                    revision.version,
                    "DRAFT",
                    revision.approval_digest,
                    None,
                    False,
                )
            cursor.execute(
                """INSERT INTO solvan_operability.guidance_definitions
                     (organization_id,project_id,environment_id,guidance_key,
                      display_name,owner_department)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(guidance_key)s,%(display_name)s,%(owner_department)s)
                   ON CONFLICT DO NOTHING""",
                {
                    **params,
                    "guidance_key": revision.guidance_key,
                    "display_name": revision.display_name,
                    "owner_department": revision.owner_department,
                },
            )
            cursor.execute(
                """SELECT display_name,owner_department
                     FROM solvan_operability.guidance_definitions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND guidance_key=%(guidance_key)s
                    FOR UPDATE""",
                {**params, "guidance_key": revision.guidance_key},
            )
            definition = cursor.fetchone()
            if definition is None or (
                definition["display_name"],
                definition["owner_department"],
            ) != (revision.display_name, revision.owner_department):
                raise GuidanceError("a guidance key already belongs to another definition")

            supersedes_version = None
            if revision.supersedes is not None:
                key, separator, version = revision.supersedes.partition("@")
                if separator != "@" or key != revision.guidance_key or not version:
                    raise GuidanceError("guidance may supersede only an exact revision of itself")
                supersedes_version = version
                cursor.execute(
                    """SELECT 1 FROM solvan_operability.guidance_revisions
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND guidance_key=%(guidance_key)s AND version=%(version)s""",
                    {
                        **params,
                        "guidance_key": revision.guidance_key,
                        "version": supersedes_version,
                    },
                )
                if cursor.fetchone() is None:
                    raise GuidanceError("LINEAGE_PREDECESSOR_NOT_FOUND")
            cursor.execute(
                """SELECT version FROM solvan_operability.guidance_revisions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND guidance_key=%(guidance_key)s
                      AND supersedes_version IS NOT DISTINCT FROM %(supersedes_version)s
                      AND version<>%(version)s
                    LIMIT 1""",
                {
                    **params,
                    "guidance_key": revision.guidance_key,
                    "version": revision.version,
                    "supersedes_version": supersedes_version,
                },
            )
            if cursor.fetchone() is not None:
                raise GuidanceError("LINEAGE_CONFLICT")
            cursor.execute(
                """INSERT INTO solvan_operability.guidance_revisions
                     (organization_id,project_id,environment_id,guidance_key,version,
                      description,discoverable_departments_json,guidance_kind,
                      applicable_service_kinds_json,applicable_incident_classes_json,
                      symptom_tags_json,purpose,classification,eligible_regions_json,
                      content_ref,content_hash,revision_hash,source_kind,source_ref,
                      source_license,evaluation_ref,approval_ref,approved_digest,
                      author_principal,approved_by_principal,supersedes_version,
                      lifecycle,approved_at)
                   VALUES
                     (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(guidance_key)s,%(version)s,%(description)s,%(departments)s,
                      %(guidance_kind)s,%(service_kinds)s,%(incident_classes)s,
                      %(symptom_tags)s,%(purpose)s,%(classification)s,%(regions)s,
                      %(content_ref)s,%(content_hash)s,%(revision_hash)s,%(source_kind)s,
                      %(source_ref)s,%(source_license)s,%(evaluation_ref)s,%(approval_ref)s,
                      %(approved_digest)s,%(author_principal)s,%(approved_by_principal)s,
                      %(supersedes_version)s,%(lifecycle)s,%(approved_at)s)
                   ON CONFLICT (organization_id,project_id,environment_id,
                                guidance_key,version) DO NOTHING""",
                {
                    **params,
                    "guidance_key": revision.guidance_key,
                    "version": revision.version,
                    "description": revision.description,
                    "departments": Jsonb(list(revision.discoverable_departments)),
                    "guidance_kind": str(revision.guidance_kind),
                    "service_kinds": Jsonb(list(revision.applicable_service_kinds)),
                    "incident_classes": Jsonb(list(revision.applicable_incident_classes)),
                    "symptom_tags": Jsonb(list(revision.symptom_tags)),
                    "purpose": revision.purpose,
                    "classification": revision.classification,
                    "regions": Jsonb(list(revision.eligible_regions)),
                    "content_ref": revision.content_ref,
                    "content_hash": revision.content_hash,
                    "revision_hash": revision.approval_digest,
                    "source_kind": str(revision.source_kind),
                    "source_ref": revision.source_ref,
                    "source_license": revision.source_license,
                    "evaluation_ref": revision.evaluation_ref,
                    "approval_ref": revision.approval_ref,
                    "approved_digest": None,
                    "author_principal": revision.author_principal,
                    "approved_by_principal": revision.approved_by_principal,
                    "supersedes_version": supersedes_version,
                    "lifecycle": str(revision.lifecycle),
                    "approved_at": revision.approved_at,
                },
            )
            cursor.execute(
                """SELECT revision_hash
                     FROM solvan_operability.guidance_revisions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND guidance_key=%(guidance_key)s AND version=%(version)s""",
                {**params, "guidance_key": revision.guidance_key, "version": revision.version},
            )
            stored_revision = cursor.fetchone()
            if (
                stored_revision is None
                or stored_revision["revision_hash"] != revision.approval_digest
            ):
                raise GuidanceError("a guidance revision already has different material")

            for agent_key in revision.allowed_agent_keys:
                cursor.execute(
                    """INSERT INTO solvan_operability.guidance_revision_agents
                         (organization_id,project_id,environment_id,guidance_key,
                          guidance_version,agent_key)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                               %(guidance_key)s,%(version)s,%(agent_key)s)
                       ON CONFLICT DO NOTHING""",
                    {
                        **params,
                        "guidance_key": revision.guidance_key,
                        "version": revision.version,
                        "agent_key": agent_key,
                    },
                )
            for profile_ref in revision.required_profile_revisions:
                profile_key, profile_version = profile_ref.split("@", 1)
                cursor.execute(
                    """INSERT INTO solvan_operability.guidance_revision_profiles
                         (organization_id,project_id,environment_id,guidance_key,
                          guidance_version,profile_key,profile_version)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                               %(guidance_key)s,%(version)s,%(profile_key)s,
                               %(profile_version)s) ON CONFLICT DO NOTHING""",
                    {
                        **params,
                        "guidance_key": revision.guidance_key,
                        "version": revision.version,
                        "profile_key": profile_key,
                        "profile_version": profile_version,
                    },
                )
            for step in revision.steps:
                cursor.execute(
                    """INSERT INTO solvan_operability.guidance_steps
                         (organization_id,project_id,environment_id,guidance_key,
                          guidance_version,step_key,ordinal,title,objective,step_kind,
                          prerequisite_step_keys_json,completion_predicate_key,
                          completion_predicate_version,required_evidence_kinds_json,
                          maximum_tool_requests,on_blocked)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                               %(guidance_key)s,%(version)s,%(step_key)s,%(ordinal)s,
                               %(title)s,%(objective)s,%(step_kind)s,%(prerequisites)s,
                               %(predicate_key)s,%(predicate_version)s,%(evidence_kinds)s,
                               %(maximum_tool_requests)s,%(on_blocked)s)
                       ON CONFLICT DO NOTHING""",
                    {
                        **params,
                        "guidance_key": revision.guidance_key,
                        "version": revision.version,
                        "step_key": step.step_key,
                        "ordinal": step.ordinal,
                        "title": step.title,
                        "objective": step.objective,
                        "step_kind": str(step.step_kind),
                        "prerequisites": Jsonb(list(step.prerequisite_step_keys)),
                        "predicate_key": step.completion_predicate_key,
                        "predicate_version": step.completion_predicate_version,
                        "evidence_kinds": Jsonb(list(step.required_evidence_kinds)),
                        "maximum_tool_requests": step.maximum_tool_requests,
                        "on_blocked": str(step.on_blocked),
                    },
                )
                for tool_ref in step.allowed_tool_revisions:
                    tool_key, tool_version = tool_ref.split("@", 1)
                    cursor.execute(
                        """INSERT INTO solvan_operability.guidance_step_tools
                             (organization_id,project_id,environment_id,guidance_key,
                              guidance_version,step_key,tool_key,tool_version)
                           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                                   %(guidance_key)s,%(version)s,%(step_key)s,%(tool_key)s,
                                   %(tool_version)s) ON CONFLICT DO NOTHING""",
                        {
                            **params,
                            "guidance_key": revision.guidance_key,
                            "version": revision.version,
                            "step_key": step.step_key,
                            "tool_key": tool_key,
                            "tool_version": tool_version,
                        },
                    )
            for declaration in revision.incompatibilities:
                cursor.execute(
                    """INSERT INTO solvan_operability.guidance_incompatibilities
                         (organization_id,project_id,environment_id,
                          declaring_guidance_key,declaring_version,
                          incompatible_guidance_key,reason_code,reviewable_digest)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                               %(guidance_key)s,%(version)s,%(incompatible_key)s,
                               %(reason_code)s,%(digest)s)
                       ON CONFLICT DO NOTHING""",
                    {
                        **params,
                        "guidance_key": revision.guidance_key,
                        "version": revision.version,
                        "incompatible_key": declaration.guidance_key,
                        "reason_code": declaration.reason_code,
                        "digest": revision.approval_digest,
                    },
                )
            self._append_audit(
                cursor=cursor,
                scope=scope,
                principal=revision.author_principal,
                event_type="GUIDANCE_DRAFT_CREATED",
                entity_ref=f"guidance:{revision.revision_ref}",
                digest=revision.approval_digest,
                decision_request_id=decision_request_id,
                reason_code="AUTHORIZED_DRAFT_CREATED",
            )
        return GuidanceLifecycleCommit(
            revision.guidance_key,
            revision.version,
            "DRAFT",
            revision.approval_digest,
            None,
            True,
        )

    def record_ingestion(
        self,
        *,
        scope: Scope,
        guidance_key: str,
        version: str,
        content_hash: str,
        accepted: bool,
        reason_codes: tuple[str, ...],
        armor_verdict_ref: str | None,
        principal: str,
        decision_request_id: str,
    ) -> str:
        if not reason_codes:
            raise GuidanceError("ingestion requires closed reason codes")
        receipt_id = new_identifier("gir")
        event_type = "GUIDANCE_INGESTION_ACCEPTED" if accepted else "GUIDANCE_INGESTION_REJECTED"
        entity_ref = f"guidance:{guidance_key}@{version}"
        with self._connection.cursor(row_factory=dict_row) as cursor:
            self._require_current_role_for_key(
                cursor=cursor,
                scope=scope,
                guidance_key=guidance_key,
                principal=principal,
                roles=("GUIDANCE_AUTHOR", "OPERABILITY_ADMIN"),
            )
            existing = self._audit_by_request(
                cursor=cursor, scope=scope, decision_request_id=decision_request_id
            )
            if existing is not None:
                self._require_same_audit(
                    existing=existing,
                    entity_ref=entity_ref,
                    digest=content_hash,
                    principal=principal,
                    event_type=event_type,
                )
                cursor.execute(
                    """SELECT id FROM solvan_operability.guidance_ingestion_receipts
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND guidance_key=%(guidance_key)s AND guidance_version=%(version)s
                          AND content_hash=%(content_hash)s AND decision=%(decision)s
                        ORDER BY evaluated_at,id LIMIT 1""",
                    {
                        **scope.canonical_dict(),
                        "guidance_key": guidance_key,
                        "version": version,
                        "content_hash": content_hash,
                        "decision": "ACCEPTED" if accepted else "REJECTED",
                    },
                )
                row = cursor.fetchone()
                if row is None:
                    raise GuidanceError("ingestion idempotency record is inconsistent")
                return str(row["id"])
            cursor.execute(
                """SELECT d.owner_department
                     FROM solvan_operability.guidance_revisions r
                     JOIN solvan_operability.guidance_definitions d USING
                       (organization_id,project_id,environment_id,guidance_key)
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s AND r.environment_id=%(environment_id)s
                      AND r.guidance_key=%(guidance_key)s AND r.version=%(version)s""",
                {**scope.canonical_dict(), "guidance_key": guidance_key, "version": version},
            )
            definition = cursor.fetchone()
            if definition is None:
                raise GuidanceError("guidance revision or content hash is unavailable")
            self._require_role(
                scope=scope,
                principal=principal,
                roles=("GUIDANCE_AUTHOR", "OPERABILITY_ADMIN"),
                department=str(definition["owner_department"]),
            )
            cursor.execute(
                """INSERT INTO solvan_operability.guidance_ingestion_receipts
                     (organization_id,project_id,environment_id,id,guidance_key,
                      guidance_version,content_hash,decision,reason_codes_json,
                      armor_verdict_ref,evaluated_at)
                   SELECT %(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                          guidance_key,version,content_hash,%(decision)s,%(reasons)s,
                          %(armor)s,%(evaluated_at)s
                     FROM solvan_operability.guidance_revisions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND guidance_key=%(guidance_key)s AND version=%(version)s
                      AND content_hash=%(content_hash)s""",
                {
                    **scope.canonical_dict(),
                    "id": receipt_id,
                    "guidance_key": guidance_key,
                    "version": version,
                    "content_hash": content_hash,
                    "decision": "ACCEPTED" if accepted else "REJECTED",
                    "reasons": Jsonb(list(reason_codes)),
                    "armor": armor_verdict_ref,
                    "evaluated_at": datetime.now(UTC),
                },
            )
            if cursor.rowcount != 1:
                raise GuidanceError("guidance revision or content hash is unavailable")
            self._append_audit(
                cursor=cursor,
                scope=scope,
                principal=principal,
                event_type=event_type,
                entity_ref=entity_ref,
                digest=content_hash,
                decision_request_id=decision_request_id,
                reason_code=reason_codes[0],
            )
        return receipt_id

    def guidance_runs_projection(self, *, scope: Scope, incident_id: str) -> list[dict[str, Any]]:
        """Reader-safe selected guidance and application-owned step verdicts."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT s.id AS selection_id,s.guidance_key,s.guidance_version,
                          s.guidance_hash,s.selection_role,s.selection_reason,s.selected_at,
                          r.id AS step_run_id,r.step_key,r.status,r.predicate_key,
                          r.predicate_version,r.predicate_result_ref,r.cited_records_json,
                          r.reason_code,r.tool_requests,r.started_at,r.completed_at
                     FROM solvan_operability.guidance_selections s
                     JOIN solvan.agent_runs a ON
                       (a.organization_id,a.project_id,a.environment_id,a.id)=
                       (s.organization_id,s.project_id,s.environment_id,s.agent_run_id)
                     LEFT JOIN solvan_operability.guidance_step_runs r ON
                       (r.organization_id,r.project_id,r.environment_id,r.selection_id)=
                       (s.organization_id,s.project_id,s.environment_id,s.id)
                    WHERE s.organization_id=%(organization_id)s
                      AND s.project_id=%(project_id)s AND s.environment_id=%(environment_id)s
                      AND a.incident_id=%(incident_id)s
                    ORDER BY s.selected_at,r.step_key""",
                {**scope.canonical_dict(), "incident_id": incident_id},
            )
            return [dict(row) for row in cursor.fetchall()]

    def evaluations_projection(
        self, *, scope: Scope, guidance_key: str, version: str
    ) -> list[dict[str, Any]]:
        """Return safe evaluation metadata without bodies, principals, or raw receipts."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,suite_version,decision,passed_cases,failed_cases,
                          reason_codes_json,evaluated_at,
                          right(receipt_hash,12) AS receipt_hash_suffix
                     FROM solvan_operability.guidance_evaluations
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND guidance_key=%(guidance_key)s AND guidance_version=%(version)s
                    ORDER BY evaluated_at DESC,id DESC""",
                {**scope.canonical_dict(), "guidance_key": guidance_key, "version": version},
            )
            return [dict(row) for row in cursor.fetchall()]

    def record_evaluation(
        self,
        *,
        scope: Scope,
        guidance_key: str,
        version: str,
        expected_digest: str,
        principal: str,
        suite_version: str,
        passed_cases: int,
        failed_cases: int,
        receipt_ref: str,
        receipt_hash: str,
        receipt_generation: str,
        corpus_digest: str,
        case_set_digest: str,
        scorer_name: str,
        scorer_version: str,
        model_config_pins: dict[str, str],
        repetitions: int,
        pass_thresholds: dict[str, float],
        reason_codes: tuple[str, ...],
        decision_request_id: str,
    ) -> str:
        """Record evaluator-owned evidence without mutating the draft revision."""

        if (
            not suite_version.strip()
            or not receipt_ref.strip()
            or not receipt_generation.isdigit()
            or not scorer_name.strip()
            or not scorer_version.strip()
            or not model_config_pins
            or repetitions < 1
            or not pass_thresholds
            or not reason_codes
        ):
            raise GuidanceError("guidance evaluation material is incomplete")
        digests = (receipt_hash, corpus_digest, case_set_digest)
        if any(not value.startswith("sha256:") or len(value) != 71 for value in digests):
            raise GuidanceError("guidance evaluation receipt hash is invalid")
        if passed_cases < 0 or failed_cases < 0 or passed_cases + failed_cases == 0:
            raise GuidanceError("guidance evaluation case counts are invalid")
        evaluation_id = new_identifier("gev")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            self._require_current_role_for_key(
                cursor=cursor,
                scope=scope,
                guidance_key=guidance_key,
                principal=principal,
                roles=("GUIDANCE_EVALUATOR", "OPERABILITY_ADMIN"),
            )
            existing = self._audit_by_request(
                cursor=cursor, scope=scope, decision_request_id=decision_request_id
            )
            entity_ref = f"guidance-evaluation:{guidance_key}@{version}"
            if existing is not None:
                self._require_same_audit(
                    existing=existing,
                    entity_ref=entity_ref,
                    digest=expected_digest,
                    principal=principal,
                    event_type="GUIDANCE_EVALUATED",
                )
                cursor.execute(
                    """SELECT id FROM solvan_operability.guidance_evaluations
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND guidance_key=%(guidance_key)s AND guidance_version=%(version)s
                          AND revision_digest=%(digest)s AND suite_version=%(suite)s""",
                    {
                        **scope.canonical_dict(),
                        "guidance_key": guidance_key,
                        "version": version,
                        "digest": expected_digest,
                        "suite": suite_version,
                    },
                )
                row = cursor.fetchone()
                if row is None:
                    raise GuidanceError("evaluation idempotency record is inconsistent")
                return str(row["id"])
            cursor.execute(
                """SELECT r.author_principal,r.revision_hash,r.lifecycle,d.owner_department
                     FROM solvan_operability.guidance_revisions r
                     JOIN solvan_operability.guidance_definitions d USING
                       (organization_id,project_id,environment_id,guidance_key)
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s AND r.environment_id=%(environment_id)s
                      AND r.guidance_key=%(guidance_key)s AND r.version=%(version)s
                    FOR UPDATE OF r""",
                {**scope.canonical_dict(), "guidance_key": guidance_key, "version": version},
            )
            row = cursor.fetchone()
            if row is None or row["lifecycle"] not in {"DRAFT", "IN_REVIEW"}:
                raise GuidanceError("guidance is not eligible for evaluation")
            if row["revision_hash"] != expected_digest:
                raise GuidanceError("guidance evaluation digest is stale")
            if row["author_principal"] == principal:
                raise GuidanceError("a guidance author cannot evaluate their revision")
            self._require_role(
                scope=scope,
                principal=principal,
                roles=("GUIDANCE_EVALUATOR", "OPERABILITY_ADMIN"),
                department=str(row["owner_department"]),
            )
            decision = "PASS" if failed_cases == 0 else "FAIL"
            cursor.execute(
                """INSERT INTO solvan_operability.guidance_evaluations
                     (organization_id,project_id,environment_id,id,guidance_key,
                      guidance_version,revision_digest,suite_version,decision,
                      passed_cases,failed_cases,receipt_ref,receipt_hash,
                      receipt_generation,corpus_digest,case_set_digest,
                      scorer_name,scorer_version,model_config_pins_json,
                      repetitions,pass_thresholds_json,evaluator_principal,
                      reason_codes_json)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                           %(guidance_key)s,%(version)s,%(digest)s,%(suite)s,%(decision)s,
                           %(passed)s,%(failed)s,%(receipt_ref)s,%(receipt_hash)s,
                           %(receipt_generation)s,%(corpus_digest)s,%(case_set_digest)s,
                           %(scorer_name)s,%(scorer_version)s,%(model_config_pins)s,
                           %(repetitions)s,%(pass_thresholds)s,%(principal)s,%(reasons)s)""",
                {
                    **scope.canonical_dict(),
                    "id": evaluation_id,
                    "guidance_key": guidance_key,
                    "version": version,
                    "digest": expected_digest,
                    "suite": suite_version,
                    "decision": decision,
                    "passed": passed_cases,
                    "failed": failed_cases,
                    "receipt_ref": receipt_ref,
                    "receipt_hash": receipt_hash,
                    "receipt_generation": receipt_generation,
                    "corpus_digest": corpus_digest,
                    "case_set_digest": case_set_digest,
                    "scorer_name": scorer_name,
                    "scorer_version": scorer_version,
                    "model_config_pins": Jsonb(model_config_pins),
                    "repetitions": repetitions,
                    "pass_thresholds": Jsonb(pass_thresholds),
                    "principal": principal,
                    "reasons": Jsonb(list(reason_codes)),
                },
            )
            self._append_audit(
                cursor=cursor,
                scope=scope,
                principal=principal,
                event_type="GUIDANCE_EVALUATED",
                entity_ref=entity_ref,
                digest=expected_digest,
                decision_request_id=decision_request_id,
                reason_code=reason_codes[0],
            )
        return evaluation_id
