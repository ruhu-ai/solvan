"""Run-bound Operational Guidance selection and deterministic predicates."""

from __future__ import annotations

from typing import Any

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.operational_guidance import GuidanceError
from solvan.domain import Scope, new_identifier
from solvan.persistence.operational_guidance_base import OperationalGuidanceStoreBase
from solvan.persistence.operational_guidance_predicates import evaluate_registered_predicate
from solvan.persistence.operational_guidance_types import (
    GuidanceSelectedMaterial,
    GuidanceStepVerdict,
)


class OperationalGuidanceRuntimeMixin(OperationalGuidanceStoreBase):
    def pending_steps(
        self, *, scope: Scope, maximum_items: int = 100
    ) -> tuple[tuple[str, str], ...]:
        if not 1 <= maximum_items <= 500:
            raise GuidanceError("guidance pending-step limit is invalid")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT selection_id,step_key
                     FROM solvan_operability.guidance_step_runs
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND status IN ('PENDING','RUNNING')
                    ORDER BY id LIMIT %(maximum_items)s""",
                {**scope.canonical_dict(), "maximum_items": maximum_items},
            )
            return tuple((str(row[0]), str(row[1])) for row in cursor.fetchall())

    def select_approved(
        self,
        *,
        scope: Scope,
        agent_run_id: str,
        guidance_key: str,
        version: str,
        expected_guidance_hash: str,
        runtime_region: str,
        purpose: str,
        data_classification: str,
        role: str,
        reason: str,
    ) -> GuidanceSelectedMaterial:
        """Persist an exact eligible selection before revealing its content reference."""

        if role not in {"PRIMARY", "SUPPORTING"} or not reason.strip():
            raise GuidanceError("selection role and bounded reason are required")
        selection_id = new_identifier("gsl")
        existing_selection_query = """SELECT id,guidance_hash,selection_role FROM
                     solvan_operability.guidance_selections
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND agent_run_id=%(agent_run_id)s AND guidance_key=%(guidance_key)s
                      AND guidance_version=%(version)s FOR UPDATE"""
        existing_selection_params = {
            **scope.canonical_dict(),
            "agent_run_id": agent_run_id,
            "guidance_key": guidance_key,
            "version": version,
        }

        def _idempotent_material(
            existing: dict[str, Any], eligible: dict[str, Any]
        ) -> GuidanceSelectedMaterial:
            if (
                existing["guidance_hash"] != expected_guidance_hash
                or existing["selection_role"] != role
            ):
                raise GuidanceError("guidance selection retry changed immutable material")
            return GuidanceSelectedMaterial(
                selection_id=str(existing["id"]),
                guidance_key=guidance_key,
                version=version,
                guidance_hash=expected_guidance_hash,
                content_ref=str(eligible["content_ref"]),
                content_hash=str(eligible["content_hash"]),
                classification=str(eligible["classification"]),
                selected=True,
            )

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT a.agent_key,b.profile_key,b.profile_version,b.profile_material_hash,
                          COALESCE((
                            SELECT jsonb_object_agg(accepted.connection_id,
                                                    accepted.connection_epoch)
                              FROM solvan_operability.agent_run_accepted_tool_bindings accepted
                             WHERE accepted.organization_id=b.organization_id
                               AND accepted.project_id=b.project_id
                               AND accepted.environment_id=b.environment_id
                               AND accepted.agent_run_id=b.agent_run_id
                               AND accepted.connection_id IS NOT NULL
                          ), '{}'::jsonb) AS connection_epochs_json,
                          r.lifecycle,r.revision_hash,
                          r.content_ref,r.content_hash,r.classification,
                          r.purpose,r.eligible_regions_json,
                          EXISTS (
                            SELECT 1 FROM solvan_operability.guidance_revision_agents ga
                             WHERE (ga.organization_id,ga.project_id,ga.environment_id,
                                    ga.guidance_key,ga.guidance_version,ga.agent_key)=
                                   (r.organization_id,r.project_id,r.environment_id,
                                    r.guidance_key,r.version,a.agent_key)
                          ) AS agent_allowed,
                          EXISTS (
                            SELECT 1 FROM solvan_operability.guidance_revision_profiles gp
                             WHERE (gp.organization_id,gp.project_id,gp.environment_id,
                                    gp.guidance_key,gp.guidance_version,gp.profile_key,
                                    gp.profile_version)=
                                   (r.organization_id,r.project_id,r.environment_id,
                                    r.guidance_key,r.version,b.profile_key,b.profile_version)
                          ) AS profile_allowed
                     FROM solvan.agent_runs a
                     JOIN solvan_operability.agent_run_tool_bindings b ON
                       (b.organization_id,b.project_id,b.environment_id,b.agent_run_id)=
                       (a.organization_id,a.project_id,a.environment_id,a.id)
                     JOIN solvan_operability.guidance_revisions r ON
                       (r.organization_id,r.project_id,r.environment_id)=
                       (a.organization_id,a.project_id,a.environment_id)
                    WHERE a.organization_id=%(organization_id)s
                      AND a.project_id=%(project_id)s AND a.environment_id=%(environment_id)s
                      AND a.id=%(agent_run_id)s AND r.guidance_key=%(guidance_key)s
                      AND r.version=%(version)s FOR SHARE OF a,b,r""",
                {
                    **scope.canonical_dict(),
                    "agent_run_id": agent_run_id,
                    "guidance_key": guidance_key,
                    "version": version,
                },
            )
            row = cursor.fetchone()
            if row is None:
                raise GuidanceError("guidance selection lacks an exact frozen run binding")
            if row["lifecycle"] != "APPROVED":
                raise GuidanceError("only approved guidance may enter a new run")
            if row["revision_hash"] != expected_guidance_hash:
                raise GuidanceError("guidance selection digest is stale")
            if not row["agent_allowed"] or not row["profile_allowed"]:
                raise GuidanceError("guidance is outside the frozen Agent profile")
            if row["purpose"] != purpose:
                raise GuidanceError("guidance purpose does not match the run")
            if runtime_region not in row["eligible_regions_json"]:
                raise GuidanceError("guidance is not eligible in the Runtime region")
            if self._classification_rank(str(row["classification"])) > self._classification_rank(
                data_classification
            ):
                raise GuidanceError("guidance exceeds the run classification ceiling")
            cursor.execute(existing_selection_query, existing_selection_params)
            existing = cursor.fetchone()
            if existing is not None:
                return _idempotent_material(existing, row)
            cursor.execute(
                """INSERT INTO solvan_operability.guidance_selections
                         (organization_id,project_id,environment_id,id,agent_run_id,
                          guidance_key,guidance_version,guidance_hash,profile_key,
                          profile_version,profile_material_hash,connection_epochs_json,
                          selection_role,selection_reason)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                               %(agent_run_id)s,%(guidance_key)s,%(guidance_version)s,
                               %(guidance_hash)s,%(profile_key)s,%(profile_version)s,
                               %(profile_material_hash)s,%(connection_epochs)s,%(role)s,
                               %(reason)s)
                       ON CONFLICT DO NOTHING
                       RETURNING id""",
                {
                    **scope.canonical_dict(),
                    "id": selection_id,
                    "agent_run_id": agent_run_id,
                    "guidance_key": guidance_key,
                    "guidance_version": version,
                    "guidance_hash": expected_guidance_hash,
                    "profile_key": row["profile_key"],
                    "profile_version": row["profile_version"],
                    "profile_material_hash": row["profile_material_hash"],
                    "connection_epochs": Jsonb(row["connection_epochs_json"]),
                    "role": role,
                    "reason": reason.strip()[:500],
                },
            )
            if cursor.fetchone() is None:
                cursor.execute(existing_selection_query, existing_selection_params)
                concurrent = cursor.fetchone()
                if concurrent is None:
                    if role == "PRIMARY":
                        raise GuidanceError(
                            "a run already holds a different primary guidance selection"
                        )
                    raise GuidanceError("guidance selection conflicts with existing authority")
                return _idempotent_material(concurrent, row)
            for step in self._guidance_steps(
                cursor=cursor, scope=scope, guidance_key=guidance_key, version=version
            ):
                cursor.execute(
                    """INSERT INTO solvan_operability.guidance_step_runs
                         (organization_id,project_id,environment_id,id,selection_id,
                          step_key,status,predicate_key,predicate_version)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                               %(selection_id)s,%(step_key)s,'PENDING',%(predicate_key)s,
                               %(predicate_version)s)""",
                    {
                        **scope.canonical_dict(),
                        "id": new_identifier("gsr"),
                        "selection_id": selection_id,
                        "step_key": step["step_key"],
                        "predicate_key": step["completion_predicate_key"],
                        "predicate_version": step["completion_predicate_version"],
                    },
                )
        return GuidanceSelectedMaterial(
            selection_id=selection_id,
            guidance_key=guidance_key,
            version=version,
            guidance_hash=expected_guidance_hash,
            content_ref=str(row["content_ref"]),
            content_hash=str(row["content_hash"]),
            classification=str(row["classification"]),
            selected=True,
        )

    @staticmethod
    def _classification_rank(value: str) -> int:
        try:
            return {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}[value]
        except KeyError as error:
            raise GuidanceError("guidance classification is invalid") from error

    def trigger_guidance_for_run(
        self, *, scope: Scope, agent_run_id: str
    ) -> tuple[str, str, str] | None:
        """Resolve only the exact guidance revision approved on the incident trigger policy."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT p.guidance_key,p.guidance_version,g.revision_hash
                     FROM solvan.agent_runs a
                     JOIN solvan.incidents i ON
                       (i.organization_id,i.project_id,i.environment_id,i.id)=
                       (a.organization_id,a.project_id,a.environment_id,a.incident_id)
                     JOIN solvan_operability.trigger_policy_revisions p ON
                       (p.organization_id,p.project_id,p.environment_id,p.policy_key,p.version)=
                       (i.organization_id,i.project_id,i.environment_id,
                        i.trigger_policy_key,i.trigger_policy_version)
                     JOIN solvan_operability.guidance_revisions g ON
                       (g.organization_id,g.project_id,g.environment_id,g.guidance_key,g.version)=
                       (p.organization_id,p.project_id,p.environment_id,
                        p.guidance_key,p.guidance_version)
                    WHERE a.organization_id=%(organization_id)s
                      AND a.project_id=%(project_id)s
                      AND a.environment_id=%(environment_id)s
                      AND a.id=%(agent_run_id)s AND p.lifecycle='APPROVED'
                      AND g.lifecycle='APPROVED'""",
                {**scope.canonical_dict(), "agent_run_id": agent_run_id},
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return str(row["guidance_key"]), str(row["guidance_version"]), str(row["revision_hash"])

    def record_fetch(
        self,
        *,
        scope: Scope,
        selection_id: str,
        content_hash: str,
        outcome: str,
        reason_codes: tuple[str, ...],
    ) -> None:
        if outcome not in {"ALLOWED", "BLOCKED"} or not reason_codes:
            raise GuidanceError("guidance fetch audit material is invalid")
        with self._connection.cursor() as cursor:
            request_id = f"guidance-fetch:{selection_id}:{outcome}"
            existing = self._audit_by_request(
                cursor=cursor, scope=scope, decision_request_id=request_id
            )
            if existing is not None:
                self._require_same_audit(
                    existing=existing,
                    entity_ref=f"guidance-selection:{selection_id}",
                    digest=content_hash,
                    principal="service:coordinator",
                    event_type=f"GUIDANCE_FETCH_{outcome}",
                )
                return
            self._append_audit(
                cursor=cursor,
                scope=scope,
                principal="service:coordinator",
                event_type=f"GUIDANCE_FETCH_{outcome}",
                entity_ref=f"guidance-selection:{selection_id}",
                digest=content_hash,
                decision_request_id=request_id,
                reason_code=reason_codes[0],
            )

    @staticmethod
    def _guidance_steps(
        *, cursor: Any, scope: Scope, guidance_key: str, version: str
    ) -> list[dict[str, Any]]:
        cursor.execute(
            """SELECT step_key,completion_predicate_key,completion_predicate_version
                 FROM solvan_operability.guidance_steps
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND guidance_key=%(guidance_key)s AND guidance_version=%(version)s
                ORDER BY ordinal""",
            {**scope.canonical_dict(), "guidance_key": guidance_key, "version": version},
        )
        return list(cursor.fetchall())

    def evaluate_step(
        self, *, scope: Scope, selection_id: str, step_key: str
    ) -> GuidanceStepVerdict:
        """Evaluate a registered predicate over committed records; model prose is ignored."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT sr.id,sr.status,sr.predicate_key,sr.predicate_version,
                          s.agent_run_id,gs.required_evidence_kinds_json,
                          gs.prerequisite_step_keys_json
                     FROM solvan_operability.guidance_step_runs sr
                     JOIN solvan_operability.guidance_selections s ON
                       (s.organization_id,s.project_id,s.environment_id,s.id)=
                       (sr.organization_id,sr.project_id,sr.environment_id,sr.selection_id)
                     JOIN solvan_operability.guidance_steps gs ON
                       (gs.organization_id,gs.project_id,gs.environment_id,gs.guidance_key,
                        gs.guidance_version,gs.step_key)=
                       (s.organization_id,s.project_id,s.environment_id,s.guidance_key,
                        s.guidance_version,sr.step_key)
                    WHERE sr.organization_id=%(organization_id)s
                      AND sr.project_id=%(project_id)s
                      AND sr.environment_id=%(environment_id)s
                      AND sr.selection_id=%(selection_id)s AND sr.step_key=%(step_key)s
                    FOR UPDATE OF sr""",
                {**scope.canonical_dict(), "selection_id": selection_id, "step_key": step_key},
            )
            row = cursor.fetchone()
            if row is None:
                raise GuidanceError("guidance step run was not found")
            predicate_ref = f"{row['predicate_key']}@{row['predicate_version']}"
            if row["status"] not in {"PENDING", "RUNNING"}:
                cursor.execute(
                    """SELECT cited_records_json,reason_code FROM
                         solvan_operability.guidance_step_runs
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND id=%(id)s""",
                    {**scope.canonical_dict(), "id": row["id"]},
                )
                material = cursor.fetchone()
                if material is None:
                    raise GuidanceError("guidance step verdict disappeared")
                return GuidanceStepVerdict(
                    str(row["id"]),
                    step_key,
                    str(row["status"]),
                    predicate_ref,
                    tuple(material["cited_records_json"]),
                    material["reason_code"],
                    False,
                )
            prerequisites = tuple(row["prerequisite_step_keys_json"])
            if prerequisites:
                cursor.execute(
                    """SELECT count(*) FILTER (WHERE status='SATISFIED') AS satisfied,
                              count(*) AS total
                         FROM solvan_operability.guidance_step_runs
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND selection_id=%(selection_id)s AND step_key=ANY(%(keys)s)""",
                    {
                        **scope.canonical_dict(),
                        "selection_id": selection_id,
                        "keys": list(prerequisites),
                    },
                )
                dependency = cursor.fetchone()
                if dependency is None:
                    raise GuidanceError("guidance prerequisite projection failed")
                if int(dependency["satisfied"]) != len(prerequisites):
                    raise GuidanceError("guidance step prerequisites are not satisfied")
            status_value, cited, reason_code = self._evaluate_registered_predicate(
                cursor=cursor,
                scope=scope,
                predicate_ref=predicate_ref,
                selection_id=selection_id,
                agent_run_id=str(row["agent_run_id"]),
                required_evidence_kinds=tuple(row["required_evidence_kinds_json"]),
            )
            result_ref = f"db://solvan-operability/guidance-step-runs/{row['id']}"
            cursor.execute(
                """UPDATE solvan_operability.guidance_step_runs
                      SET status=%(status)s,predicate_result_ref=%(result_ref)s,
                          cited_records_json=%(cited)s,reason_code=%(reason_code)s,
                          started_at=coalesce(started_at,now()),completed_at=now()
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(id)s AND status IN ('PENDING','RUNNING')""",
                {
                    **scope.canonical_dict(),
                    "id": row["id"],
                    "status": status_value,
                    "result_ref": result_ref,
                    "cited": Jsonb(list(cited)),
                    "reason_code": reason_code,
                },
            )
        return GuidanceStepVerdict(
            str(row["id"]),
            step_key,
            status_value,
            predicate_ref,
            cited,
            reason_code,
            True,
        )

    def bind_step_tool_call(
        self,
        *,
        scope: Scope,
        selection_id: str,
        step_key: str,
        tool_call_id: str,
    ) -> bool:
        """Append one exact, budgeted Tool receipt to a selected guidance step."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id FROM solvan_operability.guidance_step_runs
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND selection_id=%(selection_id)s AND step_key=%(step_key)s
                    FOR UPDATE""",
                {
                    **scope.canonical_dict(),
                    "selection_id": selection_id,
                    "step_key": step_key,
                },
            )
            step = cursor.fetchone()
            if step is None:
                raise GuidanceError("guidance step run was not found")
            cursor.execute(
                """INSERT INTO solvan_operability.guidance_step_tool_calls
                     (organization_id,project_id,environment_id,step_run_id,
                      tool_call_id)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(step_run_id)s,%(tool_call_id)s)
                   ON CONFLICT DO NOTHING
                   RETURNING tool_call_id""",
                {
                    **scope.canonical_dict(),
                    "step_run_id": step["id"],
                    "tool_call_id": tool_call_id,
                },
            )
            return cursor.fetchone() is not None

    def _evaluate_registered_predicate(
        self,
        *,
        cursor: Any,
        scope: Scope,
        predicate_ref: str,
        selection_id: str,
        agent_run_id: str,
        required_evidence_kinds: tuple[str, ...],
    ) -> tuple[str, tuple[str, ...], str | None]:
        return evaluate_registered_predicate(
            cursor=cursor,
            scope=scope,
            predicate_ref=predicate_ref,
            selection_id=selection_id,
            agent_run_id=agent_run_id,
            required_evidence_kinds=required_evidence_kinds,
        )
