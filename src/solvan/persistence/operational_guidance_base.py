"""Shared transaction and authorization primitives for Operational Guidance stores."""

from __future__ import annotations

from typing import Any, cast

from psycopg import Connection

from solvan.application.operational_guidance import GuidanceError
from solvan.domain import Scope, new_identifier


class OperationalGuidanceStoreBase:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def _require_role(
        self,
        *,
        scope: Scope,
        principal: str,
        roles: tuple[str, ...],
        department: str,
    ) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT 1 FROM solvan_operability.operability_role_bindings
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND principal=%(principal)s AND role=ANY(%(roles)s)
                      AND department=%(department)s
                      AND (expires_at IS NULL OR expires_at > now()) LIMIT 1""",
                {
                    **scope.canonical_dict(),
                    "principal": principal,
                    "roles": list(roles),
                    "department": department,
                },
            )
            if cursor.fetchone() is None:
                raise GuidanceError("required operational-guidance role is inactive")

    def _require_current_role_for_key(
        self,
        *,
        cursor: Any,
        scope: Scope,
        guidance_key: str,
        principal: str,
        roles: tuple[str, ...],
    ) -> None:
        """Re-verify the caller's current, unexpired binding before a replay.

        Idempotent replay must not outlive the grant that authorized the first
        attempt: a revoked or expired role means the prior result is not
        returned (specification 17 §10). The department comes from the stored
        definition, never from the request. A key with no definition yet fails
        later on the fresh path with its own closed error.
        """

        cursor.execute(
            """SELECT owner_department FROM solvan_operability.guidance_definitions
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND guidance_key=%(guidance_key)s""",
            {**scope.canonical_dict(), "guidance_key": guidance_key},
        )
        definition = cursor.fetchone()
        if definition is None:
            return
        self._require_role(
            scope=scope,
            principal=principal,
            roles=roles,
            department=str(definition["owner_department"]),
        )

    @staticmethod
    def _audit_by_request(
        *, cursor: Any, scope: Scope, decision_request_id: str
    ) -> dict[str, Any] | None:
        if not 8 <= len(decision_request_id) <= 128:
            raise GuidanceError("decision request ID must contain 8 to 128 characters")
        cursor.execute(
            """SELECT * FROM solvan_operability.operability_audit_events
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND decision_request_id=%(request_id)s FOR UPDATE""",
            {**scope.canonical_dict(), "request_id": decision_request_id},
        )
        return cast("dict[str, Any] | None", cursor.fetchone())

    @staticmethod
    def _require_same_audit(
        *,
        existing: dict[str, Any],
        entity_ref: str,
        digest: str,
        principal: str,
        event_type: str,
    ) -> None:
        if (
            existing["entity_ref"] != entity_ref
            or existing["material_digest"] != digest
            or existing["principal"] != principal
            or existing["event_type"] != event_type
        ):
            raise GuidanceError("guidance idempotency material mismatch")

    @staticmethod
    def _append_audit(
        *,
        cursor: Any,
        scope: Scope,
        principal: str,
        event_type: str,
        entity_ref: str,
        digest: str,
        decision_request_id: str,
        reason_code: str,
    ) -> None:
        cursor.execute(
            """INSERT INTO solvan_operability.operability_audit_events
                 (organization_id,project_id,environment_id,id,principal,event_type,
                  entity_ref,material_digest,decision_request_id,reason_code)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                       %(principal)s,%(event_type)s,%(entity_ref)s,%(digest)s,
                       %(request_id)s,%(reason_code)s)""",
            {
                **scope.canonical_dict(),
                "id": new_identifier("goa"),
                "principal": principal,
                "event_type": event_type,
                "entity_ref": entity_ref,
                "digest": digest,
                "request_id": decision_request_id,
                "reason_code": reason_code,
            },
        )

    @staticmethod
    def _require_approval_dependencies(
        *,
        cursor: Any,
        scope: Scope,
        guidance_key: str,
        version: str,
        content_hash: str,
        reviewable_digest: str,
        known_predicates: frozenset[str],
    ) -> None:
        params = {
            **scope.canonical_dict(),
            "guidance_key": guidance_key,
            "version": version,
            "content_hash": content_hash,
            "reviewable_digest": reviewable_digest,
        }
        cursor.execute(
            """SELECT 1 FROM solvan_operability.guidance_ingestion_receipts
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND guidance_key=%(guidance_key)s
                  AND guidance_version=%(version)s AND content_hash=%(content_hash)s
                  AND decision='ACCEPTED' LIMIT 1""",
            params,
        )
        if cursor.fetchone() is None:
            raise GuidanceError("guidance has no accepted exact ingestion receipt")
        cursor.execute(
            """SELECT completion_predicate_key,completion_predicate_version
                 FROM solvan_operability.guidance_steps
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND guidance_key=%(guidance_key)s
                  AND guidance_version=%(version)s""",
            params,
        )
        predicates = {
            f"{row['completion_predicate_key']}@{row['completion_predicate_version']}"
            for row in cursor.fetchall()
        }
        if not predicates or not predicates.issubset(known_predicates):
            raise GuidanceError("guidance uses an unknown completion predicate")
        cursor.execute(
            """SELECT 1
                 FROM solvan_operability.guidance_step_tools st
                 JOIN solvan_operability.tool_revisions t
                   ON (t.tool_key,t.version)=(st.tool_key,st.tool_version)
                WHERE st.organization_id=%(organization_id)s
                  AND st.project_id=%(project_id)s AND st.environment_id=%(environment_id)s
                  AND st.guidance_key=%(guidance_key)s
                  AND st.guidance_version=%(version)s
                  AND (t.lifecycle <> 'APPROVED' OR t.permission_class='MUTATE' OR EXISTS (
                    SELECT 1 FROM solvan_operability.guidance_revision_profiles gp
                     WHERE gp.organization_id=st.organization_id
                       AND gp.project_id=st.project_id
                       AND gp.environment_id=st.environment_id
                       AND gp.guidance_key=st.guidance_key
                       AND gp.guidance_version=st.guidance_version
                       AND NOT EXISTS (
                         SELECT 1 FROM solvan_operability.tool_profile_revisions pr
                         JOIN solvan_operability.tool_profile_members pm
                           ON (pm.profile_key,pm.profile_version)=(pr.profile_key,pr.version)
                          WHERE pr.profile_key=gp.profile_key
                            AND pr.version=gp.profile_version
                            AND pr.lifecycle='APPROVED'
                            AND pm.tool_key=st.tool_key AND pm.tool_version=st.tool_version
                       )
                  )) LIMIT 1""",
            params,
        )
        if cursor.fetchone() is not None:
            raise GuidanceError("guidance Tool is outside an approved required profile")
        cursor.execute(
            """SELECT guidance_kind,source_license
                 FROM solvan_operability.guidance_revisions
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND guidance_key=%(guidance_key)s AND version=%(version)s""",
            params,
        )
        revision = cursor.fetchone()
        if revision is not None and revision["guidance_kind"] == "SKILL":
            cursor.execute(
                """SELECT b.reviewable_digest,b.normalized_license_identifier,
                          p.enabled,p.import_allowed
                     FROM solvan_operability.guidance_skill_bindings b
                     JOIN solvan_operability.skill_license_policies p ON
                       (p.organization_id,p.project_id,p.environment_id,
                        p.normalized_identifier)=
                       (b.organization_id,b.project_id,b.environment_id,
                        b.normalized_license_identifier)
                    WHERE b.organization_id=%(organization_id)s
                      AND b.project_id=%(project_id)s
                      AND b.environment_id=%(environment_id)s
                      AND b.guidance_key=%(guidance_key)s
                      AND b.guidance_version=%(version)s""",
                params,
            )
            binding = cursor.fetchone()
            if (
                binding is None
                or binding["reviewable_digest"] != reviewable_digest
                or binding["normalized_license_identifier"] != revision["source_license"]
                or not binding["enabled"]
                or not binding["import_allowed"]
            ):
                raise GuidanceError("skill compile or license binding is absent, stale, or denied")
            cursor.execute(
                """SELECT 1 FROM solvan_operability.guidance_incompatibilities
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND declaring_guidance_key=%(guidance_key)s
                      AND declaring_version=%(version)s
                      AND reviewable_digest<>%(reviewable_digest)s LIMIT 1""",
                params,
            )
            if cursor.fetchone() is not None:
                raise GuidanceError("skill incompatibility declaration is stale")
