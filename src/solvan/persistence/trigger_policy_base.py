"""Shared authorization and audit primitives for trigger policy stores."""

from __future__ import annotations

from typing import Any, cast

from psycopg import Connection

from solvan.application.operational_guidance import GuidanceError
from solvan.domain import Scope, new_identifier

_CLASSIFICATION_RANK = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}


class TriggerPolicyStoreBase:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def current_target_snapshot_hash(self, *, scope: Scope, target_key: str) -> str:
        """Resolve the current target in a runtime-capable store implementation."""

        raise NotImplementedError

    @staticmethod
    def _require_policy_dependencies(*, cursor: Any, scope: Scope, row: dict[str, Any]) -> None:
        cursor.execute(
            """SELECT classification FROM solvan.tenant_connections
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND id=%(connection_id)s AND availability='READY'
                  AND last_probe_result='SUCCEEDED'
                  AND connection_epoch=%(connection_epoch)s
                  AND residency_region=%(region)s""",
            {
                **scope.canonical_dict(),
                "connection_id": row["source_connection_id"],
                "connection_epoch": row["source_connection_epoch"],
                "region": row["region"],
            },
        )
        connection = cursor.fetchone()
        if connection is None:
            raise GuidanceError("trigger policy source connection is unavailable or stale")
        if (
            _CLASSIFICATION_RANK[str(connection["classification"])]
            > _CLASSIFICATION_RANK[str(row["classification_ceiling"])]
        ):
            raise GuidanceError("trigger policy source connection exceeds classification ceiling")
        cursor.execute(
            """SELECT 1
                 FROM solvan_operability.tool_probe_receipts probe
                 JOIN solvan_operability.tool_revisions tool ON
                   (tool.tool_key,tool.version)=(probe.tool_key,probe.tool_version)
                 JOIN solvan_operability.tool_revision_requesters requester ON
                   (requester.tool_key,requester.tool_version,requester.requester_key)=
                   (probe.tool_key,probe.tool_version,probe.agent_key)
                 JOIN solvan.tenant_connections connection ON
                   (connection.organization_id,connection.project_id,
                    connection.environment_id,connection.id)=
                   (probe.organization_id,probe.project_id,
                    probe.environment_id,probe.connection_id)
                 JOIN solvan_operability.tool_profile_revisions profile ON
                   profile.profile_key=%(profile_key)s
                  AND profile.version=%(profile_version)s
                  AND profile.allowed_agent_key=probe.agent_key
                 JOIN solvan_operability.tool_profile_members member ON
                   (member.profile_key,member.profile_version,
                    member.tool_key,member.tool_version)=
                   (profile.profile_key,profile.version,probe.tool_key,probe.tool_version)
                 JOIN solvan_operability.tool_profile_connection_requirements requirement ON
                   (requirement.profile_key,requirement.profile_version,
                    requirement.ordinal,requirement.tool_key,requirement.tool_version)=
                   (member.profile_key,member.profile_version,
                    member.ordinal,member.tool_key,member.tool_version)
                WHERE probe.organization_id=%(organization_id)s
                  AND probe.project_id=%(project_id)s
                  AND probe.environment_id=%(environment_id)s
                  AND probe.connection_id=%(connection_id)s
                  AND probe.connection_epoch=%(connection_epoch)s
                  AND probe.tool_key=%(source_tool_key)s
                  AND probe.tool_version=%(source_tool_version)s
                  AND probe.agent_key=%(source_agent_key)s
                  AND probe.identity_ref=%(source_identity_ref)s
                  AND probe.registry_resource=tool.registry_resource
                  AND probe.network_policy_hash=tool.network_policy_hash
                  AND connection.provider=requirement.provider
                  AND requirement.binding_kind='POLICY_SOURCE_CONNECTION'
                  AND requirement.capability_key=%(source_capability_class)s
                  AND requirement.external_project_selector='TARGET_RESOURCE_PROJECT'
                  AND tool.required_connection_providers_json ? connection.provider
                  AND tool.runtime_regions_json ? %(region)s
                  AND tool.supported_data_classes_json ? %(classification)s
                  AND probe.outcome='PASSED' AND probe.expires_at > now()
                  AND tool.lifecycle='APPROVED' LIMIT 1""",
            {
                **scope.canonical_dict(),
                "connection_id": row["source_connection_id"],
                "connection_epoch": row["source_connection_epoch"],
                "source_tool_key": row["source_tool_key"],
                "source_tool_version": row["source_tool_version"],
                "source_agent_key": row["source_agent_key"],
                "source_identity_ref": row["source_identity_ref"],
                "source_capability_class": row["source_capability_class"],
                "profile_key": row["profile_key"],
                "profile_version": row["profile_version"],
                "region": row["region"],
                "classification": row["classification_ceiling"],
            },
        )
        if cursor.fetchone() is None:
            raise GuidanceError("trigger policy exact source capability proof is stale or missing")
        cursor.execute(
            """SELECT 1 FROM solvan_operability.tool_profile_revisions
                WHERE profile_key=%(profile_key)s AND version=%(profile_version)s
                  AND lifecycle='APPROVED' AND runtime_region=%(region)s""",
            {
                "profile_key": row["profile_key"],
                "profile_version": row["profile_version"],
                "region": row["region"],
            },
        )
        if cursor.fetchone() is None:
            raise GuidanceError("trigger policy investigation profile is unavailable")
        if row["guidance_key"] is not None:
            cursor.execute(
                """SELECT 1 FROM solvan_operability.guidance_revisions
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND guidance_key=%(guidance_key)s AND version=%(guidance_version)s
                      AND lifecycle='APPROVED'""",
                {
                    **scope.canonical_dict(),
                    "guidance_key": row["guidance_key"],
                    "guidance_version": row["guidance_version"],
                },
            )
            if cursor.fetchone() is None:
                raise GuidanceError("trigger policy guidance revision is unavailable")

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
                raise GuidanceError("required trigger-policy role is inactive")

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
            raise GuidanceError("decision request ID was already used for other material")

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
