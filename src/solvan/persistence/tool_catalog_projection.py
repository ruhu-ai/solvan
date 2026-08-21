"""Reader-safe governed Tool Catalog projection."""

from __future__ import annotations

from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.domain import Scope


class ToolCatalogProjectionMixin:
    _connection: Connection[Any]

    def projection(self, *, scope: Scope) -> dict[str, Any]:
        """Return catalog metadata without arguments, payloads, or credentials."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT d.tool_key,d.display_name,d.owner_department,r.version,
                          r.permission_class,r.implementation_kind,r.lifecycle,
                          r.registry_resource,r.gateway_destination,
                          r.model_armor_coverage,r.runtime_regions_json,
                          r.timeout_ms,r.max_input_bytes,r.max_output_bytes,
                          r.default_call_budget,r.content_hash,
                          array_agg(q.requester_key ORDER BY q.requester_key) AS agents
                     FROM solvan_operability.tool_definitions d
                     JOIN solvan_operability.tool_revisions r USING(tool_key)
                     JOIN solvan_operability.tool_revision_requesters q
                       ON (q.tool_key,q.tool_version)=(r.tool_key,r.version)
                    GROUP BY d.tool_key,d.display_name,d.owner_department,r.version,
                             r.permission_class,r.implementation_kind,r.lifecycle,
                             r.registry_resource,r.gateway_destination,
                             r.model_armor_coverage,r.runtime_regions_json,
                             r.timeout_ms,r.max_input_bytes,r.max_output_bytes,
                             r.default_call_budget,r.content_hash,r.created_at
                    ORDER BY d.display_name,r.created_at DESC"""
            )
            tools = [dict(row) for row in cursor.fetchall()]
            cursor.execute(
                """SELECT profile_key,version,purpose,allowed_agent_key,
                          maximum_total_calls,maximum_parallel_calls,
                          data_classification_ceiling,runtime_region,lifecycle,
                          profile_material_hash,created_at
                     FROM solvan_operability.tool_profile_revisions
                    ORDER BY profile_key,created_at DESC"""
            )
            profiles = [dict(row) for row in cursor.fetchall()]
            cursor.execute(
                """SELECT DISTINCT ON (connection_id,tool_key,tool_version,agent_key)
                          connection_id,connection_epoch,tool_key,tool_version,
                          agent_key,outcome,reason_code,missing_grant,observed_at,
                          expires_at,receipt_ref,trace_id
                     FROM solvan_operability.tool_probe_receipts
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                    ORDER BY connection_id,tool_key,tool_version,agent_key,
                             observed_at DESC""",
                scope.canonical_dict(),
            )
            probes = [dict(row) for row in cursor.fetchall()]
        return {"tools": tools, "profiles": profiles, "probes": probes}
