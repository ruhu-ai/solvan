"""Atomic evidence completion and failure settlement."""

from __future__ import annotations

from typing import Any

from psycopg import Connection
from psycopg.types.json import Jsonb

from solvan.domain import new_identifier
from solvan.persistence.evidence_errors import ToolAuthorizationError
from solvan.persistence.evidence_types import EvidenceToolReservation, EvidenceWrite


class EvidenceCompletionMixin:
    _connection: Connection[Any]

    def complete(
        self, *, reservation: EvidenceToolReservation, write: EvidenceWrite, output_bytes: int
    ) -> str:
        if output_bytes < 1:
            raise ToolAuthorizationError("tool output byte count is invalid")
        if output_bytes > reservation.max_output_bytes:
            raise ToolAuthorizationError("tool output exceeds its approved byte ceiling")
        evidence_id = new_identifier("evd")
        with self._connection.cursor() as cursor:
            # Lock the run before summing completed output so concurrent Tools
            # cannot each observe spare aggregate capacity and overrun it.
            cursor.execute(
                """SELECT 1 FROM solvan.agent_runs
                     WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                       AND environment_id=%(environment_id)s AND id=%(run_id)s
                     FOR UPDATE""",
                {**reservation.scope.canonical_dict(), "run_id": reservation.run_id},
            )
            if cursor.fetchone() is None:
                raise ToolAuthorizationError("agent run is unavailable for Tool completion")
            cursor.execute(
                """SELECT COALESCE(sum(output_bytes), 0) FROM solvan_operability.tool_call_receipts
                     WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                       AND environment_id=%(environment_id)s AND agent_run_id=%(run_id)s""",
                {**reservation.scope.canonical_dict(), "run_id": reservation.run_id},
            )
            aggregate = cursor.fetchone()
            if (
                aggregate is None
                or int(aggregate[0]) + output_bytes > reservation.maximum_aggregate_evidence_bytes
            ):
                raise ToolAuthorizationError("Tool profile aggregate evidence budget is exhausted")
            cursor.execute(
                """INSERT INTO solvan.evidence_items
                  (organization_id, project_id, environment_id, id, incident_id,
                   alert_episode_id,
                   source_kind, source_resource, query_spec_json, window_start,
                   window_end, observed_at, content_ref, content_hash,
                   classification, residency, redaction_manifest_ref,
                   provenance_json, freshness_expires_at, created_by_agent_run_id,
                   projection_json)
                  VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                    %(evidence_id)s, %(incident_id)s, %(alert_episode_id)s, %(source_kind)s,
                    %(source_resource)s, %(query_spec)s, %(window_start)s,
                    %(window_end)s, %(observed_at)s, %(content_ref)s,
                    %(content_hash)s, %(classification)s, %(residency)s,
                    %(redaction_manifest_ref)s, %(provenance)s,
                    %(freshness_expires_at)s, %(run_id)s, %(projection)s)""",
                {
                    **reservation.scope.canonical_dict(),
                    "evidence_id": evidence_id,
                    "incident_id": reservation.incident_id,
                    "alert_episode_id": reservation.alert_episode_id,
                    "run_id": reservation.run_id,
                    "source_kind": write.source_kind,
                    "source_resource": write.source_resource,
                    "query_spec": Jsonb(write.query_spec),
                    "window_start": write.window_start,
                    "window_end": write.window_end,
                    "observed_at": write.observed_at,
                    "content_ref": write.content_ref,
                    "content_hash": write.content_hash,
                    "projection": (Jsonb(write.projection) if write.projection else None),
                    "classification": write.classification,
                    "residency": write.residency,
                    "redaction_manifest_ref": write.redaction_manifest_ref,
                    "provenance": Jsonb(write.provenance),
                    "freshness_expires_at": write.freshness_expires_at,
                },
            )
            cursor.execute(
                """UPDATE solvan.tool_calls SET status = 'SUCCEEDED',
                    evidence_item_id = %(evidence_id)s, completed_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s AND id = %(call_id)s
                    AND status = 'RESERVED'""",
                {
                    **reservation.scope.canonical_dict(),
                    "call_id": reservation.call_id,
                    "evidence_id": evidence_id,
                },
            )
            if cursor.rowcount != 1:
                raise ToolAuthorizationError("tool call reservation is no longer live")
            cursor.execute(
                """UPDATE solvan_operability.tool_call_receipts
                      SET output_bytes=%(output_bytes)s,completed_at=now()
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND tool_call_id=%(call_id)s AND completed_at IS NULL""",
                {
                    **reservation.scope.canonical_dict(),
                    "call_id": reservation.call_id,
                    "output_bytes": output_bytes,
                },
            )
            if cursor.rowcount != 1:
                raise ToolAuthorizationError("Tool call receipt is no longer live")
            if reservation.incident_id is not None:
                cursor.execute(
                    """UPDATE solvan.incidents
                      SET evidence_version = evidence_version + 1, updated_at = now()
                      WHERE organization_id = %(organization_id)s
                        AND project_id = %(project_id)s
                        AND environment_id = %(environment_id)s
                        AND id = %(incident_id)s""",
                    {
                        **reservation.scope.canonical_dict(),
                        "incident_id": reservation.incident_id,
                    },
                )
            else:
                cursor.execute(
                    """UPDATE solvan_alerts.alert_episodes
                      SET evidence_version=evidence_version+1,
                          row_version=row_version+1,updated_at=now()
                      WHERE organization_id=%(organization_id)s
                        AND project_id=%(project_id)s
                        AND environment_id=%(environment_id)s
                        AND id=%(alert_episode_id)s""",
                    {
                        **reservation.scope.canonical_dict(),
                        "alert_episode_id": reservation.alert_episode_id,
                    },
                )
            if cursor.rowcount != 1:
                raise ToolAuthorizationError("evidence anchor version is unavailable")
        return evidence_id

    def fail(self, *, reservation: EvidenceToolReservation, error_class: str) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.tool_calls SET status = 'FAILED',
                    error_class = %(error_class)s, completed_at = now()
                  WHERE organization_id = %(organization_id)s
                    AND project_id = %(project_id)s
                    AND environment_id = %(environment_id)s AND id = %(call_id)s
                    AND status = 'RESERVED'""",
                {
                    **reservation.scope.canonical_dict(),
                    "call_id": reservation.call_id,
                    "error_class": error_class[:128],
                },
            )
            cursor.execute(
                """UPDATE solvan_operability.tool_call_receipts
                      SET output_bytes=0,completed_at=now()
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND tool_call_id=%(call_id)s AND completed_at IS NULL""",
                {**reservation.scope.canonical_dict(), "call_id": reservation.call_id},
            )
