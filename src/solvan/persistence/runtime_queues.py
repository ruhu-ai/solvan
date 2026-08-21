"""Cloud SQL queries for Runtime work that is ready to reserve."""

from __future__ import annotations

from typing import Any

from psycopg import Connection

from solvan.domain import Scope


class RuntimeQueueMixin:
    _connection: Connection[Any]

    def incidents_needing_supervisor(
        self, *, scope: Scope, batch_size: int = 10
    ) -> tuple[str, ...]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT i.id FROM solvan.incidents i
                  WHERE i.organization_id = %(organization_id)s
                    AND i.project_id = %(project_id)s
                    AND i.environment_id = %(environment_id)s
                    AND i.state = 'INVESTIGATING'
                    AND NOT EXISTS (
                      SELECT 1 FROM solvan.agent_runs r
                      WHERE r.organization_id = i.organization_id
                        AND r.project_id = i.project_id
                        AND r.environment_id = i.environment_id
                        AND r.incident_id = i.id
                        AND r.agent_key = 'incident-supervisor'
                        AND r.workflow_version = i.workflow_version
                        AND r.status IN ('CREATED','DISPATCHED','RUNNING','SUCCEEDED'))
                  ORDER BY i.detected_at LIMIT %(batch_size)s""",
                {**scope.canonical_dict(), "batch_size": batch_size},
            )
            return tuple(str(row[0]) for row in cursor.fetchall())

    def actions_needing_execution(
        self, *, scope: Scope, batch_size: int = 10
    ) -> tuple[tuple[str, str], ...]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT a.id, i.id AS incident_id FROM solvan.actions a
                  JOIN solvan.incidents i
                    ON (i.organization_id, i.project_id, i.environment_id, i.id)
                     = (a.organization_id, a.project_id, a.environment_id,
                        a.incident_id)
                  WHERE a.organization_id = %(organization_id)s
                    AND a.project_id = %(project_id)s
                    AND a.environment_id = %(environment_id)s
                    AND a.status = 'AUTHORIZED' AND a.expires_at > now()
                    AND i.state = 'MITIGATING'
                    AND a.workflow_version = i.workflow_version
                    AND NOT EXISTS (
                      SELECT 1 FROM solvan.agent_runs r
                      WHERE r.organization_id = a.organization_id
                        AND r.project_id = a.project_id
                        AND r.environment_id = a.environment_id
                        AND r.action_id = a.id)
                  ORDER BY a.created_at, a.id LIMIT %(batch_size)s""",
                {**scope.canonical_dict(), "batch_size": batch_size},
            )
            return tuple((str(row[0]), str(row[1])) for row in cursor.fetchall())

    def actions_needing_verification(
        self, *, scope: Scope, batch_size: int = 10
    ) -> tuple[tuple[str, str], ...]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT a.id, i.id AS incident_id FROM solvan.actions a
                  JOIN solvan.incidents i
                    ON (i.organization_id, i.project_id, i.environment_id, i.id)
                     = (a.organization_id, a.project_id, a.environment_id,
                        a.incident_id)
                  JOIN solvan.verification_profiles vp
                    ON (vp.organization_id, vp.project_id, vp.environment_id,
                        vp.id, vp.version)
                     = (a.organization_id, a.project_id, a.environment_id,
                        a.verification_profile_id, a.verification_profile_version)
                  JOIN solvan.execution_receipts er
                    ON er.organization_id = a.organization_id
                   AND er.project_id = a.project_id
                   AND er.environment_id = a.environment_id
                   AND er.action_id = a.id AND er.result = 'SUCCEEDED'
                  WHERE a.organization_id = %(organization_id)s
                    AND a.project_id = %(project_id)s
                    AND a.environment_id = %(environment_id)s
                    AND a.status = 'SUCCEEDED' AND i.state = 'VERIFYING_MITIGATION'
                    AND vp.status = 'APPROVED'
                    AND er.reconciled_at
                      + ((vp.warmup_ms + vp.observation_ms) * interval '1 millisecond')
                      <= now()
                    AND NOT EXISTS (
                      SELECT 1 FROM solvan.agent_runs r
                      WHERE r.organization_id = a.organization_id
                        AND r.project_id = a.project_id
                        AND r.environment_id = a.environment_id
                        AND r.action_id = a.id AND r.agent_key = 'verification-agent')
                    AND NOT EXISTS (
                      SELECT 1 FROM solvan.verification_runs v
                      WHERE v.organization_id = a.organization_id
                        AND v.project_id = a.project_id
                        AND v.environment_id = a.environment_id
                        AND v.action_id = a.id
                        AND v.purpose = 'MITIGATION_ACTION')
                  ORDER BY er.reconciled_at, a.id LIMIT %(batch_size)s""",
                {**scope.canonical_dict(), "batch_size": batch_size},
            )
            return tuple((str(row[0]), str(row[1])) for row in cursor.fetchall())
