"""Execution Agent invocation binding for the private actuator boundary."""

from __future__ import annotations

from typing import Any

from psycopg import Connection

from solvan.domain import ActionPolicyError, Scope


class ActionInvocationMixin:
    _connection: Connection[Any]

    def bound_scope(self) -> Scope:
        """Derive actuator scope from its immutable database-role binding."""

        row = self._connection.execute(
            """SELECT organization_id,project_id,environment_id
                 FROM solvan.database_scope_bindings
                WHERE database_role=current_user"""
        ).fetchone()
        if row is None:
            raise ActionPolicyError("actuator_database_identity_has_no_scope")
        return Scope(str(row[0]), str(row[1]), str(row[2]))

    def require_execution_invocation(
        self,
        *,
        scope: Scope,
        invocation_id: str,
        action_id: str,
    ) -> None:
        """Bind an Execution Agent tool call to its stored action and workflow."""

        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.agent_runs r SET status = 'RUNNING'
                  FROM solvan.actions a, solvan.incidents i
                  WHERE r.organization_id = %(organization_id)s
                    AND r.project_id = %(project_id)s
                    AND r.environment_id = %(environment_id)s
                    AND r.invocation_id = %(invocation_id)s
                    AND r.agent_key = 'execution-agent'
                    AND r.action_id = %(action_id)s
                    AND r.status IN ('DISPATCHED','RUNNING') AND r.deadline > now()
                    AND a.organization_id = r.organization_id
                    AND a.project_id = r.project_id
                    AND a.environment_id = r.environment_id
                    AND a.id = r.action_id AND a.status = 'AUTHORIZED'
                    AND i.organization_id = a.organization_id
                    AND i.project_id = a.project_id
                    AND i.environment_id = a.environment_id
                    AND i.id = a.incident_id AND i.state = 'MITIGATING'
                    AND i.workflow_version = r.workflow_version
                    AND a.workflow_version = r.workflow_version
                  RETURNING r.id""",
                {
                    **scope.canonical_dict(),
                    "invocation_id": invocation_id,
                    "action_id": action_id,
                },
            )
            if cursor.fetchone() is None:
                raise ActionPolicyError("execution_invocation_not_bound_to_action")
