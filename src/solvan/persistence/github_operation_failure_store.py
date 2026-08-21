"""Terminal failure transition for scoped GitHub operations."""

from __future__ import annotations

from typing import Any

from psycopg import Connection

from solvan.application.github import GitHubContractError
from solvan.domain import Scope


class GitHubOperationFailureStore:
    """Operation mixin; the concrete store supplies the scoped connection."""

    _connection: Connection[Any]

    def fail_operation(self, *, scope: Scope, operation_id: str, error_class: str) -> None:
        if not error_class or len(error_class) > 128:
            raise GitHubContractError("GitHub operation error class is invalid")
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan.github_operations
                   SET status = 'FAILED', error_class = %(error_class)s, completed_at = now()
                 WHERE organization_id = %(organization_id)s
                   AND project_id = %(project_id)s AND environment_id = %(environment_id)s
                   AND id = %(operation_id)s AND status IN ('CREATED','DISPATCHED')""",
                {
                    **scope.canonical_dict(),
                    "operation_id": operation_id,
                    "error_class": error_class,
                },
            )
