"""Coordinator-owned evaluation of selected Operational Guidance steps."""

from __future__ import annotations

from typing import Any

from psycopg import Connection

from solvan.application.operational_guidance import GuidanceError
from solvan.domain import Scope
from solvan.persistence import PostgresOperationalGuidanceStore


def advance_guidance_steps(
    connection: Connection[Any], *, scope: Scope, maximum_items: int = 100
) -> int:
    """Evaluate committed predicates; prerequisites remain pending without error state."""

    store = PostgresOperationalGuidanceStore(connection)
    with connection.transaction():
        pending = store.pending_steps(scope=scope, maximum_items=maximum_items)
    evaluated = 0
    for selection_id, step_key in pending:
        try:
            with connection.transaction():
                verdict = store.evaluate_step(
                    scope=scope, selection_id=selection_id, step_key=step_key
                )
        except GuidanceError as error:
            connection.rollback()
            if str(error) == "guidance step prerequisites are not satisfied":
                continue
            raise
        if verdict.created:
            evaluated += 1
    return evaluated
