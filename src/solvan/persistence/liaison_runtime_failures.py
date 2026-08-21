"""Small fail-closed persistence helpers for invalid turn material."""

from __future__ import annotations

from typing import Any

from psycopg import Connection

from solvan.domain import Scope


def fail_invalid_manifest(connection: Connection[Any], *, scope: Scope, message_id: str) -> None:
    connection.execute(
        """UPDATE solvan_liaison.liaison_turns
              SET status='FAILED',terminal_reason='MANIFEST_INVALID',
                  started_at=COALESCE(started_at,now()),ended_at=now()
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND message_id=%(message_id)s
              AND status='READY'""",
        {**scope.canonical_dict(), "message_id": message_id},
    )
    connection.execute(
        """UPDATE solvan_liaison.liaison_messages SET turn_state='FAILED',completed_at=now()
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND id=%(message_id)s""",
        {**scope.canonical_dict(), "message_id": message_id},
    )
    # Terminalizing the READY turn empties the single lane. Without draining it
    # here the rest of the thread's queue is stranded forever: the drain loop
    # sees no claim and stops, and only terminal completion, interrupt and the
    # RUNNING reaper ever promote. A failed turn must not silence the thread.
    # Imported here because liaison_turn_control imports liaison_runtime, which
    # imports this module: a top-level import closes that cycle.
    from solvan.persistence.liaison_turn_control import promote_next_turn

    thread = connection.execute(
        """SELECT thread_id FROM solvan_liaison.liaison_turns
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND message_id=%(message_id)s""",
        {**scope.canonical_dict(), "message_id": message_id},
    ).fetchone()
    if thread is not None:
        promote_next_turn(connection, scope=scope, thread_id=str(thread[0]))
