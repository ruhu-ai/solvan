"""The catch-up brief: a diff over committed rows, with no model in the path.

"What happened while I was away" is the question most often asked and most
easily got wrong, because the tempting implementation is to summarize. This one
cannot: it selects committed events after a cursor, filters them by the reader's
authority, and renders each through a per-event phrase stored with the event.

Two properties carry the weight. Events are ordered by a scope-local sequence,
so an anchor spanning several entities has one total order even when their
workflow versions overlap. And hidden events are neither shown nor counted —
the cursor advances across them, so their existence is not derivable from a
remainder that does not add up.

Specification 14 §6 and §17.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.liaison.anchors import Anchor, AnchorKind
from solvan.domain import Scope
from solvan.persistence.liaison_sequence import Cursor, allocate_scope_sequence

#: Deltas per brief. More than this and the brief says how many remain, so a
#: long absence never silently truncates into a plausible-looking summary.
CATCHUP_MAX_DELTAS = 50


@dataclass(frozen=True, slots=True)
class Delta:
    """One committed event, in the reader's terms."""

    sequence: int
    record_type: str
    record_id: str
    phrase: str
    authority_status: str
    classification: str
    reference: str | None
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class CatchUp:
    deltas: tuple[Delta, ...]
    cursor: Cursor
    remaining: int
    #: Set when the reader's authority changed since the cursor was issued.
    policy_changed: bool = False


def record_event(
    connection: Connection[Any],
    *,
    scope: Scope,
    record_type: str,
    record_id: str,
    event_key: str,
    phrase: str,
    authority_status: str,
    reference: str | None,
    occurred_at: datetime,
) -> int | None:
    """Order one committed event, or leave an existing one alone.

    The sequence is allocated inside the caller's transaction, so a rollback
    leaves an inert gap rather than a visible event. Re-recording the same
    `event_key` is a no-op, which is what makes syncing from a projection safe
    to repeat.
    """

    existing = connection.execute(
        """SELECT scope_sequence FROM solvan_liaison.liaison_scope_events
           WHERE organization_id = %(organization_id)s
             AND project_id = %(project_id)s
             AND environment_id = %(environment_id)s
             AND record_type = %(record_type)s AND record_id = %(record_id)s
             AND event_key = %(event_key)s""",
        {
            **scope.canonical_dict(),
            "record_type": record_type,
            "record_id": record_id,
            "event_key": event_key,
        },
    ).fetchone()
    if existing is not None:
        return None

    sequence = allocate_scope_sequence(connection, scope=scope)
    connection.execute(
        """INSERT INTO solvan_liaison.liaison_scope_events (
              organization_id, project_id, environment_id, scope_sequence,
              record_type, record_id, event_key, phrase, authority_status,
              reference, occurred_at)
           VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
              %(sequence)s, %(record_type)s, %(record_id)s, %(event_key)s,
              %(phrase)s, %(authority_status)s, %(reference)s, %(occurred_at)s)
           ON CONFLICT DO NOTHING""",
        {
            **scope.canonical_dict(),
            "sequence": sequence,
            "record_type": record_type,
            "record_id": record_id,
            "event_key": event_key,
            "phrase": phrase,
            "authority_status": authority_status,
            "reference": reference,
            "occurred_at": occurred_at,
        },
    )
    connection.execute(
        """UPDATE solvan_liaison.liaison_subscriptions
              SET next_delivery_at = least(
                    coalesce(next_delivery_at, %(occurred_at)s), %(occurred_at)s)
            WHERE organization_id = %(organization_id)s
              AND project_id = %(project_id)s
              AND environment_id = %(environment_id)s
              AND status = 'ACTIVE' AND cadence = 'ON_EVENT'
              AND anchor_kind = 'RECORD'
              AND anchor_record_type = %(record_type)s
              AND anchor_record_id = %(record_id)s
              AND (expires_at IS NULL OR expires_at > %(occurred_at)s)""",
        {
            **scope.canonical_dict(),
            "record_type": record_type,
            "record_id": record_id,
            "occurred_at": occurred_at,
        },
    )
    return sequence


def _entity_filter(anchor: Anchor) -> tuple[str, dict[str, Any]]:
    """Restrict events to the anchor's entity set.

    A record anchor reaches itself and anything the directory attributes to it;
    a service anchor reaches that service; a scope anchor reaches everything the
    reader is allowed to see, which the authority filter then narrows.
    """

    if anchor.kind is AnchorKind.RECORD:
        # The anchor itself, plus one hop of the record graph in either
        # direction. Children matter because an incident's evidence and actions
        # are where its news actually happens; the parent matters because an
        # action's incident moving on is news about the action. The hop is
        # bounded at one so a brief cannot walk the whole estate, and authority
        # is still applied per event afterwards — an edge carries context, never
        # permission.
        return (
            """ AND (
                  (e.record_type = %(anchor_record_type)s::text
                     AND e.record_id = %(anchor_record_id)s::text)
                  OR EXISTS (
                    SELECT 1 FROM solvan_liaison.liaison_record_edges g
                    WHERE g.organization_id = e.organization_id
                      AND g.project_id = e.project_id
                      AND g.environment_id = e.environment_id
                      AND ((g.parent_type = %(anchor_record_type)s::text
                              AND g.parent_id = %(anchor_record_id)s::text
                              AND g.child_type = e.record_type
                              AND g.child_id = e.record_id)
                           OR (g.child_type = %(anchor_record_type)s::text
                              AND g.child_id = %(anchor_record_id)s::text
                              AND g.parent_type = e.record_type
                              AND g.parent_id = e.record_id)))
                )""",
            {
                "anchor_record_type": anchor.record_type,
                "anchor_record_id": anchor.record_id,
            },
        )
    if anchor.kind is AnchorKind.SERVICE_WINDOW:
        return (
            """ AND EXISTS (
                  SELECT 1 FROM solvan_liaison.liaison_record_directory d
                  WHERE d.organization_id = e.organization_id
                    AND d.project_id = e.project_id
                    AND d.environment_id = e.environment_id
                    AND d.record_type = e.record_type AND d.record_id = e.record_id
                    AND d.service_key = %(anchor_service_key)s::text)
                AND e.occurred_at >= %(window_start)s
                AND e.occurred_at < %(window_end)s""",
            {
                "anchor_service_key": anchor.service_key,
                "window_start": anchor.window_start,
                "window_end": anchor.window_end,
            },
        )
    return ("", {})


def catch_up(
    connection: Connection[Any],
    *,
    scope: Scope,
    anchor: Anchor,
    cursor: Cursor,
    authorized_records: Sequence[tuple[str, str]],
    policy_epoch: int,
    limit: int = CATCHUP_MAX_DELTAS,
) -> CatchUp:
    """Return committed deltas after the cursor, for this reader only."""

    if cursor.policy_epoch != policy_epoch:
        # The reader's authority changed, so a position computed under the old
        # snapshot cannot be trusted to have skipped only what it should have.
        # Restart conservatively rather than replay history they may now see.
        return CatchUp(
            deltas=(),
            cursor=Cursor(cursor.scope_sequence, policy_epoch),
            remaining=0,
            policy_changed=True,
        )

    clause, parameters = _entity_filter(anchor)
    authorized = set(authorized_records)

    with connection.cursor(row_factory=dict_row) as db:
        db.execute(
            f"""SELECT e.*,d.classification
                  FROM solvan_liaison.liaison_scope_events e
                  JOIN solvan_liaison.liaison_record_directory d ON
                    (d.organization_id,d.project_id,d.environment_id,
                     d.record_type,d.record_id)=
                    (e.organization_id,e.project_id,e.environment_id,
                     e.record_type,e.record_id)
                WHERE e.organization_id = %(organization_id)s
                  AND e.project_id = %(project_id)s
                  AND e.environment_id = %(environment_id)s
                  AND e.scope_sequence > %(since)s
                  {clause}
                ORDER BY e.scope_sequence""",
            {**scope.canonical_dict(), **parameters, "since": cursor.scope_sequence},
        )
        rows = db.fetchall()

    deltas: list[Delta] = []
    high_water = cursor.scope_sequence
    remaining = 0
    for row in rows:
        high_water = max(high_water, int(row["scope_sequence"]))
        if (str(row["record_type"]), str(row["record_id"])) not in authorized:
            # Advance past it without counting it: a remainder that included
            # hidden events would disclose that they exist.
            continue
        if len(deltas) >= limit:
            remaining += 1
            continue
        deltas.append(
            Delta(
                sequence=int(row["scope_sequence"]),
                record_type=str(row["record_type"]),
                record_id=str(row["record_id"]),
                phrase=str(row["phrase"]),
                authority_status=str(row["authority_status"]),
                classification=str(row["classification"]),
                reference=None if row["reference"] is None else str(row["reference"]),
                occurred_at=row["occurred_at"],
            )
        )

    # When the page is full the cursor stops at the last delivered delta, so the
    # remainder is fetched next time rather than skipped.
    if remaining:
        high_water = deltas[-1].sequence if deltas else cursor.scope_sequence
    return CatchUp(
        deltas=tuple(deltas),
        cursor=Cursor(high_water, policy_epoch),
        remaining=remaining,
    )
