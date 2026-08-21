"""Retention and recovery: the two jobs that run when nobody is asking.

Both are here rather than in the turn service because neither belongs to a
turn. Purge answers "this is past its retention, everywhere it landed"; the
reaper answers "this turn's lease expired and no model may run again for it".
A turn service that also owned them would grow a second lifetime it never
observes.

Specification 14 §11.1 and §12.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from psycopg import Connection

from apps.api.liaison_reader import SnapshotProjectionReader
from solvan.domain import Scope, new_identifier


def purge_due_messages(
    connection: Connection[Any], *, scope: Scope, now: datetime | None = None
) -> int:
    """Purge transcript bodies past their retention, everywhere they landed.

    Retention that clears the transcript and leaves the same words in an
    attachment, or in the payload that was pushed to Slack, has not retained
    anything — it has moved the copy. So a purge covers every place a message's
    content came to rest: its parts, the audience lists and access rows that
    describe them, its attachments, and the payloads of anything delivered from
    it. Refs that live outside this database become a purge job rather than
    being quietly forgotten.

    A legal hold is the only extension; a held message is skipped rather than
    silently retained without a reason (§11.1).
    """

    moment = now or datetime.now(UTC)
    rows = connection.execute(
        """SELECT id FROM solvan_liaison.liaison_messages
           WHERE organization_id = %(organization_id)s
             AND project_id = %(project_id)s
             AND environment_id = %(environment_id)s
             AND deleted_at IS NULL AND legal_hold_ref IS NULL
             AND purge_after <= %(now)s""",
        {**scope.canonical_dict(), "now": moment},
    ).fetchall()
    for (message_id,) in rows:
        _purge_derived_compactions(connection, scope=scope, source_message_id=message_id)
        _purge_external_copies(connection, scope=scope, message_id=message_id)
        # Audience lists name people against a part; they go before the part
        # they describe, both because the foreign key demands it and because a
        # list of who could read a purged body is itself the body's metadata.
        connection.execute(
            """DELETE FROM solvan_liaison.liaison_part_audience_principals
               WHERE organization_id = %(organization_id)s
                 AND project_id = %(project_id)s
                 AND environment_id = %(environment_id)s
                 AND part_id IN (SELECT id FROM solvan_liaison.liaison_message_parts
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND message_id = %(message_id)s)""",
            {**scope.canonical_dict(), "message_id": message_id},
        )
        connection.execute(
            """DELETE FROM solvan_liaison.liaison_part_access
               WHERE organization_id = %(organization_id)s
                 AND project_id = %(project_id)s
                 AND environment_id = %(environment_id)s
                 AND part_id IN (SELECT id FROM solvan_liaison.liaison_message_parts
                    WHERE organization_id = %(organization_id)s
                      AND project_id = %(project_id)s
                      AND environment_id = %(environment_id)s
                      AND message_id = %(message_id)s)""",
            {**scope.canonical_dict(), "message_id": message_id},
        )
        connection.execute(
            """DELETE FROM solvan_liaison.liaison_message_parts
               WHERE organization_id = %(organization_id)s
                 AND project_id = %(project_id)s
                 AND environment_id = %(environment_id)s AND message_id = %(message_id)s""",
            {**scope.canonical_dict(), "message_id": message_id},
        )
        # The header survives as a tombstone: the fact that something was said
        # is audit, even when the words are gone.
        connection.execute(
            """UPDATE solvan_liaison.liaison_messages SET deleted_at = now()
               WHERE organization_id = %(organization_id)s
                 AND project_id = %(project_id)s
                 AND environment_id = %(environment_id)s AND id = %(message_id)s""",
            {**scope.canonical_dict(), "message_id": message_id},
        )
    return len(rows)


def _purge_derived_compactions(
    connection: Connection[Any], *, scope: Scope, source_message_id: str
) -> None:
    """Remove summaries derived from a body before that source is tombstoned."""

    rows = connection.execute(
        """SELECT DISTINCT p.id,p.message_id
             FROM solvan_liaison.liaison_compaction_sources s
             JOIN solvan_liaison.liaison_message_parts p ON
               (p.organization_id,p.project_id,p.environment_id,p.id)=
               (s.organization_id,s.project_id,s.environment_id,s.compaction_part_id)
            WHERE s.organization_id=%(organization_id)s
              AND s.project_id=%(project_id)s AND s.environment_id=%(environment_id)s
              AND s.source_message_id=%(source_message_id)s""",
        {**scope.canonical_dict(), "source_message_id": source_message_id},
    ).fetchall()
    for part_id, message_id in rows:
        _purge_compaction_part(
            connection, scope=scope, part_id=str(part_id), message_id=str(message_id)
        )


def invalidate_compactions_for_record(
    connection: Connection[Any],
    *,
    scope: Scope,
    record_type: str,
    record_id: str,
) -> int:
    """Remove compactions whose source transcript cites a changed record.

    A source correction or supersession is not a retention event: the original
    transcript remains auditable, but a summary derived from it is no longer a
    valid context projection.  Reusing the same deletion order as retention
    ensures no stale summary is selectable between the source event and the
    next compile.  The caller must run this in the same transaction as the
    committed source-event mirror.
    """

    rows = connection.execute(
        """SELECT DISTINCT compact_part.id, compact_message.id
             FROM solvan_liaison.liaison_compaction_sources source
             JOIN solvan_liaison.liaison_message_parts source_part ON
               (source_part.organization_id,source_part.project_id,
                source_part.environment_id,source_part.message_id)=
               (source.organization_id,source.project_id,
                source.environment_id,source.source_message_id)
             JOIN solvan_liaison.liaison_part_access access ON
               (access.organization_id,access.project_id,access.environment_id,
                access.part_id)=
               (source_part.organization_id,source_part.project_id,
                source_part.environment_id,source_part.id)
             JOIN solvan_liaison.liaison_message_parts compact_part ON
               (compact_part.organization_id,compact_part.project_id,
                compact_part.environment_id,compact_part.id)=
               (source.organization_id,source.project_id,
                source.environment_id,source.compaction_part_id)
             JOIN solvan_liaison.liaison_messages compact_message ON
               (compact_message.organization_id,compact_message.project_id,
                compact_message.environment_id,compact_message.id)=
               (compact_part.organization_id,compact_part.project_id,
                compact_part.environment_id,compact_part.message_id)
            WHERE source.organization_id=%(organization_id)s
              AND source.project_id=%(project_id)s
              AND source.environment_id=%(environment_id)s
              AND access.record_type=%(record_type)s
              AND access.record_id=%(record_id)s
              AND compact_part.kind='compaction'
              AND compact_part.status='COMPLETED'
              AND compact_message.deleted_at IS NULL""",
        {
            **scope.canonical_dict(),
            "record_type": record_type,
            "record_id": record_id,
        },
    ).fetchall()
    for part_id, message_id in rows:
        _purge_compaction_part(
            connection, scope=scope, part_id=str(part_id), message_id=str(message_id)
        )
    if rows:
        connection.execute(
            """INSERT INTO solvan.audit_events
                 (organization_id,project_id,environment_id,id,stream_type,stream_id,
                  event_type,actor_principal,input_refs_json,payload_hash)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                 'LIAISON_SCOPE',%(record_ref)s,'TranscriptCompactionInvalidated',
                 'service:liaison-maintenance',%(input_refs)s,%(payload_hash)s)""",
            {
                **scope.canonical_dict(),
                "id": new_identifier("aud"),
                "record_ref": f"{record_type}:{record_id}",
                "input_refs": json.dumps(
                    [f"{record_type}:{record_id}", *(str(row[0]) for row in rows)]
                ),
                "payload_hash": "sha256:"
                + hashlib.sha256(
                    f"{record_type}:{record_id}:{','.join(str(row[0]) for row in rows)}".encode()
                ).hexdigest(),
            },
        )
    return len(rows)


def _purge_compaction_part(
    connection: Connection[Any], *, scope: Scope, part_id: str, message_id: str
) -> None:
    """Delete one derived part and its tombstoned message in FK-safe order."""

    connection.execute(
        """DELETE FROM solvan_liaison.liaison_part_audience_principals
            WHERE organization_id=%(organization_id)s
              AND project_id=%(project_id)s AND environment_id=%(environment_id)s
              AND part_id=%(part_id)s""",
        {**scope.canonical_dict(), "part_id": part_id},
    )
    connection.execute(
        """DELETE FROM solvan_liaison.liaison_part_access
            WHERE organization_id=%(organization_id)s
              AND project_id=%(project_id)s AND environment_id=%(environment_id)s
              AND part_id=%(part_id)s""",
        {**scope.canonical_dict(), "part_id": part_id},
    )
    connection.execute(
        """DELETE FROM solvan_liaison.liaison_message_parts
            WHERE organization_id=%(organization_id)s
              AND project_id=%(project_id)s AND environment_id=%(environment_id)s
              AND id=%(part_id)s""",
        {**scope.canonical_dict(), "part_id": part_id},
    )
    connection.execute(
        """UPDATE solvan_liaison.liaison_messages SET deleted_at=now()
            WHERE organization_id=%(organization_id)s
              AND project_id=%(project_id)s AND environment_id=%(environment_id)s
              AND id=%(message_id)s""",
        {**scope.canonical_dict(), "message_id": message_id},
    )


def _purge_external_copies(connection: Connection[Any], *, scope: Scope, message_id: str) -> None:
    """Tombstone every copy of this message that lives outside the transcript.

    Object storage and channel providers are not reachable from a transaction,
    so what this can do in-band is mark the rows and enqueue the refs. The
    marking is what matters for correctness: an attachment with `deleted_at`
    set and a delivery with `payload_purged_at` set are no longer fetchable
    bodies, whatever the object store has yet to catch up on.
    """

    attachments = connection.execute(
        """UPDATE solvan_liaison.liaison_attachments SET deleted_at = now()
           WHERE organization_id = %(organization_id)s
             AND project_id = %(project_id)s
             AND environment_id = %(environment_id)s
             AND message_id = %(message_id)s AND deleted_at IS NULL
           RETURNING object_ref""",
        {**scope.canonical_dict(), "message_id": message_id},
    ).fetchall()
    deliveries = connection.execute(
        """UPDATE solvan_liaison.liaison_deliveries SET payload_purged_at = now()
           WHERE organization_id = %(organization_id)s
             AND project_id = %(project_id)s
             AND environment_id = %(environment_id)s
             AND source_message_id = %(message_id)s AND payload_purged_at IS NULL
           RETURNING payload_ref""",
        {**scope.canonical_dict(), "message_id": message_id},
    ).fetchall()

    # Provider Sessions and compiled-context caches are disposable projections
    # of a turn, but their keys must still be explicitly invalidated. The
    # immutable manifest and provider-request rows remain audit history; the
    # purge job carries only their opaque hashes/IDs to the external deleter.
    projection_rows = connection.execute(
        """SELECT DISTINCT m.manifest_hash, t.model_session_ref, m.context_digest
             FROM solvan_liaison.liaison_turn_input_manifests m
             JOIN solvan_liaison.liaison_turns t ON
               (t.organization_id,t.project_id,t.environment_id,t.message_id,t.attempt,t.generation)=
               (m.organization_id,m.project_id,m.environment_id,m.message_id,m.attempt,m.generation)
            WHERE m.organization_id=%(organization_id)s
              AND m.project_id=%(project_id)s
              AND m.environment_id=%(environment_id)s
              AND m.message_id=%(message_id)s""",
        {**scope.canonical_dict(), "message_id": message_id},
    ).fetchall()
    object_refs = [str(row[0]) for row in attachments] + [str(row[0]) for row in deliveries]
    manifest_hashes = [str(row[0]) for row in projection_rows if row[0]]
    session_refs = [str(row[1]) for row in projection_rows if row[1]]
    context_digests = [str(row[2]) for row in projection_rows if row[2]]
    if not object_refs and not manifest_hashes and not session_refs and not context_digests:
        return
    target_kinds: list[str] = []
    if object_refs:
        target_kinds.extend(("ATTACHMENT", "DELIVERY_PAYLOAD"))
    if manifest_hashes:
        target_kinds.append("MANIFEST")
    if session_refs:
        target_kinds.append("MANAGED_SESSION")
    if context_digests:
        target_kinds.append("CONTEXT_CACHE")
    connection.execute(
        """INSERT INTO solvan_liaison.liaison_purge_jobs (
              organization_id, project_id, environment_id, id, message_id,
              targets_json, target_kinds, deadline_at, status)
           VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
              %(id)s, %(message_id)s, %(targets)s,
              %(target_kinds)s::text[],
              now() + interval '30 days', 'PENDING')""",
        {
            **scope.canonical_dict(),
            "id": new_identifier("prg"),
            "message_id": message_id,
            "targets": json.dumps(
                {
                    "object_refs": object_refs,
                    "manifest_hashes": manifest_hashes,
                    "session_refs": session_refs,
                    "context_digests": context_digests,
                },
                sort_keys=True,
            ),
            "target_kinds": target_kinds,
        },
    )


def reap_expired_turns(connection: Connection[Any], *, scope: Scope) -> Sequence[str]:
    """Finalize turns whose lease expired. Never re-invokes a model.

    Only `RUNNING` turns are eligible: a `PARKED` turn holds no lease and may
    wait for a person indefinitely.
    """

    rows = connection.execute(
        """UPDATE solvan_liaison.liaison_turns
           SET status = 'INTERRUPTED', ended_at = now(),
               terminal_reason = 'LEASE_EXPIRED', lease_owner = NULL,
               lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL
           WHERE organization_id = %(organization_id)s
             AND project_id = %(project_id)s
             AND environment_id = %(environment_id)s
             AND status = 'RUNNING' AND lease_expires_at < now()
           RETURNING message_id,thread_id,attempt,generation""",
        scope.canonical_dict(),
    ).fetchall()
    from solvan.persistence.liaison_stream import append_stream_event
    from solvan.persistence.liaison_turn_control import promote_next_turn

    for message_id, thread_id, attempt, generation in rows:
        connection.execute(
            """UPDATE solvan_liaison.liaison_messages
               SET turn_state = 'INTERRUPTED', completed_at = now()
               WHERE organization_id = %(organization_id)s
                 AND project_id = %(project_id)s
                 AND environment_id = %(environment_id)s AND id = %(message_id)s""",
            {**scope.canonical_dict(), "message_id": message_id},
        )
        append_stream_event(
            connection,
            scope=scope,
            thread_id=str(thread_id),
            event_type="turn.interrupted",
            message_id=str(message_id),
            attempt=int(attempt),
            generation=int(generation),
            payload={"state": "INTERRUPTED", "terminal_reason": "LEASE_EXPIRED"},
        )
        promote_next_turn(connection, scope=scope, thread_id=str(thread_id))
    return [str(row[0]) for row in rows]


#: How a timeline entry's committed state maps to what may be claimed about it.
#: A restated hypothesis travels as MODEL_PROPOSED so a brief can never dress it
#: as a verified fact (§6).
_AUTHORITY_BY_STATE = {
    "MITIGATED": "RECONCILED",
    "RESOLVED": "VERIFIED",
    "CLOSED": "VERIFIED",
    "ROOT_CAUSE_CONFIRMED": "CONFIRMED",
    "VERIFYING_MITIGATION": "RECONCILED",
    "DETECTED": "OBSERVED",
}


def sync_scope_events(
    connection: Connection[Any], *, scope: Scope, reader: SnapshotProjectionReader
) -> int:
    """Order the projection's committed events, idempotently.

    Repeating this is safe: an event already carrying a sequence keeps it, so a
    brief never renumbers history under a reader who is mid-catch-up.
    """

    from solvan.persistence.liaison_catchup import record_event

    ordered = 0
    for record_type, record_id in sorted(reader.authorized_records()):
        if record_type != "incident":
            continue
        record = reader.read(record_type, record_id) or {}
        for entry in record.get("timeline", []) or []:
            if not isinstance(entry, dict):
                continue
            state = str(entry.get("state", "")).split(" ")[0].upper()
            allocated = record_event(
                connection,
                scope=scope,
                record_type=record_type,
                record_id=record_id,
                event_key=f"{entry.get('time', '')}-{entry.get('event', '')}"[:200],
                phrase=f"{entry.get('actor', 'Solvan')}: {entry.get('event', '')}",
                authority_status=_AUTHORITY_BY_STATE.get(state, "OBSERVED"),
                reference=str(entry.get("state", "")) or None,
                occurred_at=datetime.now(UTC),
            )
            if allocated is not None:
                invalidate_compactions_for_record(
                    connection,
                    scope=scope,
                    record_type=record_type,
                    record_id=record_id,
                )
                ordered += 1
    return ordered
