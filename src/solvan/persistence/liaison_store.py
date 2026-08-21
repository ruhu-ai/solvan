"""PostgreSQL authority for conversations: threads, messages, parts, access.

Two rules shape every method here. Parts are rows, not a rewritten JSON array,
so a streaming append cannot lose a concurrent one and a completed part is
immutable. And the access envelope is stored beside the part, so the per-reader
transcript filter is a join rather than a re-derivation — a reader sees a part
only when their authority covers every record it references.

Specification 14 §5, §11, §12.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.liaison.anchors import Anchor
from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_parts_store import LiaisonPartStoreMixin
from solvan.persistence.liaison_records import MessageRecord as MessageRecord
from solvan.persistence.liaison_records import ThreadRecord as ThreadRecord
from solvan.persistence.liaison_transcript_store import LiaisonTranscriptMixin

#: Transcript bodies outlive the conversation by a bounded window only
#: (specification 14 §11.1). The value is a default, not a constant: a tenant
#: may shorten it, and only a legal hold may extend it.
TRANSCRIPT_RETENTION_DAYS = 180


class ThreadAccessError(RuntimeError):
    """A supplied thread id is not one this principal may write to.

    Carries a reason code so the boundary can choose a status without parsing
    the message, and a message a person can act on.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class LiaisonStore(LiaisonPartStoreMixin, LiaisonTranscriptMixin):
    """Every method is scope-bound; row-level security is the second control."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    # -- record directory ---------------------------------------------------

    def sync_directory(
        self, *, scope: Scope, records: Iterable[tuple[str, str, str | None, str]]
    ) -> int:
        """Mirror the addressable records a projection currently exposes.

        The directory is what makes an anchor or a citation checkable, so it
        is refreshed from the projection rather than trusted from a caller.
        """

        written = 0
        with self._connection.cursor() as cursor:
            for record_type, record_id, service_key, classification in records:
                cursor.execute(
                    """INSERT INTO solvan_liaison.liaison_record_directory (
                          organization_id, project_id, environment_id,
                          record_type, record_id, service_key, classification)
                       VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                          %(record_type)s, %(record_id)s, %(service_key)s, %(classification)s)
                       ON CONFLICT (organization_id, project_id, environment_id,
                          record_type, record_id) DO UPDATE
                       SET service_key = EXCLUDED.service_key,
                           classification = EXCLUDED.classification""",
                    {
                        **scope.canonical_dict(),
                        "record_type": record_type,
                        "record_id": record_id,
                        "service_key": service_key,
                        "classification": classification,
                    },
                )
                written += 1
        return written

    def sync_edges(self, *, scope: Scope, edges: Iterable[tuple[str, str, str, str, str]]) -> int:
        """Mirror the parent/child graph the projection implies.

        Written after the directory, never before: both endpoints of an edge
        must already be addressable, which the foreign keys enforce. An edge
        whose endpoints have not synced yet is skipped rather than failing the
        turn — the next sync picks it up once the directory catches up.
        """

        written = 0
        with self._connection.cursor() as cursor:
            for parent_type, parent_id, child_type, child_id, relation in edges:
                cursor.execute(
                    """INSERT INTO solvan_liaison.liaison_record_edges (
                          organization_id, project_id, environment_id,
                          parent_type, parent_id, child_type, child_id, relation)
                       SELECT %(organization_id)s, %(project_id)s, %(environment_id)s,
                          %(parent_type)s, %(parent_id)s, %(child_type)s,
                          %(child_id)s, %(relation)s
                       WHERE EXISTS (SELECT 1 FROM solvan_liaison.liaison_record_directory
                            WHERE organization_id = %(organization_id)s
                              AND project_id = %(project_id)s
                              AND environment_id = %(environment_id)s
                              AND record_type = %(parent_type)s AND record_id = %(parent_id)s)
                         AND EXISTS (SELECT 1 FROM solvan_liaison.liaison_record_directory
                            WHERE organization_id = %(organization_id)s
                              AND project_id = %(project_id)s
                              AND environment_id = %(environment_id)s
                              AND record_type = %(child_type)s AND record_id = %(child_id)s)
                       ON CONFLICT DO NOTHING""",
                    {
                        **scope.canonical_dict(),
                        "parent_type": parent_type,
                        "parent_id": parent_id,
                        "child_type": child_type,
                        "child_id": child_id,
                        "relation": relation,
                    },
                )
                written += cursor.rowcount
        return written

    def record_exists(self, *, scope: Scope, record_type: str, record_id: str) -> bool:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT 1 FROM solvan_liaison.liaison_record_directory
                   WHERE organization_id = %(organization_id)s
                     AND project_id = %(project_id)s
                     AND environment_id = %(environment_id)s
                     AND record_type = %(record_type)s AND record_id = %(record_id)s""",
                {**scope.canonical_dict(), "record_type": record_type, "record_id": record_id},
            )
            return cursor.fetchone() is not None

    # -- threads ------------------------------------------------------------

    def open_thread(
        self,
        *,
        scope: Scope,
        anchor: Anchor,
        visibility: str,
        principal: str,
    ) -> str:
        """Create a thread and insert its creator as an owner participant.

        Both happen in the caller's transaction: a thread whose creator is not
        a participant would be a thread nobody could read.
        """

        thread_id = new_identifier("thr")
        payload = anchor.canonical_dict()
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan_liaison.liaison_threads (
                      organization_id, project_id, environment_id, id, anchor_kind,
                      anchor_record_type, anchor_record_id, anchor_service_key,
                      anchor_window_start, anchor_window_end, visibility, status,
                      created_by_principal)
                   VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                      %(id)s, %(anchor_kind)s, %(anchor_record_type)s,
                      %(anchor_record_id)s, %(anchor_service_key)s,
                      %(anchor_window_start)s, %(anchor_window_end)s,
                      %(visibility)s, 'OPEN', %(principal)s)""",
                {
                    **scope.canonical_dict(),
                    **payload,
                    "id": thread_id,
                    "visibility": visibility,
                    "principal": principal,
                },
            )
            cursor.execute(
                """INSERT INTO solvan_liaison.liaison_thread_participants (
                      organization_id, project_id, environment_id, thread_id,
                      principal, membership_epoch, role, added_by_principal)
                   VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                      %(thread_id)s, %(principal)s, 1, 'OWNER', %(principal)s)""",
                {**scope.canonical_dict(), "thread_id": thread_id, "principal": principal},
            )
        return thread_id

    def thread(self, *, scope: Scope, thread_id: str) -> ThreadRecord | None:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT * FROM solvan_liaison.liaison_threads
                   WHERE organization_id = %(organization_id)s
                     AND project_id = %(project_id)s
                     AND environment_id = %(environment_id)s
                     AND id = %(id)s""",
                {**scope.canonical_dict(), "id": thread_id},
            )
            row = cursor.fetchone()
        if row is None:
            return None
        from solvan.application.liaison.anchors import anchor_from_mapping

        return ThreadRecord(
            id=str(row["id"]),
            anchor=anchor_from_mapping(row),
            visibility=str(row["visibility"]),
            status=str(row["status"]),
            created_by_principal=str(row["created_by_principal"]),
            last_activity_at=row["last_activity_at"],
        )

    def threads_for_anchor(
        self,
        *,
        scope: Scope,
        anchor: Anchor,
        before: tuple[datetime, str] | None = None,
        limit: int = 50,
    ) -> tuple[ThreadRecord, ...]:
        """Threads whose anchor falls within this object's graph (§5)."""

        payload = anchor.canonical_dict()
        before_time, before_id = before or (None, None)
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT * FROM solvan_liaison.liaison_threads
                   WHERE organization_id = %(organization_id)s
                     AND project_id = %(project_id)s
                     AND environment_id = %(environment_id)s
                     AND status = 'OPEN'
                     AND (
                       (anchor_kind = 'SCOPE'
                          AND %(anchor_kind)s::text = 'SCOPE')
                       OR (%(anchor_record_id)s::text IS NOT NULL
                          AND anchor_record_id = %(anchor_record_id)s::text
                          AND anchor_record_type = %(anchor_record_type)s::text)
                       OR (%(anchor_service_key)s::text IS NOT NULL
                          AND anchor_service_key = %(anchor_service_key)s::text)
                     )
                     AND (%(anchor_service_key)s::text IS NULL OR
                          (anchor_window_start = %(anchor_window_start)s::timestamptz
                           AND anchor_window_end = %(anchor_window_end)s::timestamptz))
                     AND (%(before_time)s::timestamptz IS NULL OR
                          (last_activity_at,id) <
                          (%(before_time)s::timestamptz,%(before_id)s::text))
                   ORDER BY last_activity_at DESC, id DESC
                   LIMIT %(limit)s""",
                {
                    **scope.canonical_dict(),
                    **payload,
                    "before_time": before_time,
                    "before_id": before_id,
                    "limit": limit,
                },
            )
            rows = cursor.fetchall()
        from solvan.application.liaison.anchors import anchor_from_mapping

        return tuple(
            ThreadRecord(
                id=str(row["id"]),
                anchor=anchor_from_mapping(row),
                visibility=str(row["visibility"]),
                status=str(row["status"]),
                created_by_principal=str(row["created_by_principal"]),
                last_activity_at=row["last_activity_at"],
            )
            for row in rows
        )

    def require_writable_thread(
        self, *, scope: Scope, thread_id: str, anchor: Anchor, principal: str
    ) -> ThreadRecord:
        """The four things that must be true before anyone writes to a thread.

        A caller supplies a thread id; nothing about that id is evidence. It
        must name a thread in this scope, still open, anchored where the caller
        says it is, and one this principal actually belongs to. Without all
        four, a stranger could append a message to somebody else's conversation
        merely by guessing an identifier — and every reader of that thread would
        then see it carrying the thread's authority (§5, §10).
        """

        record = self.thread(scope=scope, thread_id=thread_id)
        if record is None:
            raise ThreadAccessError("NOT_FOUND", "thread not found in this scope")
        if record.status != "OPEN":
            raise ThreadAccessError("CLOSED", "this thread is archived and takes no new messages")
        if record.anchor.canonical_dict() != anchor.canonical_dict():
            raise ThreadAccessError("MISMATCHED", "this thread is anchored to a different record")
        if principal not in self.participants(scope=scope, thread_id=thread_id):
            raise ThreadAccessError("FORBIDDEN", "you are not a participant in this thread")
        return record

    def participants(self, *, scope: Scope, thread_id: str) -> tuple[str, ...]:
        """Currently active members. Removal ends access to the projection."""

        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT principal FROM solvan_liaison.liaison_thread_participants
                   WHERE organization_id = %(organization_id)s
                     AND project_id = %(project_id)s
                     AND environment_id = %(environment_id)s
                     AND thread_id = %(thread_id)s AND removed_at IS NULL
                   ORDER BY principal""",
                {**scope.canonical_dict(), "thread_id": thread_id},
            )
            return tuple(str(row[0]) for row in cursor.fetchall())

    def participant_epochs(self, *, scope: Scope, thread_id: str) -> dict[str, int]:
        """Current principals and the epoch at which their current membership began."""

        rows = self._connection.execute(
            """SELECT principal,membership_epoch
                 FROM solvan_liaison.liaison_thread_participants
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND thread_id=%(thread_id)s AND removed_at IS NULL""",
            {**scope.canonical_dict(), "thread_id": thread_id},
        ).fetchall()
        return {str(row[0]): int(row[1]) for row in rows}

    def participant_roles(self, *, scope: Scope, thread_id: str) -> dict[str, str]:
        rows = self._connection.execute(
            """SELECT principal,role FROM solvan_liaison.liaison_thread_participants
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND thread_id=%(thread_id)s
                  AND removed_at IS NULL ORDER BY principal""",
            {**scope.canonical_dict(), "thread_id": thread_id},
        ).fetchall()
        return {str(row[0]): str(row[1]) for row in rows}

    def add_participant(
        self,
        *,
        scope: Scope,
        thread_id: str,
        owner_principal: str,
        principal: str,
        role: str = "PARTICIPANT",
    ) -> int:
        """Append one membership epoch; only a current owner may do so."""

        self._connection.execute(
            """SELECT 1 FROM solvan_liaison.liaison_threads
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(thread_id)s FOR UPDATE""",
            {**scope.canonical_dict(), "thread_id": thread_id},
        )
        roles = self.participant_roles(scope=scope, thread_id=thread_id)
        if roles.get(owner_principal) != "OWNER":
            raise ThreadAccessError("FORBIDDEN", "only a current thread owner may add a person")
        if principal in roles:
            return self.current_membership_epoch(
                scope=scope, thread_id=thread_id, principal=principal
            )
        if role not in {"OWNER", "PARTICIPANT"}:
            raise ValueError("unsupported participant role")
        next_epoch_row = self._connection.execute(
            """SELECT COALESCE(max(membership_epoch),0)+1
                 FROM solvan_liaison.liaison_thread_participants
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND thread_id=%(thread_id)s""",
            {**scope.canonical_dict(), "thread_id": thread_id},
        ).fetchone()
        next_epoch = int(next_epoch_row[0]) if next_epoch_row else 1
        self._connection.execute(
            """INSERT INTO solvan_liaison.liaison_thread_participants (
                  organization_id,project_id,environment_id,thread_id,principal,
                  membership_epoch,role,added_by_principal)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(thread_id)s,
                  %(principal)s,%(epoch)s,%(role)s,%(owner)s)""",
            {
                **scope.canonical_dict(),
                "thread_id": thread_id,
                "principal": principal,
                "epoch": next_epoch,
                "role": role,
                "owner": owner_principal,
            },
        )
        return next_epoch

    def remove_participant(
        self, *, scope: Scope, thread_id: str, owner_principal: str, principal: str
    ) -> int:
        """End current membership without rewriting history or removing the final owner."""

        self._connection.execute(
            """SELECT 1 FROM solvan_liaison.liaison_threads
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND id=%(thread_id)s FOR UPDATE""",
            {**scope.canonical_dict(), "thread_id": thread_id},
        )
        roles = self.participant_roles(scope=scope, thread_id=thread_id)
        if roles.get(owner_principal) != "OWNER":
            raise ThreadAccessError("FORBIDDEN", "only a current thread owner may remove a person")
        removed_role = roles.get(principal)
        if removed_role is None:
            raise ThreadAccessError("NOT_FOUND", "participant is not active")
        if removed_role == "OWNER" and sum(role == "OWNER" for role in roles.values()) == 1:
            raise ThreadAccessError("CLOSED", "the final thread owner cannot be removed")
        row = self._connection.execute(
            """UPDATE solvan_liaison.liaison_thread_participants SET removed_at=now()
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND thread_id=%(thread_id)s
                  AND principal=%(principal)s AND removed_at IS NULL
              RETURNING membership_epoch""",
            {**scope.canonical_dict(), "thread_id": thread_id, "principal": principal},
        ).fetchone()
        if row is None:
            raise ThreadAccessError("NOT_FOUND", "participant is not active")
        return int(row[0])

    def current_membership_epoch(self, *, scope: Scope, thread_id: str, principal: str) -> int:
        row = self._connection.execute(
            """SELECT membership_epoch
                 FROM solvan_liaison.liaison_thread_participants
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND thread_id=%(thread_id)s AND principal=%(principal)s
                  AND removed_at IS NULL""",
            {
                **scope.canonical_dict(),
                "thread_id": thread_id,
                "principal": principal,
            },
        ).fetchone()
        if row is None:
            raise ThreadAccessError("FORBIDDEN", "principal is not a current thread participant")
        return int(row[0])

    # -- messages and parts -------------------------------------------------

    def append_message(
        self,
        *,
        scope: Scope,
        thread_id: str,
        role: str,
        classification: str,
        author_principal: str | None = None,
        in_reply_to: str | None = None,
        turn_state: str = "COMPLETED",
        retention_days: int = TRANSCRIPT_RETENTION_DAYS,
        redaction_verdict_ref: str | None = None,
        content_hash: str | None = None,
    ) -> str:
        """Write one message header. Parts follow as their own rows."""

        message_id = new_identifier("lms")
        completed = (
            datetime.now(UTC) if turn_state in {"COMPLETED", "INTERRUPTED", "FAILED"} else None
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan_liaison.liaison_messages (
                      organization_id, project_id, environment_id, id, thread_id,
                      role, author_principal, in_reply_to_message_id, classification,
                      redaction_verdict_ref, content_hash, turn_state, purge_after, completed_at)
                   VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                      %(id)s, %(thread_id)s, %(role)s, %(author_principal)s,
                      %(in_reply_to)s, %(classification)s, %(redaction_verdict_ref)s,
                      %(content_hash)s, %(turn_state)s, %(purge_after)s, %(completed_at)s)""",
                {
                    **scope.canonical_dict(),
                    "id": message_id,
                    "redaction_verdict_ref": redaction_verdict_ref,
                    "content_hash": content_hash,
                    "thread_id": thread_id,
                    "role": role,
                    "author_principal": author_principal,
                    "in_reply_to": in_reply_to,
                    "classification": classification,
                    "turn_state": turn_state,
                    "purge_after": datetime.now(UTC) + timedelta(days=retention_days),
                    "completed_at": completed,
                },
            )
            cursor.execute(
                """UPDATE solvan_liaison.liaison_threads SET last_activity_at = now()
                   WHERE organization_id = %(organization_id)s
                     AND project_id = %(project_id)s
                     AND environment_id = %(environment_id)s AND id = %(thread_id)s""",
                {**scope.canonical_dict(), "thread_id": thread_id},
            )
        return message_id
