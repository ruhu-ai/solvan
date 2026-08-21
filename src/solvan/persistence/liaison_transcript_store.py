"""Reader-filtered, cursor-paged Liaison transcript projection."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from psycopg.rows import dict_row

from solvan.application.liaison.parts import AccessMode, Part
from solvan.domain import Scope
from solvan.persistence.liaison_records import MessageRecord
from solvan.persistence.liaison_visibility import (
    reader_may_see_compaction,
    reader_may_see_row,
)


class LiaisonTranscriptMixin:
    """Transcript responsibility mixed into the scope-bound LiaisonStore."""

    _connection: Any
    participant_epochs: Any

    def transcript(
        self,
        *,
        scope: Scope,
        thread_id: str,
        reader_principal: str,
        authorized_records: Sequence[tuple[str, str]],
        limit: int = 100,
        before_id: str | None = None,
    ) -> tuple[MessageRecord, ...]:
        """One reader's projection of a thread, cursor-paged.

        The filter is applied per part, not per message, and a part the reader
        may not see is replaced by a visible placeholder rather than removed —
        absence would be its own disclosure.
        """

        from solvan.application.liaison.parts import PartKind, withheld_part

        participant_epochs = self.participant_epochs(scope=scope, thread_id=thread_id)
        authorized = set(authorized_records)

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT * FROM solvan_liaison.liaison_messages
                   WHERE organization_id = %(organization_id)s
                     AND project_id = %(project_id)s
                     AND environment_id = %(environment_id)s
                     AND thread_id = %(thread_id)s
                     AND deleted_at IS NULL
                     -- The cursor walks the insertion ordinal, which is the
                     -- only total order the database guarantees. Ordering by id
                     -- would page through ULIDs whose lexical order need not
                     -- match arrival order inside a millisecond, and ordering
                     -- by created_at would tie every message a single turn
                     -- wrote. Either can skip a message or repeat one.
                     AND (%(before_id)s::text IS NULL
                          OR stream_position < (
                            SELECT m.stream_position
                            FROM solvan_liaison.liaison_messages m
                            WHERE m.organization_id = %(organization_id)s
                              AND m.project_id = %(project_id)s
                              AND m.environment_id = %(environment_id)s
                              AND m.id = %(before_id)s::text))
                   ORDER BY stream_position DESC
                   LIMIT %(limit)s""",
                {
                    **scope.canonical_dict(),
                    "thread_id": thread_id,
                    "before_id": before_id,
                    "limit": limit,
                },
            )
            message_rows = list(reversed(cursor.fetchall()))

            messages: list[MessageRecord] = []
            for row in message_rows:
                cursor.execute(
                    """SELECT p.*, coalesce(array_agg(
                            a.record_type || ':' || a.record_id
                            ORDER BY a.record_type, a.record_id)
                            FILTER (WHERE a.record_type IS NOT NULL), '{}') AS access
                       FROM solvan_liaison.liaison_message_parts p
                       LEFT JOIN solvan_liaison.liaison_part_access a
                         ON (a.organization_id, a.project_id, a.environment_id, a.part_id)
                          = (p.organization_id, p.project_id, p.environment_id, p.id)
                       WHERE p.organization_id = %(organization_id)s
                         AND p.project_id = %(project_id)s
                         AND p.environment_id = %(environment_id)s
                         AND p.message_id = %(message_id)s
                       GROUP BY p.organization_id, p.project_id, p.environment_id, p.id
                       ORDER BY p.sequence""",
                    {**scope.canonical_dict(), "message_id": row["id"]},
                )
                parts: list[Part] = []
                for part_row in cursor.fetchall():
                    references = {tuple(item.split(":", 1)) for item in (part_row["access"] or [])}
                    if part_row["access_mode"] == "DERIVED_SOURCES":
                        visible = reader_may_see_compaction(
                            cursor,
                            scope=scope,
                            part_id=str(part_row["id"]),
                            reader_principal=reader_principal,
                            authorized=authorized,
                            participant_epochs=participant_epochs,
                        )
                    else:
                        visible = reader_may_see_row(
                            access_mode=str(part_row["access_mode"]),
                            author_principal=part_row["author_principal"],
                            references=references,
                            reader_principal=reader_principal,
                            authorized=authorized,
                            participant_epochs=participant_epochs,
                            membership_epoch=part_row["membership_epoch"],
                        )
                    # In-flight parts are a private progress view for the
                    # initiating reader only.  They are never admitted to a
                    # reader's shared projection until completion commits the
                    # final access envelope; everyone else receives the same
                    # explicit withheld placeholder as any hidden part.
                    if part_row["status"] == "STREAMING":
                        visible = visible and part_row["author_principal"] == reader_principal
                    if visible:
                        parts.append(
                            Part(
                                kind=PartKind(str(part_row["kind"])),
                                sequence=int(part_row["sequence"]),
                                payload=dict(part_row["payload_json"]),
                                classification=str(part_row["classification"]),
                                access_mode=AccessMode(str(part_row["access_mode"])),
                                author_principal=part_row["author_principal"],
                                membership_epoch=part_row["membership_epoch"],
                            )
                        )
                    else:
                        parts.append(
                            withheld_part(
                                sequence=int(part_row["sequence"]),
                                verdict_ref="reader-authority",
                                reason="This part references a record outside your authority.",
                            )
                        )
                messages.append(
                    MessageRecord(
                        id=str(row["id"]),
                        thread_id=str(row["thread_id"]),
                        role=str(row["role"]),
                        author_principal=row["author_principal"],
                        turn_state=str(row["turn_state"]),
                        classification=str(row["classification"]),
                        created_at=row["created_at"],
                        in_reply_to_message_id=row["in_reply_to_message_id"],
                        parts=tuple(parts),
                    )
                )
        return tuple(messages)
