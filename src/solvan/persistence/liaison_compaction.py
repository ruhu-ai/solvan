"""Persistence boundary for non-authoritative conversational compactions."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier

TRANSCRIPT_RETENTION_DAYS = 180


class CompactionError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CompactionReceipt:
    message_id: str
    part_id: str
    source_message_ids: tuple[str, ...]


def compact_next_thread(
    connection: Connection[Any],
    *,
    scope: Scope,
    preserve_recent_messages: int = 4,
    minimum_source_messages: int = 8,
) -> CompactionReceipt | None:
    """Atomically select and summarize the oldest uncompacted whole turns.

    The summary is deliberately extractive and provider-independent. It is
    context-only, receives no tools, citations, or delivery path, and a crash
    rolls the whole transaction back so the next tick safely retries it.
    """

    if preserve_recent_messages < 2 or minimum_source_messages < 2:
        raise CompactionError("compaction bounds are invalid")
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """SELECT t.id
                 FROM solvan_liaison.liaison_threads t
                WHERE t.organization_id=%(organization_id)s
                  AND t.project_id=%(project_id)s AND t.environment_id=%(environment_id)s
                  AND t.status='OPEN' AND (
                    SELECT count(*) FROM solvan_liaison.liaison_messages m
                     WHERE (m.organization_id,m.project_id,m.environment_id,m.thread_id)=
                           (t.organization_id,t.project_id,t.environment_id,t.id)
                       AND m.turn_state='COMPLETED' AND m.deleted_at IS NULL
                       AND NOT EXISTS (
                         SELECT 1 FROM solvan_liaison.liaison_compaction_sources cs
                          WHERE (cs.organization_id,cs.project_id,cs.environment_id,
                                 cs.source_message_id)=
                                (m.organization_id,m.project_id,m.environment_id,m.id))
                       AND NOT EXISTS (
                         SELECT 1 FROM solvan_liaison.liaison_message_parts cp
                          WHERE (cp.organization_id,cp.project_id,cp.environment_id,
                                 cp.message_id)=
                                (m.organization_id,m.project_id,m.environment_id,m.id)
                            AND cp.kind='compaction')
                  ) >= %(minimum_total)s
                ORDER BY t.last_activity_at,t.id FOR UPDATE SKIP LOCKED LIMIT 1""",
            {
                **scope.canonical_dict(),
                "minimum_total": minimum_source_messages + preserve_recent_messages,
            },
        )
        thread = cursor.fetchone()
        if thread is None:
            return None
        thread_id = str(thread["id"])
        cursor.execute(
            """SELECT m.id,m.role,m.in_reply_to_message_id,m.stream_position,
                      coalesce(jsonb_agg(p.payload_json ORDER BY p.sequence)
                        FILTER (WHERE p.id IS NOT NULL),'[]') AS parts
                 FROM solvan_liaison.liaison_messages m
                 LEFT JOIN solvan_liaison.liaison_message_parts p ON
                   (p.organization_id,p.project_id,p.environment_id,p.message_id)=
                   (m.organization_id,m.project_id,m.environment_id,m.id)
                WHERE m.organization_id=%(organization_id)s
                  AND m.project_id=%(project_id)s AND m.environment_id=%(environment_id)s
                  AND m.thread_id=%(thread_id)s AND m.turn_state='COMPLETED'
                  AND m.deleted_at IS NULL
                  AND NOT EXISTS (
                    SELECT 1 FROM solvan_liaison.liaison_compaction_sources cs
                     WHERE (cs.organization_id,cs.project_id,cs.environment_id,
                            cs.source_message_id)=
                           (m.organization_id,m.project_id,m.environment_id,m.id))
                  AND NOT EXISTS (
                    SELECT 1 FROM solvan_liaison.liaison_message_parts cp
                     WHERE (cp.organization_id,cp.project_id,cp.environment_id,cp.message_id)=
                           (m.organization_id,m.project_id,m.environment_id,m.id)
                       AND cp.kind='compaction')
                GROUP BY m.id,m.role,m.in_reply_to_message_id,m.stream_position
                ORDER BY m.stream_position""",
            {**scope.canonical_dict(), "thread_id": thread_id},
        )
        messages = list(cursor.fetchall())
    cutoff = max(0, len(messages) - preserve_recent_messages)
    candidates = messages[:cutoff]
    by_id = {str(row["id"]): row for row in candidates}
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for answer in candidates:
        reply = answer["in_reply_to_message_id"]
        user = by_id.get(str(reply)) if reply is not None else None
        if answer["role"] == "LIAISON" and user is not None and user["role"] == "USER":
            pairs.append((user, answer))
    selected_pairs = pairs[: max(1, minimum_source_messages // 2)]
    if len(selected_pairs) * 2 < minimum_source_messages:
        return None
    sources = tuple(str(row["id"]) for pair in selected_pairs for row in pair)
    pinned = tuple(str(row["id"]) for row in messages[cutoff:])
    summary_lines: list[str] = []
    for user, answer in selected_pairs:
        user_text = _summary_text(user["parts"])
        answer_text = _summary_text(answer["parts"])
        summary_lines.append(f"Question: {user_text}\nRecorded answer: {answer_text}")
    summary = "\n\n".join(summary_lines)[:8_000]
    source_hash = canonical_sha256({"thread_id": thread_id, "sources": sources, "summary": summary})
    receipt = store_compaction(
        connection,
        scope=scope,
        thread_id=thread_id,
        summary=summary,
        source_message_ids=sources,
        pinned_message_ids=pinned,
        model_receipt_ref=f"deterministic://liaison-compactor/v1/{source_hash}",
    )
    connection.execute(
        """INSERT INTO solvan.audit_events
             (organization_id,project_id,environment_id,id,stream_type,stream_id,
              event_type,actor_principal,input_refs_json,payload_hash)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
              'LIAISON_THREAD',%(thread_id)s,'TranscriptCompacted',
              'service:liaison-maintenance',%(input_refs)s,%(payload_hash)s)""",
        {
            **scope.canonical_dict(),
            "id": new_identifier("aud"),
            "thread_id": thread_id,
            "input_refs": json.dumps(list(sources)),
            "payload_hash": source_hash,
        },
    )
    return receipt


def _summary_text(parts: Any) -> str:
    values: list[str] = []
    for part in parts if isinstance(parts, list) else []:
        if not isinstance(part, dict):
            continue
        for key in ("sentence", "text", "prompt", "reason", "error"):
            value = part.get(key)
            if isinstance(value, str) and value.strip():
                values.append(value.strip())
                break
    return " ".join(values)[:1_000] or "[No retained visible text]"


def store_compaction(
    connection: Connection[Any],
    *,
    scope: Scope,
    thread_id: str,
    summary: str,
    source_message_ids: Sequence[str],
    pinned_message_ids: Sequence[str],
    model_receipt_ref: str,
    retention_days: int = TRANSCRIPT_RETENTION_DAYS,
) -> CompactionReceipt:
    """Store a whole-turn summary whose visibility is derived from its sources.

    Selection and summarization happen outside this boundary. This function
    accepts the result only when the source set is a complete collection of
    user/answer turns in one thread, excludes the explicitly pinned tail, and
    contains no prior compaction. The text remains context-only metadata: it
    carries no citations and cannot be delivered by a channel worker.
    """

    sources = tuple(dict.fromkeys(source_message_ids))
    if not summary.strip() or not model_receipt_ref or not sources:
        raise CompactionError("compaction requires summary, receipt, and sources")
    if set(sources) & set(pinned_message_ids):
        raise CompactionError("compaction source overlaps the pinned transcript tail")

    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """SELECT m.id,m.thread_id,m.role,m.in_reply_to_message_id,m.classification,
                      m.turn_state,m.deleted_at,m.stream_position,
                      EXISTS (SELECT 1 FROM solvan_liaison.liaison_message_parts p
                               WHERE (p.organization_id,p.project_id,p.environment_id,
                                      p.message_id)=(m.organization_id,m.project_id,
                                                     m.environment_id,m.id)
                                 AND p.kind='compaction') AS is_compaction
                 FROM solvan_liaison.liaison_messages m
                WHERE m.organization_id=%(organization_id)s
                  AND m.project_id=%(project_id)s AND m.environment_id=%(environment_id)s
                  AND m.id=ANY(%(source_ids)s) ORDER BY m.stream_position
                FOR SHARE""",
            {**scope.canonical_dict(), "source_ids": list(sources)},
        )
        rows = cursor.fetchall()
        if len(rows) != len(sources):
            raise CompactionError("a compaction source is missing from this scope")
        if any(
            row["thread_id"] != thread_id
            or row["turn_state"] != "COMPLETED"
            or row["deleted_at"] is not None
            or row["is_compaction"]
            for row in rows
        ):
            raise CompactionError("sources must be completed, live, non-compaction messages")

        source_set = {str(row["id"]) for row in rows}
        users = {str(row["id"]) for row in rows if row["role"] == "USER"}
        answers = [row for row in rows if row["role"] == "LIAISON"]
        if not users or len(users) != len(answers):
            raise CompactionError("sources must contain complete user and Liaison turn pairs")
        if any(str(row["in_reply_to_message_id"]) not in users for row in answers):
            raise CompactionError("every Liaison source must answer a selected user message")
        answered = {str(row["in_reply_to_message_id"]) for row in answers}
        if answered != users or source_set != users | {str(row["id"]) for row in answers}:
            raise CompactionError("sources must contain whole turns only")

        classification = max((str(row["classification"]) for row in rows), key=_classification_rank)
        message_id = new_identifier("lms")
        part_id = new_identifier("prt")
        cursor.execute(
            """INSERT INTO solvan_liaison.liaison_messages
                 (organization_id,project_id,environment_id,id,thread_id,role,
                  classification,turn_state,purge_after,completed_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(message_id)s,
                  %(thread_id)s,'LIAISON',%(classification)s,'COMPLETED',%(purge_after)s,now())""",
            {
                **scope.canonical_dict(),
                "message_id": message_id,
                "thread_id": thread_id,
                "classification": classification,
                "purge_after": datetime.now(UTC) + timedelta(days=retention_days),
            },
        )
        cursor.execute(
            """INSERT INTO solvan_liaison.liaison_message_parts
                 (organization_id,project_id,environment_id,id,message_id,sequence,kind,
                  schema_version,status,classification,access_mode,payload_json,completed_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(part_id)s,
                  %(message_id)s,0,'compaction',1,'COMPLETED',%(classification)s,
                  'DERIVED_SOURCES',%(payload)s,now())""",
            {
                **scope.canonical_dict(),
                "part_id": part_id,
                "message_id": message_id,
                "classification": classification,
                "payload": json.dumps(
                    {
                        "summary": summary.strip(),
                        "context_only": True,
                        "citable": False,
                        "channel_deliverable": False,
                        "model_receipt_ref": model_receipt_ref,
                    },
                    sort_keys=True,
                ),
            },
        )
        cursor.executemany(
            """INSERT INTO solvan_liaison.liaison_compaction_sources
                 (organization_id,project_id,environment_id,compaction_part_id,
                  source_message_id)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                  %(part_id)s,%(source_message_id)s)""",
            [
                {
                    **scope.canonical_dict(),
                    "part_id": part_id,
                    "source_message_id": source_id,
                }
                for source_id in sources
            ],
        )
        # Union the source record envelopes for audit/search. Reader visibility
        # is stricter: transcript reads evaluate every original source part.
        cursor.execute(
            """INSERT INTO solvan_liaison.liaison_part_access
                 (organization_id,project_id,environment_id,part_id,
                  record_type,record_id,relation)
               SELECT organization_id,project_id,environment_id,%(part_id)s,
                      record_type,record_id,'SOURCE'
                 FROM solvan_liaison.liaison_part_access
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND part_id IN (
                    SELECT id FROM solvan_liaison.liaison_message_parts
                     WHERE organization_id=%(organization_id)s
                       AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                       AND message_id=ANY(%(source_ids)s))
               ON CONFLICT DO NOTHING""",
            {**scope.canonical_dict(), "part_id": part_id, "source_ids": list(sources)},
        )
        cursor.execute(
            """UPDATE solvan_liaison.liaison_threads SET last_activity_at=now()
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND id=%(thread_id)s""",
            {**scope.canonical_dict(), "thread_id": thread_id},
        )
    return CompactionReceipt(message_id, part_id, sources)


def _classification_rank(value: str) -> int:
    try:
        return {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}[value]
    except KeyError as error:
        raise CompactionError("source classification is invalid") from error
