"""Reader-filtered transcript, cursor, and event-replay routes."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse

from apps.api.liaison_http_support import (
    _CLIENT_EVENT_BUFFER_CEILING,
    _FINITE_REPLAY_PAGE_CEILING,
    ReadCursorRequest,
    _claim_json_operation,
    _complete_json_operation,
)
from apps.api.liaison_service import LiaisonService
from solvan.application.liaison.engine import default_turn_budget
from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_policy import current_policy_epoch
from solvan.persistence.liaison_projection_grants import projection_read
from solvan.persistence.liaison_store import LiaisonStore
from solvan.persistence.liaison_turn_control import (
    visible_events,
)

#: How long a quiet stream waits between reads, and how long one connection
#: lives before the client is asked to resume from its cursor.
_STREAM_IDLE_SECONDS = 1.0
_STREAM_SESSION_SECONDS = 600.0
#: What the browser should wait before reconnecting after a dropped stream.
_STREAM_RETRY_MS = 1_000


@dataclass(frozen=True, slots=True)
class StreamPageDecision:
    overflow: bool
    last_sequence: int


def classify_stream_page(
    *, page_size: int, cursor: int, buffer_ceiling: int = _CLIENT_EVENT_BUFFER_CEILING
) -> StreamPageDecision:
    """Decide whether a bounded replay page must force cursor recovery."""

    if page_size < 0 or cursor < 0 or buffer_ceiling < 1:
        raise ValueError("stream page operands are invalid")
    return StreamPageDecision(
        overflow=page_size >= buffer_ceiling,
        last_sequence=cursor,
    )


def register_replay_routes(
    router: APIRouter,
    *,
    connect: Callable[[], Any],
    scope_provider: Callable[[], Scope],
    principal_provider: Callable[[str | None], str],
    snapshot_provider: Callable[[], dict[str, Any]],
    service: LiaisonService,
) -> None:
    @router.get("/api/v1/threads/{thread_id}/messages")
    @router.get("/api/v1/liaison/threads/{thread_id}/messages")
    def transcript(
        thread_id: str,
        before_id: str | None = None,
        limit: int = 100,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        """This reader's projection of a thread, cursor-paged.

        Filtering happens per part against the reader's authority; a part they
        may not see is replaced by a visible placeholder, never removed.
        """

        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        reader = service.reader(principal=principal, scope=scope)
        authorized = tuple(reader.authorized_records())
        with connect() as connection, connection.transaction():
            store = LiaisonStore(connection)
            thread_record = store.thread(scope=scope, thread_id=thread_id)
            if thread_record is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "thread not found in this scope")
            # Per-part filtering below decides what this reader sees inside the
            # thread; membership decides whether they see the thread at all. A
            # participant-visible thread is not listable by a non-participant,
            # so it must not be readable by one either.
            if thread_record.visibility == "PARTICIPANTS" and principal not in store.participants(
                scope=scope, thread_id=thread_id
            ):
                raise HTTPException(status.HTTP_404_NOT_FOUND, "thread not found in this scope")
            membership_epoch = store.current_membership_epoch(
                scope=scope, thread_id=thread_id, principal=principal
            )
            with projection_read(
                connection,
                scope=scope,
                principal=principal,
                purpose="incident-investigation",
                classification_ceiling="CONFIDENTIAL",
                method="read_transcript",
                operation_id=new_identifier("opr"),
                anchor_label=thread_record.anchor.label(),
                authorized_records=authorized,
                membership_epoch=membership_epoch,
            ):
                messages = store.transcript(
                    scope=scope,
                    thread_id=thread_id,
                    reader_principal=principal,
                    authorized_records=authorized,
                    limit=min(limit, 100),
                    before_id=before_id,
                )
                turn_rows = connection.execute(
                    """SELECT message_id,attempt,generation,queue_sequence,status,
                          model_calls,tool_calls,tokens
                    FROM solvan_liaison.liaison_turns
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND thread_id=%(thread_id)s
                    ORDER BY attempt DESC""",
                    {**scope.canonical_dict(), "thread_id": thread_id},
                ).fetchall()
            turns: dict[str, tuple[int, int, int | None, str, int, int, int]] = {}
            for (
                message_id,
                attempt,
                generation,
                queue_sequence,
                turn_status,
                model_calls,
                tool_calls,
                tokens,
            ) in turn_rows:
                turns.setdefault(
                    str(message_id),
                    (
                        int(attempt),
                        int(generation),
                        queue_sequence,
                        str(turn_status),
                        int(model_calls),
                        int(tool_calls),
                        int(tokens),
                    ),
                )
            attachment_rows = (
                connection.execute(
                    """SELECT message_id,id,scan_status,classification,mime,size_bytes
                     FROM solvan_liaison.liaison_attachments
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND message_id = ANY(%(message_ids)s) AND deleted_at IS NULL""",
                    {
                        **scope.canonical_dict(),
                        "message_ids": [message.id for message in messages],
                    },
                ).fetchall()
                if messages
                else []
            )
            attachments: dict[str, list[dict[str, Any]]] = {}
            for (
                attached_message_id,
                attachment_id,
                scan_status,
                classification,
                mime,
                size_bytes,
            ) in attachment_rows:
                attachments.setdefault(str(attached_message_id), []).append(
                    {
                        "attachment_id": str(attachment_id),
                        "scan_status": str(scan_status),
                        "classification": str(classification),
                        "mime": str(mime),
                        "size_bytes": int(size_bytes),
                    }
                )
        return {
            "thread_id": thread_id,
            # The ceilings travel with the transcript so a rehydrated turn
            # reports the budget that applied instead of a browser-side copy.
            "budget": default_turn_budget().as_dict(),
            "messages": [
                {
                    "id": message.id,
                    "role": message.role,
                    "author": message.author_principal,
                    "in_reply_to_message_id": message.in_reply_to_message_id,
                    "turn_state": message.turn_state,
                    "attempt": turns.get(message.id, (None, None, None, "", 0, 0, 0))[0],
                    "generation": turns.get(message.id, (None, None, None, "", 0, 0, 0))[1],
                    "queue_sequence": turns.get(message.id, (None, None, None, "", 0, 0, 0))[2],
                    "model_calls": turns.get(message.id, (None, None, None, "", 0, 0, 0))[4],
                    "tool_calls": turns.get(message.id, (None, None, None, "", 0, 0, 0))[5],
                    "tokens": turns.get(message.id, (None, None, None, "", 0, 0, 0))[6],
                    "attachments": attachments.get(message.id, []),
                    "created_at": message.created_at.isoformat(),
                    "parts": [
                        {
                            "kind": str(part.kind),
                            "sequence": part.sequence,
                            "payload": part.payload,
                            "classification": part.classification,
                            "access_mode": str(part.access_mode),
                        }
                        for part in message.parts
                    ],
                }
                for message in messages
            ],
            "next_before_id": messages[0].id if messages else None,
        }

    @router.put("/api/v1/threads/{thread_id}/read-cursor")
    def advance_read_cursor(
        thread_id: str,
        request: ReadCursorRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        """Advance one reader's durable position without granting visibility."""

        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        with connect() as connection, connection.transaction():
            operation = "liaison.read_cursor.advance"
            replay = _claim_json_operation(
                connection,
                scope=scope,
                key=idempotency_key,
                operation=operation,
                request={
                    "thread_id": thread_id,
                    "stream_sequence": request.stream_sequence,
                    "principal": principal,
                },
            )
            if replay is not None:
                return replay
            store = LiaisonStore(connection)
            if principal not in store.participants(scope=scope, thread_id=thread_id):
                raise HTTPException(status.HTTP_404_NOT_FOUND, "thread not found")
            epoch = current_policy_epoch(connection, scope=scope, principal=principal)
            connection.execute(
                """INSERT INTO solvan_liaison.liaison_thread_read_cursors (
                      organization_id,project_id,environment_id,thread_id,principal,
                      policy_epoch,stream_sequence)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(thread_id)s,%(principal)s,%(epoch)s,%(sequence)s)
                   ON CONFLICT (organization_id,project_id,environment_id,thread_id,principal)
                   DO UPDATE SET policy_epoch=EXCLUDED.policy_epoch,
                     stream_sequence=GREATEST(
                       solvan_liaison.liaison_thread_read_cursors.stream_sequence,
                       EXCLUDED.stream_sequence),updated_at=now()""",
                {
                    **scope.canonical_dict(),
                    "thread_id": thread_id,
                    "principal": principal,
                    "epoch": epoch,
                    "sequence": request.stream_sequence,
                },
            )
            response = {"thread_id": thread_id, "stream_sequence": request.stream_sequence}
            _complete_json_operation(
                connection,
                scope=scope,
                key=idempotency_key or "",
                operation=operation,
                response=response,
            )
            return response

    def _event_page(
        *, thread_id: str, principal: str, after_sequence: int, limit: int
    ) -> tuple[Any, ...]:
        scope = scope_provider()
        reader = service.reader(principal=principal, scope=scope)
        with connect() as connection:
            store = LiaisonStore(connection)
            thread = store.thread(scope=scope, thread_id=thread_id)
            if thread is None or principal not in store.participants(
                scope=scope, thread_id=thread_id
            ):
                return ()
            return visible_events(
                connection,
                scope=scope,
                thread_id=thread_id,
                principal=principal,
                authorized_records=reader.authorized_records(),
                after_sequence=after_sequence,
                limit=min(limit, _CLIENT_EVENT_BUFFER_CEILING),
            )

    def _authorize_event_read(*, thread_id: str, principal: str, ttl_seconds: int = 60) -> None:
        """Bind one replay or stream session to current reader authority."""

        scope = scope_provider()
        reader = service.reader(principal=principal, scope=scope)
        authorized = tuple(reader.authorized_records())
        with connect() as connection, connection.transaction():
            store = LiaisonStore(connection)
            thread = store.thread(scope=scope, thread_id=thread_id)
            if thread is None or principal not in store.participants(
                scope=scope, thread_id=thread_id
            ):
                raise HTTPException(status.HTTP_404_NOT_FOUND, "thread not found")
            membership_epoch = store.current_membership_epoch(
                scope=scope, thread_id=thread_id, principal=principal
            )
            with projection_read(
                connection,
                scope=scope,
                principal=principal,
                purpose="incident-investigation",
                classification_ceiling="CONFIDENTIAL",
                method="read_events",
                operation_id=new_identifier("opr"),
                anchor_label=thread.anchor.label(),
                authorized_records=authorized,
                membership_epoch=membership_epoch,
                ttl_seconds=ttl_seconds,
            ):
                pass

    @router.get("/api/v1/threads/{thread_id}/events")
    def replay_events(
        thread_id: str,
        after_sequence: int = 0,
        limit: int = 256,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        """Finite replay used before a client opens the live stream."""

        principal = principal_provider(human_identity_token)
        _authorize_event_read(thread_id=thread_id, principal=principal)
        page_limit = max(1, min(limit, _FINITE_REPLAY_PAGE_CEILING))
        events = _event_page(
            thread_id=thread_id,
            principal=principal,
            after_sequence=max(0, after_sequence),
            limit=page_limit,
        )
        return {
            "thread_id": thread_id,
            "events": [
                {
                    "sequence": item.sequence,
                    "id": item.event_id,
                    "type": item.event_type,
                    "message_id": item.message_id,
                    "attempt": item.attempt,
                    "generation": item.generation,
                    "payload": item.payload,
                }
                for item in events
            ],
            "last_sequence": events[-1].sequence if events else max(0, after_sequence),
            "has_more": len(events) >= page_limit,
        }

    @router.get("/api/v1/liaison/events")
    async def stream_events(
        thread_id: str,
        after_sequence: int = 0,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> StreamingResponse:
        """Replayable SSE with a bounded per-connection event page.

        The generator is async and its database reads run on the threadpool:
        the earlier synchronous `time.sleep` held a worker for the whole
        connection, which is why the console polled instead of subscribing.
        A connection lives until the client drops it or the session ceiling is
        reached; the client always resumes from its last acknowledged
        `stream_sequence`, so an ended stream costs a reconnect and nothing
        else (§19.2).
        """

        principal = principal_provider(human_identity_token)
        _authorize_event_read(
            thread_id=thread_id,
            principal=principal,
            ttl_seconds=int(_STREAM_SESSION_SECONDS) + 10,
        )

        async def generate() -> AsyncIterator[str]:
            cursor = max(0, after_sequence)
            waited = 0.0
            yield f"retry: {_STREAM_RETRY_MS}\n\n"
            while waited < _STREAM_SESSION_SECONDS:
                page = await run_in_threadpool(
                    _event_page,
                    thread_id=thread_id,
                    principal=principal,
                    after_sequence=cursor,
                    limit=_CLIENT_EVENT_BUFFER_CEILING,
                )
                decision = classify_stream_page(page_size=len(page), cursor=cursor)
                if decision.overflow:
                    payload = json.dumps(
                        {"code": "EVENT_BUFFER_OVERFLOW", "last_sequence": decision.last_sequence}
                    )
                    yield f"event: error\ndata: {payload}\n\n"
                    return
                if not page:
                    waited += _STREAM_IDLE_SECONDS
                    # A comment frame keeps proxies and the browser from
                    # judging a quiet conversation to be a dead connection.
                    yield ": keepalive\n\n"
                    await asyncio.sleep(_STREAM_IDLE_SECONDS)
                    continue
                waited = 0.0
                for item in page:
                    cursor = item.sequence
                    payload = json.dumps(
                        {
                            "sequence": item.sequence,
                            "message_id": item.message_id,
                            "attempt": item.attempt,
                            "generation": item.generation,
                            "payload": item.payload,
                        },
                        separators=(",", ":"),
                    )
                    yield f"id: {item.sequence}\nevent: {item.event_type}\ndata: {payload}\n\n"

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={"cache-control": "no-store", "x-accel-buffering": "no"},
        )
