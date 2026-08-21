"""The conversation API composition root and primary Ask routes."""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, status

from apps.api.liaison_attachment_routes import register_attachment_routes
from apps.api.liaison_http_support import (
    _CLIENT_EVENT_BUFFER_CEILING as _CLIENT_EVENT_BUFFER_CEILING,
)
from apps.api.liaison_http_support import (
    _THREAD_STATUS,
    AskRequest,
    AskResponse,
    _view,
)
from apps.api.liaison_http_support import (
    liaison_registry as liaison_registry,
)
from apps.api.liaison_participant_routes import register_participant_routes
from apps.api.liaison_replay_routes import register_replay_routes
from apps.api.liaison_selection_routes import register_selection_routes
from apps.api.liaison_service import LiaisonService
from apps.api.liaison_steer import SteerService
from apps.api.liaison_subscription_routes import subscription_router
from apps.api.liaison_turn_routes import register_turn_routes
from apps.api.liaison_types import IdempotencyConflict
from solvan.application.liaison import (
    Anchor,
    AnchorError,
    GrantIssuer,
    resolve_anchor,
)
from solvan.application.liaison.questions import (
    offered_questions,
    question_prompt,
    scope_offered_questions,
)
from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_projection_grants import projection_read
from solvan.persistence.liaison_store import LiaisonStore, ThreadAccessError


def liaison_router(
    *,
    snapshot_provider: Callable[[], dict[str, Any]],
    principal_provider: Callable[[str | None], str],
    scope_provider: Callable[[], Scope],
    connect: Callable[[], Any],
    quarantine_dir: Path,
) -> APIRouter:
    router = APIRouter()
    _steer = SteerService(issuer=GrantIssuer())
    service = LiaisonService(
        connect=connect,
        snapshot_provider=snapshot_provider,
        registry_provider=liaison_registry,
    )

    @router.get("/api/v1/liaison/questions")
    def questions(
        record_type: str | None = None,
        record_id: str | None = None,
        anchor_kind: str = "RECORD",
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        """The enumerated questions worth asking about this record (§4.2).

        Derived from the record's state, never generated, so a chip cannot
        disclose the existence of something the reader may not see.
        """

        principal = principal_provider(human_identity_token)
        scope = scope_provider()
        reader = service.reader(principal=principal, scope=scope)
        if anchor_kind.upper() != "RECORD":
            # A conversation with no single record still has questions it can
            # answer. Offering nothing was what left the workspace Chat with a
            # bare composer and no way to discover what it does.
            if not reader.scope_authorized:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "questions are unavailable")
            return {
                "record": "scope",
                "questions": [
                    {"id": item, "prompt": question_prompt(item)}
                    for item in scope_offered_questions()
                ],
            }
        if not record_type or not record_id:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "a record anchor needs a record type and id",
            )
        try:
            anchor = resolve_anchor(reader, Anchor.record(record_type, record_id))
        except AnchorError as error:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "record is not addressable") from error
        allowed = reader.authorized_records_for_anchor(anchor)
        if (record_type, record_id) not in set(allowed):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "record is not addressable")
        # Persist the production read boundary even though the enumerated
        # question set is deterministic. The local fixture has no workflow
        # authority and intentionally keeps its fast, database-free preview.
        if os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE") == "GOOGLE_CLOUD_IAM":
            with (
                connect() as connection,
                connection.transaction(),
                projection_read(
                    connection,
                    scope=scope,
                    principal=principal,
                    purpose="incident-investigation",
                    classification_ceiling="CONFIDENTIAL",
                    method="list_questions",
                    operation_id=new_identifier("opr"),
                    anchor_label=anchor.label(),
                    authorized_records=allowed,
                ),
            ):
                record = reader.read(record_type, record_id)
        else:
            record = reader.read(record_type, record_id)
        if record is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "record is not addressable")
        return {
            "record": f"{record_type}:{record_id}",
            "questions": [
                {"id": item, "prompt": question_prompt(item)} for item in offered_questions(record)
            ],
        }

    @router.post("/api/v1/liaison:ask", response_model=AskResponse)
    def ask(
        request: AskRequest,
        background_tasks: BackgroundTasks,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        prefer: str | None = Header(default=None, alias="Prefer"),
    ) -> AskResponse:
        """Answer one question from the ledger, durably, under the asker's grant."""

        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        reader = service.reader(principal=principal, scope=scope)

        try:
            if request.anchor_kind == "SCOPE":
                anchor = Anchor.scope()
            elif request.anchor_kind == "SERVICE_WINDOW":
                assert request.anchor_service_key is not None
                assert request.anchor_window_start is not None
                assert request.anchor_window_end is not None
                anchor = Anchor.service(
                    request.anchor_service_key,
                    request.anchor_window_start,
                    request.anchor_window_end,
                )
                if not reader.authorized_records_for_anchor(anchor):
                    raise AnchorError("service window is not addressable")
            else:
                anchor = resolve_anchor(
                    reader,
                    Anchor.record(str(request.anchor_record_type), str(request.anchor_record_id)),
                )
        except AnchorError as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error

        try:
            outcome = service.ask(
                scope=scope,
                principal=principal,
                anchor=anchor,
                question=request.question,
                thread_id=request.thread_id,
                mentions=tuple(request.mentions),
                idempotency_key=idempotency_key,
                defer_execution=prefer == "respond-async",
            )
        except ThreadAccessError as error:
            raise HTTPException(_THREAD_STATUS[error.code], str(error)) from error
        except IdempotencyConflict as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        if prefer == "respond-async" and outcome.durable_state in {"READY", "QUEUED"}:
            background_tasks.add_task(
                service.run_pending,
                scope=scope,
                thread_id=outcome.thread_id,
                target_message_id=outcome.answer_message_id,
            )
        return AskResponse(
            thread_id=outcome.thread_id,
            thread_anchor=anchor.label(),
            state=outcome.durable_state or str(outcome.result.state),
            user_message_id=outcome.user_message_id,
            answer_message_id=outcome.answer_message_id,
            attempt=outcome.attempt,
            generation=outcome.generation,
            queue_sequence=outcome.queue_sequence,
            model_calls=outcome.result.usage.model_calls,
            tool_calls=outcome.result.usage.tool_calls,
            tokens=outcome.result.usage.tokens,
            parts=_view(outcome.result, reader, principal),
            suggested=[
                {"id": item, "prompt": question_prompt(item)} for item in outcome.result.suggested
            ],
            budget=outcome.result.budget.as_dict(),
            defects={
                "suppressed": outcome.result.defects.suppressed,
                "held": outcome.result.defects.held,
                "unresolved_citations": outcome.result.defects.unresolved_citations,
                "unknown_templates": outcome.result.defects.unknown_templates,
                "provider_degraded": outcome.result.defects.provider_degraded,
            },
        )

    @router.get("/api/v1/threads")
    @router.get("/api/v1/liaison/threads")
    def threads(
        anchor_kind: str = "RECORD",
        record_type: str | None = None,
        record_id: str | None = None,
        service_key: str | None = None,
        window_start: datetime | None = None,
        window_end: datetime | None = None,
        cursor: str | None = None,
        limit: int = 20,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        """Reader-visible conversations on one exact record or current scope (§5)."""

        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        try:
            normalized_kind = anchor_kind.upper()
            if normalized_kind == "SCOPE":
                anchor = Anchor.scope()
            elif normalized_kind == "SERVICE_WINDOW":
                if service_key is None or window_start is None or window_end is None:
                    raise AnchorError("a service conversation needs a service and closed window")
                anchor = Anchor.service(service_key, window_start, window_end)
            else:
                anchor = Anchor.record(str(record_type), str(record_id))
        except AnchorError as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error
        reader = service.reader(principal=principal, scope=scope)
        if not reader.scope_authorized:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "thread directory is unavailable")
        if anchor.kind.value == "RECORD" and not reader.exists(
            str(anchor.record_type), str(anchor.record_id)
        ):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "record is not addressable")
        authorized = (
            tuple(reader.authorized_records())
            if anchor.kind.value == "SCOPE"
            else tuple(reader.authorized_records_for_anchor(anchor))
        )
        before = None
        if cursor:
            try:
                decoded = json.loads(
                    base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
                )
                before = (datetime.fromisoformat(str(decoded[0])), str(decoded[1]))
            except (ValueError, TypeError, json.JSONDecodeError) as error:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid cursor"
                ) from error
        page_size = max(1, min(limit, 50))
        with (
            connect() as connection,
            connection.transaction(),
            projection_read(
                connection,
                scope=scope,
                principal=principal,
                purpose="incident-investigation",
                classification_ceiling="CONFIDENTIAL",
                method="list_threads",
                operation_id=new_identifier("opr"),
                anchor_label=anchor.label(),
                authorized_records=authorized,
            ),
        ):
            store = LiaisonStore(connection)
            # Exactly this anchor, including at scope. Listing every thread the
            # reader's entity set touches put record- and service-anchored
            # conversations in the workspace picker, where the console showed
            # them under a workspace heading and the anchor fence then refused
            # every message sent into them. A record conversation is reached by
            # attaching its record, which is what mints the selection receipt.
            candidates = store.threads_for_anchor(
                scope=scope,
                anchor=anchor,
                before=before,
                limit=page_size + 1,
            )
            records = tuple(
                item
                for item in candidates
                if principal in store.participants(scope=scope, thread_id=item.id)
            )
        has_more = len(records) > page_size
        records = records[:page_size]
        return {
            "anchor": anchor.label(),
            "threads": [
                {
                    "id": item.id,
                    "visibility": item.visibility,
                    "status": item.status,
                    "created_by": item.created_by_principal,
                    "last_activity_at": item.last_activity_at.isoformat(),
                }
                for item in records
            ],
            "next_cursor": (
                base64.urlsafe_b64encode(
                    json.dumps(
                        [records[-1].last_activity_at.isoformat(), records[-1].id],
                        separators=(",", ":"),
                    ).encode()
                )
                .decode()
                .rstrip("=")
                if has_more and records
                else None
            ),
        }

    register_participant_routes(
        router,
        connect=connect,
        scope_provider=scope_provider,
        principal_provider=principal_provider,
    )
    register_attachment_routes(
        router,
        connect=connect,
        scope_provider=scope_provider,
        principal_provider=principal_provider,
        quarantine_dir=quarantine_dir,
    )
    register_replay_routes(
        router,
        connect=connect,
        scope_provider=scope_provider,
        principal_provider=principal_provider,
        snapshot_provider=snapshot_provider,
        service=service,
    )
    register_selection_routes(
        router,
        connect=connect,
        scope_provider=scope_provider,
        principal_provider=principal_provider,
        reader_provider=service.reader,
    )
    register_turn_routes(
        router,
        connect=connect,
        scope_provider=scope_provider,
        principal_provider=principal_provider,
        service=service,
        steer=_steer,
    )

    router.include_router(
        subscription_router(
            principal_provider=principal_provider,
            scope_provider=scope_provider,
            connect=connect,
            reader_provider=service.reader,
        )
    )
    return router
