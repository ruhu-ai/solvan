"""Exact turn control, catch-up, Steer, and parked-request routes."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, status

from apps.api.liaison_http_support import (
    _THREAD_STATUS,
    DecideRequest,
    ExactTurnRequest,
    SteerRequest,
    StopAndSendRequest,
    _claim_json_operation,
    _complete_json_operation,
)
from apps.api.liaison_maintenance import sync_scope_events
from apps.api.liaison_service import LiaisonService, sync_projection
from apps.api.liaison_steer import SteerDraft, SteerRefused, SteerService
from apps.api.liaison_types import IdempotencyConflict
from solvan.application.liaison import (
    Anchor,
    AnchorError,
    resolve_anchor,
)
from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_catchup import catch_up
from solvan.persistence.liaison_parked import ParkedRequestStore
from solvan.persistence.liaison_policy import current_policy_epoch
from solvan.persistence.liaison_projection_grants import projection_read
from solvan.persistence.liaison_sequence import Cursor
from solvan.persistence.liaison_store import LiaisonStore, ThreadAccessError
from solvan.persistence.liaison_turn_control import (
    reject_parked_turn,
    resume_answered_parked_turn,
)


def register_turn_routes(
    router: APIRouter,
    *,
    connect: Callable[[], Any],
    scope_provider: Callable[[], Scope],
    principal_provider: Callable[[str | None], str],
    service: LiaisonService,
    steer: SteerService,
) -> None:
    _steer = steer

    @router.post("/api/v1/threads/{thread_id}/turns/{message_id}:cancel")
    def cancel_turn(
        thread_id: str,
        message_id: str,
        request: ExactTurnRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        if not idempotency_key:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Idempotency-Key is required")
        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        try:
            interrupted = service.cancel_turn(
                scope=scope,
                principal=principal,
                thread_id=thread_id,
                message_id=message_id,
                attempt=request.attempt,
                generation=request.generation,
                idempotency_key=idempotency_key,
            )
        except (IdempotencyConflict, ValueError) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        if not interrupted:
            raise HTTPException(status.HTTP_409_CONFLICT, "queued turn is no longer cancellable")
        return {"state": "INTERRUPTED", "terminal_reason": "USER_CANCELLED_BEFORE_START"}

    @router.post("/api/v1/threads/{thread_id}/turns/{message_id}:abort")
    def abort_turn(
        thread_id: str,
        message_id: str,
        request: ExactTurnRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        if not idempotency_key:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Idempotency-Key is required")
        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        try:
            interrupted = service.abort_turn(
                scope=scope,
                principal=principal,
                thread_id=thread_id,
                message_id=message_id,
                attempt=request.attempt,
                generation=request.generation,
                idempotency_key=idempotency_key,
            )
        except (IdempotencyConflict, ValueError) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        if not interrupted:
            raise HTTPException(status.HTTP_409_CONFLICT, "running turn no longer matches")
        return {"state": "INTERRUPTED", "terminal_reason": "USER_ABORTED"}

    @router.post("/api/v1/threads/{thread_id}/turns/{message_id}:stop-and-send")
    def stop_and_send(
        thread_id: str,
        message_id: str,
        request: StopAndSendRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        if not idempotency_key:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Idempotency-Key is required")
        try:
            outcome = service.stop_and_send(
                scope=scope_provider(),
                principal=principal_provider(human_identity_token),
                thread_id=thread_id,
                running_message_id=message_id,
                attempt=request.attempt,
                generation=request.generation,
                replacement=request.replacement,
                idempotency_key=idempotency_key,
            )
        except (IdempotencyConflict, ValueError) as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        return {
            "thread_id": outcome.thread_id,
            "user_message_id": outcome.user_message_id,
            "answer_message_id": outcome.answer_message_id,
            "state": outcome.durable_state or str(outcome.result.state),
            "attempt": outcome.attempt,
            "generation": outcome.generation,
            "queue_sequence": outcome.queue_sequence,
        }

    @router.get("/api/v1/liaison/catchup")
    def catchup(
        record_type: str,
        record_id: str,
        cursor: str | None = None,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        """What happened since the caller's cursor. No model in this path.

        The brief is a diff over committed rows: phrasing comes from the stored
        event, and every delta carries the authority status of its source, so a
        model-proposed hypothesis is never delivered as a verified fact (§6).
        """

        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        # The projection sync is an internal maintenance read.  The response
        # itself must use the principal-scoped reader; otherwise catch-up is a
        # snapshot-wide disclosure path even when transcript and Ask are
        # correctly filtered.
        reader = service.reader(principal=principal, scope=scope)
        if not reader.scope_authorized:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "record is not addressable")
        anchor = Anchor.record(record_type, record_id)
        try:
            resolve_anchor(reader, anchor)
        except AnchorError as error:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "record is not addressable") from error
        projection_reader = service.reader()

        authorized = tuple(reader.authorized_records_for_anchor(anchor))
        with connect() as connection, connection.transaction():
            sync_projection(LiaisonStore(connection), scope=scope, reader=projection_reader)
            sync_scope_events(connection, scope=scope, reader=projection_reader)
            # Derived, not assumed: a cursor minted before this reader's
            # authority changed is superseded rather than resumed.
            policy_epoch = current_policy_epoch(connection, scope=scope, principal=principal)
            with projection_read(
                connection,
                scope=scope,
                principal=principal,
                purpose="incident-investigation",
                classification_ceiling="CONFIDENTIAL",
                method="catch_up",
                operation_id=new_identifier("opr"),
                anchor_label=anchor.label(),
                authorized_records=authorized,
            ):
                brief = catch_up(
                    connection,
                    scope=scope,
                    anchor=anchor,
                    cursor=Cursor.decode(cursor, policy_epoch=policy_epoch),
                    authorized_records=authorized,
                    policy_epoch=policy_epoch,
                )
        return {
            "anchor": anchor.label(),
            "principal": principal,
            "cursor": brief.cursor.encode(),
            "policy_changed": brief.policy_changed,
            "remaining": brief.remaining,
            "deltas": [
                {
                    "sequence": delta.sequence,
                    "record": f"{delta.record_type}:{delta.record_id}",
                    "phrase": delta.phrase,
                    "authority_status": delta.authority_status,
                    "reference": delta.reference,
                }
                for delta in brief.deltas
            ],
        }

    @router.post("/api/v1/liaison/steer:draft")
    def steer_draft(
        request: SteerRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        """Park a typed step for confirmation. Nothing is requested yet (§15)."""

        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        reader = service.reader(principal=principal, scope=scope)
        if not reader.scope_authorized:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "record is not addressable")
        record = reader.read(request.anchor_record_type, request.anchor_record_id)
        if record is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "record is not addressable")
        try:
            anchor = resolve_anchor(
                reader, Anchor.record(request.anchor_record_type, request.anchor_record_id)
            )
        except AnchorError as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error

        with connect() as connection, connection.transaction():
            operation = "liaison.steer.draft"
            replay = _claim_json_operation(
                connection,
                scope=scope,
                key=idempotency_key,
                operation=operation,
                request={**request.model_dump(), "principal": principal},
            )
            if replay is not None:
                return replay
            store = LiaisonStore(connection)
            try:
                store.require_writable_thread(
                    scope=scope,
                    thread_id=request.thread_id,
                    anchor=anchor,
                    principal=principal,
                )
            except ThreadAccessError as error:
                raise HTTPException(_THREAD_STATUS[error.code], str(error)) from error
            message_id = store.append_message(
                scope=scope,
                thread_id=request.thread_id,
                role="LIAISON",
                classification="INTERNAL",
                turn_state="PARKED",
            )
            # Do not let the reader projection's optional display fields be
            # the only version fence.  The durable incident and its one
            # current accepted plan are the values the coordinator will
            # revalidate when this confirmation crosses the inbox boundary.
            version_row = connection.execute(
                """SELECT i.workflow_version,
                          (SELECT p.plan_version FROM solvan.investigation_plans p
                            WHERE p.organization_id=i.organization_id
                              AND p.project_id=i.project_id
                              AND p.environment_id=i.environment_id AND p.incident_id=i.id
                              AND p.status='ACCEPTED'
                            ORDER BY p.plan_version DESC LIMIT 1) AS plan_version
                     FROM solvan.incidents i
                    WHERE i.organization_id=%(organization_id)s
                      AND i.project_id=%(project_id)s
                      AND i.environment_id=%(environment_id)s
                      AND (i.id=%(anchor_id)s OR i.display_id=%(anchor_id)s)""",
                {**scope.canonical_dict(), "anchor_id": request.anchor_record_id},
            ).fetchone()
            if version_row is None:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    "a bounded Steer requires a current incident workflow anchor",
                )
            try:
                request_id = _steer.park_draft(
                    connection,
                    scope=scope,
                    thread_id=request.thread_id,
                    message_id=message_id,
                    draft=SteerDraft(
                        purpose=request.purpose,
                        agent="evidence-agent",
                        tool_profile=tuple(request.tool_profile),
                        budget="1 model · 3 tools",
                        anchor_record_type=request.anchor_record_type,
                        anchor_record_id=request.anchor_record_id,
                    ),
                    principal=principal,
                    expected_workflow_version=int(version_row[0]),
                    expected_plan_version=(None if version_row[1] is None else int(version_row[1])),
                )
            except SteerRefused as error:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error
            response = {"parked_request_id": request_id, "status": "PENDING"}
            _complete_json_operation(
                connection,
                scope=scope,
                key=idempotency_key or "",
                operation=operation,
                response=response,
            )
            return response

    @router.post("/api/v1/parked/{request_id}:answer")
    @router.post("/api/v1/liaison/parked/{request_id}:decide")
    def decide(
        request_id: str,
        request: DecideRequest,
        background_tasks: BackgroundTasks,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        """Resolve a parked request exactly once (§14).

        A steer confirmation additionally submits the typed envelope to the
        coordinator inbox, under a one-time grant addressed to that audience.
        """

        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        reader = service.reader(principal=principal, scope=scope)
        if not reader.scope_authorized:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "parked request is not addressable")

        prepared = None
        rejected = None
        with connect() as connection, connection.transaction():
            store = ParkedRequestStore(connection)
            parked = store.get(scope=scope, request_id=request_id)
            if parked is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "no such parked request")

            if parked.kind.value == "STEER_CONFIRMATION" and request.accept:
                record = reader.read(
                    str(parked.payload.get("anchor_record_type", "")),
                    str(parked.payload.get("anchor_record_id", "")),
                )
                try:
                    submission = _steer.confirm(
                        connection,
                        scope=scope,
                        request_id=request_id,
                        confirming_principal=principal,
                        decided_payload=request.decided_payload,
                        idempotency_key=idempotency_key,
                        current_workflow_version=(
                            int(record.get("workflow_version", 0)) or None if record else None
                        ),
                    )
                except SteerRefused as error:
                    raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
                return {
                    "outcome": "SUBMITTED",
                    "parked_request_id": request_id,
                    "coordinator_inbox_id": submission.inbox_id,
                    "decided_payload_hash": submission.envelope["decided_payload_hash"],
                }

            if parked.kind.value == "QUESTION" and request.accept and not request.answer:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "an accepted clarification requires an answer",
                )
            decision = store.decide(
                scope=scope,
                request_id=request_id,
                principal=principal,
                accept=request.accept,
                decided_payload=request.decided_payload,
                idempotency_key=idempotency_key,
                feedback=request.answer,
            )
            should_close_question = (
                decision.outcome.value in {"ACCEPTED", "REPLAYED"}
                and parked.kind.value == "QUESTION"
            )
            if should_close_question:
                if request.accept:
                    prepared = resume_answered_parked_turn(
                        connection, scope=scope, request_id=request_id
                    )
                else:
                    rejected = reject_parked_turn(connection, scope=scope, request_id=request_id)
        if decision.outcome.value in {"CONFLICT", "FORBIDDEN", "WIDENED"}:
            raise HTTPException(status.HTTP_409_CONFLICT, decision.reason)
        if prepared is not None:
            background_tasks.add_task(
                service.run_pending,
                scope=scope,
                thread_id=prepared.thread_id,
                target_message_id=prepared.answer_message_id,
            )
        return {
            "outcome": decision.outcome.value,
            "parked_request_id": request_id,
            "turn_state": prepared.state
            if prepared is not None
            else ("INTERRUPTED" if rejected is not None else None),
            "attempt": prepared.attempt if prepared is not None else None,
            "generation": prepared.generation if prepared is not None else None,
            "queue_sequence": prepared.queue_sequence if prepared is not None else None,
        }
