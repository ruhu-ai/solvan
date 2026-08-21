"""Participant membership and exact access-request routes."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status

from apps.api.liaison_http_support import (
    _THREAD_STATUS,
    AccessRequestDecision,
    ParticipantChangeRequest,
    _claim_json_operation,
    _complete_json_operation,
)
from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_channels import LiaisonChannelStore
from solvan.persistence.liaison_projection_grants import projection_read
from solvan.persistence.liaison_store import LiaisonStore, ThreadAccessError
from solvan.persistence.liaison_stream import append_stream_event


def register_participant_routes(
    router: APIRouter,
    *,
    connect: Callable[[], Any],
    scope_provider: Callable[[], Scope],
    principal_provider: Callable[[str | None], str],
) -> None:
    def require_directory_principal(connection: Any, *, scope: Scope, principal: str) -> None:
        """Reject arbitrary strings as people in the regional deployment.

        A participant target is an untrusted request field.  Production only
        admits identities present in the tenant's active role directory; the
        local development environment intentionally has no directory authority.
        """

        import os

        if os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE") != "GOOGLE_CLOUD_IAM":
            return
        if not principal.startswith("user:"):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "participant is not in the directory")
        row = connection.execute(
            """SELECT 1 FROM solvan.actor_role_bindings
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND principal=%(principal)s
                  AND (expires_at IS NULL OR expires_at > now())
                LIMIT 1""",
            {**scope.canonical_dict(), "principal": principal},
        ).fetchone()
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "participant is not in the directory")

    @router.get("/api/v1/threads/{thread_id}/participants")
    def participants(
        thread_id: str,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        with connect() as connection, connection.transaction():
            store = LiaisonStore(connection)
            roles = store.participant_roles(scope=scope, thread_id=thread_id)
            if principal not in roles:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "thread not found in this scope")
            thread = store.thread(scope=scope, thread_id=thread_id)
            if thread is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "thread not found in this scope")
            membership_epoch = store.current_membership_epoch(
                scope=scope, thread_id=thread_id, principal=principal
            )
            with projection_read(
                connection,
                scope=scope,
                principal=principal,
                purpose="conversation-collaboration",
                classification_ceiling="INTERNAL",
                method="list_participants",
                operation_id=new_identifier("opr"),
                anchor_label=thread.anchor.label(),
                authorized_records=(),
                membership_epoch=membership_epoch,
            ):
                result = [{"principal": item, "role": role} for item, role in sorted(roles.items())]
        return {
            "thread_id": thread_id,
            "participants": result,
        }

    @router.post("/api/v1/threads/{thread_id}/participants")
    def add_participant(
        thread_id: str,
        request: ParticipantChangeRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        operation = "liaison.participant.add"
        body = {
            "thread_id": thread_id,
            "principal": request.principal,
            "role": request.role,
            "actor": principal,
        }
        try:
            with connect() as connection, connection.transaction():
                require_directory_principal(connection, scope=scope, principal=request.principal)
                replay = _claim_json_operation(
                    connection,
                    scope=scope,
                    key=idempotency_key,
                    operation=operation,
                    request=body,
                )
                if replay is not None:
                    return replay
                epoch = LiaisonStore(connection).add_participant(
                    scope=scope,
                    thread_id=thread_id,
                    owner_principal=principal,
                    principal=request.principal,
                    role=request.role,
                )
                append_stream_event(
                    connection,
                    scope=scope,
                    thread_id=thread_id,
                    event_type="thread.membership.changed",
                    membership_epoch=epoch,
                    payload={
                        "change": "ADDED",
                        "principal": request.principal,
                        "role": request.role,
                    },
                )
                response = {
                    "thread_id": thread_id,
                    "principal": request.principal,
                    "role": request.role,
                    "membership_epoch": epoch,
                    "status": "ACTIVE",
                }
                _complete_json_operation(
                    connection,
                    scope=scope,
                    key=idempotency_key or "",
                    operation=operation,
                    response=response,
                )
                return response
        except ThreadAccessError as error:
            raise HTTPException(_THREAD_STATUS[error.code], str(error)) from error

    @router.delete("/api/v1/threads/{thread_id}/participants")
    def remove_participant(
        thread_id: str,
        request: ParticipantChangeRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        operation = "liaison.participant.remove"
        body = {"thread_id": thread_id, "principal": request.principal, "actor": principal}
        try:
            with connect() as connection, connection.transaction():
                replay = _claim_json_operation(
                    connection,
                    scope=scope,
                    key=idempotency_key,
                    operation=operation,
                    request=body,
                )
                if replay is not None:
                    return replay
                epoch = LiaisonStore(connection).remove_participant(
                    scope=scope,
                    thread_id=thread_id,
                    owner_principal=principal,
                    principal=request.principal,
                )
                LiaisonChannelStore(connection).stop_thread_for_participant(
                    scope=scope,
                    thread_id=thread_id,
                    principal=request.principal,
                    reason="MEMBERSHIP_ENDED",
                )
                append_stream_event(
                    connection,
                    scope=scope,
                    thread_id=thread_id,
                    event_type="thread.membership.changed",
                    membership_epoch=epoch,
                    payload={"change": "REMOVED", "principal": request.principal},
                )
                response = {
                    "thread_id": thread_id,
                    "principal": request.principal,
                    "membership_epoch": epoch,
                    "status": "REMOVED",
                }
                _complete_json_operation(
                    connection,
                    scope=scope,
                    key=idempotency_key or "",
                    operation=operation,
                    response=response,
                )
                return response
        except ThreadAccessError as error:
            raise HTTPException(_THREAD_STATUS[error.code], str(error)) from error

    @router.post("/api/v1/threads/{thread_id}/access-requests")
    def request_thread_access(
        thread_id: str,
        request: ParticipantChangeRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        """Ask an owner to admit a teammate without notifying the teammate."""

        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        operation = "liaison.access.request"
        body = {"thread_id": thread_id, "requested": request.principal, "actor": principal}
        with connect() as connection, connection.transaction():
            require_directory_principal(connection, scope=scope, principal=request.principal)
            replay = _claim_json_operation(
                connection,
                scope=scope,
                key=idempotency_key,
                operation=operation,
                request=body,
            )
            if replay is not None:
                return replay
            store = LiaisonStore(connection)
            if principal not in store.participants(scope=scope, thread_id=thread_id):
                raise HTTPException(status.HTTP_404_NOT_FOUND, "thread not found in this scope")
            request_id = new_identifier("lar")
            connection.execute(
                """INSERT INTO solvan_liaison.liaison_access_requests (
                      organization_id,project_id,environment_id,id,thread_id,
                      requested_principal,requested_by_principal,status,expires_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                      %(thread_id)s,%(requested)s,%(actor)s,'PENDING',now()+interval '24 hours')""",
                {**scope.canonical_dict(), "id": request_id, **body},
            )
            response = {"request_id": request_id, "status": "PENDING"}
            _complete_json_operation(
                connection,
                scope=scope,
                key=idempotency_key or "",
                operation=operation,
                response=response,
            )
            return response

    @router.get("/api/v1/threads/{thread_id}/access-requests")
    def pending_access_requests(
        thread_id: str,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        """List content-free pending requests for an owner decision."""

        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        with connect() as connection, connection.transaction():
            store = LiaisonStore(connection)
            roles = store.participant_roles(scope=scope, thread_id=thread_id)
            if roles.get(principal) != "OWNER":
                raise HTTPException(status.HTTP_404_NOT_FOUND, "thread not found in this scope")
            thread = store.thread(scope=scope, thread_id=thread_id)
            if thread is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "thread not found in this scope")
            membership_epoch = store.current_membership_epoch(
                scope=scope, thread_id=thread_id, principal=principal
            )
            with projection_read(
                connection,
                scope=scope,
                principal=principal,
                purpose="conversation-collaboration",
                classification_ceiling="INTERNAL",
                method="list_access_requests",
                operation_id=new_identifier("opr"),
                anchor_label=thread.anchor.label(),
                authorized_records=(),
                membership_epoch=membership_epoch,
            ):
                rows = connection.execute(
                    """SELECT id,requested_principal,requested_by_principal,expires_at
                         FROM solvan_liaison.liaison_access_requests
                        WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s AND thread_id=%(thread_id)s
                          AND status='PENDING' AND expires_at>now()
                        ORDER BY created_at""",
                    {**scope.canonical_dict(), "thread_id": thread_id},
                ).fetchall()
        return {
            "thread_id": thread_id,
            "requests": [
                {
                    "request_id": str(row[0]),
                    "requested_principal": str(row[1]),
                    "requested_by_principal": str(row[2]),
                    "expires_at": row[3].isoformat(),
                }
                for row in rows
            ],
        }

    @router.post("/api/v1/threads/{thread_id}/access-requests/{request_id}:decide")
    def decide_thread_access(
        thread_id: str,
        request_id: str,
        request: AccessRequestDecision,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        operation = "liaison.access.decide"
        body = {
            "thread_id": thread_id,
            "request_id": request_id,
            "approve": request.approve,
            "actor": principal,
        }
        try:
            with connect() as connection, connection.transaction():
                replay = _claim_json_operation(
                    connection,
                    scope=scope,
                    key=idempotency_key,
                    operation=operation,
                    request=body,
                )
                if replay is not None:
                    return replay
                store = LiaisonStore(connection)
                roles = store.participant_roles(scope=scope, thread_id=thread_id)
                if roles.get(principal) != "OWNER":
                    raise ThreadAccessError("FORBIDDEN", "only a thread owner may decide access")
                row = connection.execute(
                    """UPDATE solvan_liaison.liaison_access_requests
                          SET status=%(decision)s,decided_by_principal=%(actor)s,decided_at=now()
                        WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s AND id=%(id)s
                          AND thread_id=%(thread_id)s AND status='PENDING' AND expires_at>now()
                    RETURNING requested_principal""",
                    {
                        **scope.canonical_dict(),
                        "id": request_id,
                        "thread_id": thread_id,
                        "decision": "APPROVED" if request.approve else "DENIED",
                        "actor": principal,
                    },
                ).fetchone()
                if row is None:
                    raise HTTPException(
                        status.HTTP_409_CONFLICT, "access request is no longer pending"
                    )
                admitted = str(row[0])
                epoch = None
                if request.approve:
                    epoch = store.add_participant(
                        scope=scope,
                        thread_id=thread_id,
                        owner_principal=principal,
                        principal=admitted,
                    )
                    append_stream_event(
                        connection,
                        scope=scope,
                        thread_id=thread_id,
                        event_type="thread.membership.changed",
                        membership_epoch=epoch,
                        payload={"change": "ADDED", "principal": admitted, "role": "PARTICIPANT"},
                    )
                response = {
                    "request_id": request_id,
                    "status": "APPROVED" if request.approve else "DENIED",
                    "membership_epoch": epoch,
                }
                _complete_json_operation(
                    connection,
                    scope=scope,
                    key=idempotency_key or "",
                    operation=operation,
                    response=response,
                )
                return response
        except ThreadAccessError as error:
            raise HTTPException(_THREAD_STATUS[error.code], str(error)) from error
