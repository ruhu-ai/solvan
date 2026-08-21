"""Explicit, audited subscription lifecycle routes for the Liaison."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from apps.api.liaison_http_support import _claim_json_operation, _complete_json_operation
from apps.api.liaison_reader import SnapshotProjectionReader
from solvan.application.liaison import Anchor, AnchorError, resolve_anchor
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_policy import current_policy_epoch
from solvan.persistence.liaison_projection_grants import projection_read
from solvan.persistence.liaison_subscriptions import (
    Cadence,
    LiaisonSubscriptionStore,
    SubscriptionError,
)


class SubscriptionRequest(BaseModel):
    """An explicit console act; principal and scope are never body fields."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    anchor_record_type: str = Field(min_length=1, max_length=40)
    anchor_record_id: str = Field(min_length=1, max_length=64)
    cadence: Cadence
    channel_binding_id: str | None = Field(
        default=None, pattern=r"^chb_[0-7][0-9A-HJKMNP-TV-Z]{25}$"
    )
    external_conversation_id: str | None = Field(default=None, min_length=1, max_length=240)
    expires_at: datetime | None = None


def subscription_router(
    *,
    principal_provider: Callable[[str | None], str],
    scope_provider: Callable[[], Scope],
    connect: Callable[[], Any],
    reader_provider: Callable[..., SnapshotProjectionReader],
) -> APIRouter:
    router = APIRouter()

    @router.get("/api/v1/subscriptions")
    def list_subscriptions(
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        reader = reader_provider(principal=principal, scope=scope)
        if not reader.scope_authorized:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "subscriptions are unavailable")
        with (
            connect() as connection,
            connection.transaction(),
            projection_read(
                connection,
                scope=scope,
                principal=principal,
                purpose="incident-investigation",
                classification_ceiling="CONFIDENTIAL",
                method="list_subscriptions",
                operation_id=new_identifier("opr"),
                anchor_label="SCOPE",
                authorized_records=reader.authorized_records(),
            ),
        ):
            subscriptions = LiaisonSubscriptionStore(connection).list_for_principal(
                scope=scope, principal=principal
            )
        return {"subscriptions": subscriptions}

    @router.post("/api/v1/subscriptions", status_code=status.HTTP_201_CREATED)
    def create_subscription(
        request: SubscriptionRequest,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        if not idempotency_key or len(idempotency_key) > 200:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Idempotency-Key is required")
        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        reader = reader_provider(principal=principal, scope=scope)
        try:
            anchor = resolve_anchor(
                reader, Anchor.record(request.anchor_record_type, request.anchor_record_id)
            )
        except AnchorError as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error
        if (request.anchor_record_type, request.anchor_record_id) not in set(
            reader.authorized_records_for_anchor(anchor)
        ):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "record is not addressable")
        request_hash = canonical_sha256(
            {"principal": principal, "anchor": anchor.canonical_dict(), **request.model_dump()}
        )
        with connect() as connection, connection.transaction():
            operation = "liaison.subscription.create"
            operation_args = {
                **scope.canonical_dict(),
                "operation": operation,
                "idempotency_key": idempotency_key,
                "request_hash": request_hash,
            }
            # The unique ledger insert is the concurrency gate. ON CONFLICT
            # waits for an in-flight winner; the subsequent row lock then
            # observes exactly one request hash and, when complete, one result.
            connection.execute(
                """INSERT INTO solvan_liaison.liaison_operation_ledger (
                      organization_id,project_id,environment_id,idempotency_key,
                      operation,request_hash,status,claim_token,expires_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(idempotency_key)s,%(operation)s,%(request_hash)s,'PENDING',
                      gen_random_uuid(),now() + interval '1 hour')
                   ON CONFLICT (organization_id,project_id,environment_id,operation,
                      idempotency_key) DO NOTHING""",
                operation_args,
            )
            prior = connection.execute(
                """SELECT status,response_ref,request_hash
                   FROM solvan_liaison.liaison_operation_ledger
                   WHERE organization_id=%(organization_id)s
                     AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                     AND operation=%(operation)s AND idempotency_key=%(idempotency_key)s
                   FOR UPDATE""",
                operation_args,
            ).fetchone()
            if prior is None:  # pragma: no cover - insertion and read share one transaction
                raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "operation claim lost")
            if str(prior[2]) != request_hash:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    "Idempotency-Key was already used for different subscription material",
                )
            if prior[0] == "COMPLETED" and prior[1]:
                response = json.loads(str(prior[1]))
                return {**response, "replayed": True}
            if prior[0] != "PENDING":
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    "the prior subscription operation did not complete",
                )
            policy_epoch = current_policy_epoch(connection, scope=scope, principal=principal)
            consent_id = new_identifier("aud")
            try:
                subscription_id = LiaisonSubscriptionStore(connection).create(
                    scope=scope,
                    principal=principal,
                    anchor=anchor,
                    cadence=request.cadence,
                    consent_kind="CONSOLE_ACTION",
                    consent_ref=consent_id,
                    policy_epoch=policy_epoch,
                    channel_binding_id=request.channel_binding_id,
                    external_conversation_id=request.external_conversation_id,
                    expires_at=request.expires_at,
                )
            except SubscriptionError as error:
                raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
            connection.execute(
                """INSERT INTO solvan.audit_events
                     (organization_id,project_id,environment_id,id,stream_type,stream_id,
                      event_type,actor_principal,decision_ref,payload_hash)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                      'LIAISON_SUBSCRIPTION_REQUEST',%(stream_id)s,'SubscriptionConfirmed',
                      %(principal)s,%(idempotency_key)s,%(payload_hash)s)""",
                {
                    **scope.canonical_dict(),
                    "id": consent_id,
                    "stream_id": subscription_id,
                    "principal": principal,
                    "idempotency_key": idempotency_key,
                    "payload_hash": request_hash,
                },
            )
            connection.execute(
                """UPDATE solvan_liaison.liaison_operation_ledger
                   SET status='COMPLETED',response_ref=%(response_ref)s,completed_at=now()
                   WHERE organization_id=%(organization_id)s
                     AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                     AND operation=%(operation)s AND idempotency_key=%(idempotency_key)s""",
                {
                    **operation_args,
                    "response_ref": json.dumps(
                        {"subscription_id": subscription_id, "status": "ACTIVE"}
                    ),
                },
            )
        return {"subscription_id": subscription_id, "status": "ACTIVE", "replayed": False}

    @router.delete("/api/v1/subscriptions/{subscription_id}")
    def end_subscription(
        subscription_id: str,
        human_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, str]:
        scope = scope_provider()
        principal = principal_provider(human_identity_token)
        with connect() as connection, connection.transaction():
            operation = "liaison.subscription.end"
            replay = _claim_json_operation(
                connection,
                scope=scope,
                key=idempotency_key,
                operation=operation,
                request={"subscription_id": subscription_id, "principal": principal},
            )
            if replay is not None:
                return {str(key): str(value) for key, value in replay.items()}
            if not LiaisonSubscriptionStore(connection).end(
                scope=scope, subscription_id=subscription_id, principal=principal
            ):
                raise HTTPException(status.HTTP_404_NOT_FOUND, "active subscription not found")
            connection.execute(
                """INSERT INTO solvan.audit_events
                     (organization_id,project_id,environment_id,id,stream_type,stream_id,
                      event_type,actor_principal,payload_hash)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                      'LIAISON_SUBSCRIPTION',%(stream_id)s,'SubscriptionEnded',%(principal)s,
                      %(payload_hash)s)""",
                {
                    **scope.canonical_dict(),
                    "id": new_identifier("aud"),
                    "stream_id": subscription_id,
                    "principal": principal,
                    "payload_hash": canonical_sha256(
                        {"subscription_id": subscription_id, "principal": principal}
                    ),
                },
            )
            response = {"subscription_id": subscription_id, "status": "ENDED"}
            _complete_json_operation(
                connection,
                scope=scope,
                key=idempotency_key or "",
                operation=operation,
                response=response,
            )
            return response

    return router
