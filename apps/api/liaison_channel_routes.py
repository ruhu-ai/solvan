"""Authenticated provider onboarding, channel binding, and revocation routes."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from collections.abc import Callable
from dataclasses import asdict
from typing import Any, Literal

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from apps.api.liaison_http_support import _claim_json_operation, _complete_json_operation
from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_channels import ChannelBindingError, LiaisonChannelStore
from solvan.persistence.liaison_projection_grants import projection_read
from solvan.platform.email_enrollment import EmailEnrollmentError, EmailEnrollmentSender

_EMAIL = re.compile(r"^[^\s@]{1,64}@[^\s@]{1,190}$")
_PROVIDER_KINDS = ("SLACK", "DISCORD", "EMAIL")


class EnrollmentRequest(BaseModel):
    """A channel choice, never a browser-asserted provider identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    channel_kind: Literal["EMAIL", "SLACK", "DISCORD"]
    email_address: str | None = Field(default=None, min_length=3, max_length=254)

    @model_validator(mode="after")
    def channel_inputs(self) -> EnrollmentRequest:
        if self.channel_kind == "EMAIL":
            normalized = self.email_address.casefold().strip() if self.email_address else ""
            if _EMAIL.fullmatch(normalized) is None:
                raise ValueError("a valid email address is required")
            object.__setattr__(self, "email_address", normalized)
        elif self.email_address is not None:
            raise ValueError("Slack and Discord identity comes from the signed provider event")
        return self


def _enrollment_nonce(*, key: str, material: str) -> str:
    secret = os.environ.get("SOLVAN_CHANNEL_ENROLLMENT_HMAC_KEY")
    if not secret:
        if os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE") == "GOOGLE_CLOUD_IAM":
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "channel enrollment is unavailable",
            )
        secret = "local-development-channel-enrollment-only"
    digest = hmac.new(secret.encode(), f"{key}\0{material}".encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")[:32]


def _production_mode() -> bool:
    return os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE") == "GOOGLE_CLOUD_IAM"


def channel_router(
    *,
    principal_provider: Callable[[str | None], str],
    scope_provider: Callable[[], Scope],
    connect: Callable[[], Any],
    email_sender_provider: Callable[[], EmailEnrollmentSender] | None = None,
) -> APIRouter:
    router = APIRouter()

    @router.get("/api/v1/channels/providers")
    def provider_statuses(
        identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        scope = scope_provider()
        principal = principal_provider(identity_token)
        with (
            connect() as connection,
            connection.transaction(),
            projection_read(
                connection,
                scope=scope,
                principal=principal,
                purpose="channel-administration",
                classification_ceiling="INTERNAL",
                method="list_channel_provider_health",
                operation_id=new_identifier("opr"),
                anchor_label="SCOPE",
                authorized_records=(),
            ),
        ):
            current = {
                receipt.channel_kind: receipt
                for receipt in LiaisonChannelStore(connection).current_provider_health(scope=scope)
            }
        providers: list[dict[str, Any]] = []
        for channel_kind in _PROVIDER_KINDS:
            receipt = current.get(channel_kind)
            if receipt is not None:
                providers.append(asdict(receipt))
            elif _production_mode():
                providers.append(
                    {
                        "channel_kind": channel_kind,
                        "status": "NOT_CONFIGURED",
                        "safe_reason_code": "NO_DEPLOYED_PATH_RECEIPT",
                        "next_step_code": "QUALIFY_PROVIDER_INSTALLATION",
                        "checked_at": None,
                        "expires_at": None,
                        "receipt_ref": None,
                        "deployment_id": None,
                        "service_revision": None,
                    }
                )
            else:
                providers.append(
                    {
                        "channel_kind": channel_kind,
                        "status": "AVAILABLE",
                        "safe_reason_code": "LOCAL_DEVELOPMENT_ONLY",
                        "next_step_code": "DEPLOY_AND_QUALIFY_FOR_PRODUCTION",
                        "checked_at": None,
                        "expires_at": None,
                        "receipt_ref": "local-development",
                        "deployment_id": "local",
                        "service_revision": "worktree",
                    }
                )
        return {
            "providers": providers,
            "authority": "PRODUCTION" if _production_mode() else "LOCAL_DEVELOPMENT",
        }

    @router.get("/api/v1/channels/bindings")
    def list_bindings(
        identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        scope = scope_provider()
        principal = principal_provider(identity_token)
        with (
            connect() as connection,
            connection.transaction(),
            projection_read(
                connection,
                scope=scope,
                principal=principal,
                purpose="channel-administration",
                classification_ceiling="INTERNAL",
                method="list_channel_bindings",
                operation_id=new_identifier("opr"),
                anchor_label="SCOPE",
                authorized_records=(),
            ),
        ):
            bindings = LiaisonChannelStore(connection).list_bindings(
                scope=scope, principal=principal
            )
        return {"bindings": bindings}

    @router.post("/api/v1/channels/enrollments", status_code=status.HTTP_201_CREATED)
    def issue_enrollment(
        request: EnrollmentRequest,
        identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        scope = scope_provider()
        principal = principal_provider(identity_token)
        if not idempotency_key:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Idempotency-Key is required")
        if _production_mode():
            with connect() as connection, connection.transaction():
                health = {
                    item.channel_kind: item
                    for item in LiaisonChannelStore(connection).current_provider_health(scope=scope)
                }.get(request.channel_kind)
            if health is None or health.status != "AVAILABLE":
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    "channel provider is not currently qualified",
                )
        channel_identity = (
            f"email:{request.email_address}" if request.channel_kind == "EMAIL" else None
        )
        nonce = _enrollment_nonce(
            key=idempotency_key,
            material="|".join(
                (
                    *scope.canonical_dict().values(),
                    principal,
                    request.channel_kind,
                    channel_identity or "provider-derived",
                )
            ),
        )
        callback = {
            "SLACK": "Send `solvan enroll <code>` to the installed Solvan app.",
            "DISCORD": "Run `/solvan enroll <code>` in the installed server.",
            "EMAIL": "Reply to the signed enrollment email with `solvan enroll <code>`.",
        }[request.channel_kind]
        challenge_id = ""
        try:
            with connect() as connection, connection.transaction():
                operation = "liaison.channel.enroll"
                replay = _claim_json_operation(
                    connection,
                    scope=scope,
                    key=idempotency_key,
                    operation=operation,
                    request={
                        "principal": principal,
                        "channel_kind": request.channel_kind,
                        "channel_identity": channel_identity,
                    },
                )
                if replay is not None:
                    challenge_id = str(replay["challenge_id"])
                else:
                    challenge_id = LiaisonChannelStore(connection).issue_enrollment(
                        scope=scope,
                        principal=principal,
                        channel_kind=request.channel_kind,
                        channel_identity=channel_identity,
                        nonce=nonce,
                        callback_mechanism=callback,
                    )
            with connect() as connection, connection.transaction():
                enrollment = LiaisonChannelStore(connection).enrollment(
                    scope=scope, challenge_id=challenge_id, principal=principal
                )
            if enrollment is None:
                raise ChannelBindingError("enrollment challenge is unavailable")
            if enrollment.status in {"FAILED", "CANCELLED", "EXPIRED"}:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    "enrollment challenge is no longer usable",
                )
            receipt_ref: str
            instruction: str
            expose_code = request.channel_kind != "EMAIL" or not _production_mode()
            if (
                enrollment.status == "REQUESTED"
                and request.channel_kind == "EMAIL"
                and _production_mode()
            ):
                if email_sender_provider is None:
                    raise EmailEnrollmentError("email enrollment sender is unavailable")
                receipt_ref = email_sender_provider().send(
                    address=request.email_address or "",
                    code=nonce,
                    challenge_id=challenge_id,
                )
                instruction = "Check your inbox and reply to the signed verification message."
            elif enrollment.status == "REQUESTED":
                receipt_ref = (
                    "local-development-email"
                    if request.channel_kind == "EMAIL"
                    else "provider-command"
                )
                instruction = callback.replace("<code>", nonce)
            else:
                receipt_ref = "already-dispatched"
                instruction = (
                    "Check your inbox and reply to the signed verification message."
                    if request.channel_kind == "EMAIL" and _production_mode()
                    else callback.replace("<code>", nonce)
                )
            with connect() as connection, connection.transaction():
                store = LiaisonChannelStore(connection)
                if enrollment.status == "REQUESTED" and not store.mark_enrollment_dispatched(
                    scope=scope,
                    challenge_id=challenge_id,
                    principal=principal,
                    receipt_ref=receipt_ref,
                ):
                    raise ChannelBindingError("enrollment dispatch could not be committed")
                _complete_json_operation(
                    connection,
                    scope=scope,
                    key=idempotency_key,
                    operation=operation,
                    response={
                        "challenge_id": challenge_id,
                        "channel_kind": request.channel_kind,
                    },
                )
        except EmailEnrollmentError as error:
            with connect() as connection, connection.transaction():
                LiaisonChannelStore(connection).fail_enrollment(
                    scope=scope,
                    challenge_id=challenge_id,
                    principal=principal,
                    reason_code="EMAIL_DELIVERY_REFUSED",
                )
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "email verification could not be delivered"
            ) from error
        except ChannelBindingError as error:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error
        response: dict[str, Any] = {
            "challenge_id": challenge_id,
            "channel_kind": request.channel_kind,
            "status": "DISPATCHED",
            "instruction": instruction,
            "expires_in_seconds": 600,
        }
        if expose_code:
            response["code"] = nonce
        return response

    @router.get("/api/v1/channels/enrollments/{challenge_id}")
    def enrollment_status(
        challenge_id: str,
        identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        scope = scope_provider()
        principal = principal_provider(identity_token)
        with connect() as connection, connection.transaction():
            enrollment = LiaisonChannelStore(connection).enrollment(
                scope=scope, challenge_id=challenge_id, principal=principal
            )
        if enrollment is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "enrollment challenge not found")
        return asdict(enrollment)

    @router.delete("/api/v1/channels/enrollments/{challenge_id}")
    def cancel_enrollment(
        challenge_id: str,
        identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, str]:
        if not idempotency_key:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Idempotency-Key is required")
        scope = scope_provider()
        principal = principal_provider(identity_token)
        with connect() as connection, connection.transaction():
            operation = "liaison.channel.enrollment.cancel"
            replay = _claim_json_operation(
                connection,
                scope=scope,
                key=idempotency_key,
                operation=operation,
                request={"challenge_id": challenge_id, "principal": principal},
            )
            if replay is not None:
                return {str(key): str(value) for key, value in replay.items()}
            cancelled = LiaisonChannelStore(connection).cancel_enrollment(
                scope=scope, challenge_id=challenge_id, principal=principal
            )
            if not cancelled:
                raise HTTPException(
                    status.HTTP_409_CONFLICT, "enrollment is not pending or was already finalized"
                )
            response = {"challenge_id": challenge_id, "status": "CANCELLED"}
            _complete_json_operation(
                connection,
                scope=scope,
                key=idempotency_key,
                operation=operation,
                response=response,
            )
            return response

    @router.delete("/api/v1/channels/bindings/{binding_id}")
    def revoke_binding(
        binding_id: str,
        identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, str]:
        if not idempotency_key:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Idempotency-Key is required")
        scope = scope_provider()
        principal = principal_provider(identity_token)
        with connect() as connection, connection.transaction():
            operation = "liaison.channel.revoke"
            replay = _claim_json_operation(
                connection,
                scope=scope,
                key=idempotency_key,
                operation=operation,
                request={"binding_id": binding_id, "principal": principal},
            )
            if replay is not None:
                return {str(key): str(value) for key, value in replay.items()}
            revoked = LiaisonChannelStore(connection).revoke_binding(
                scope=scope, binding_id=binding_id, principal=principal
            )
            if not revoked:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "active channel binding not found")
            response = {"binding_id": binding_id, "status": "REVOKED"}
            _complete_json_operation(
                connection,
                scope=scope,
                key=idempotency_key,
                operation=operation,
                response=response,
            )
            return response

    return router
