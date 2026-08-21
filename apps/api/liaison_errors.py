"""Closed public error contract for conversational HTTP surfaces."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


@dataclass(frozen=True)
class LiaisonPublicError:
    code: str
    http_status: int
    retryable: bool
    safe_message: str


_ERRORS: dict[str, LiaisonPublicError] = {
    "INVALID_REQUEST": LiaisonPublicError("INVALID_REQUEST", 422, False, "The request is invalid."),
    "TEMPORARILY_UNAVAILABLE": LiaisonPublicError(
        "TEMPORARILY_UNAVAILABLE", 503, True, "The service is temporarily unavailable."
    ),
    "REVISION_CONFLICT": LiaisonPublicError(
        "REVISION_CONFLICT", 409, False, "The request conflicts with current state."
    ),
    "NOT_FOUND_OR_FORBIDDEN": LiaisonPublicError(
        "NOT_FOUND_OR_FORBIDDEN", 404, False, "The resource is unavailable."
    ),
    "THREAD_ARCHIVED": LiaisonPublicError("THREAD_ARCHIVED", 409, False, "The thread is archived."),
    "CURSOR_POLICY_CHANGED": LiaisonPublicError(
        "CURSOR_POLICY_CHANGED", 409, True, "The read policy changed; reload the thread."
    ),
    "CURSOR_HISTORY_EXPIRED": LiaisonPublicError(
        "CURSOR_HISTORY_EXPIRED", 410, True, "The requested history is no longer retained."
    ),
    "EVENT_BUFFER_OVERFLOW": LiaisonPublicError(
        "EVENT_BUFFER_OVERFLOW", 409, True, "The event stream must be resumed."
    ),
    "MANIFEST_INVALID": LiaisonPublicError(
        "MANIFEST_INVALID", 409, False, "The resolved execution manifest is invalid."
    ),
    "PARKED_REQUEST_EXPIRED": LiaisonPublicError(
        "PARKED_REQUEST_EXPIRED", 410, False, "The parked request expired."
    ),
    "PARKED_REQUEST_ALREADY_DECIDED": LiaisonPublicError(
        "PARKED_REQUEST_ALREADY_DECIDED", 409, False, "The parked request was already decided."
    ),
    "CHANNEL_BINDING_REVOKED": LiaisonPublicError(
        "CHANNEL_BINDING_REVOKED", 403, False, "The channel binding is unavailable."
    ),
    "RETENTION_PURGED": LiaisonPublicError(
        "RETENTION_PURGED", 410, False, "The requested content was purged."
    ),
    "DELEGATION_DENIED": LiaisonPublicError(
        "DELEGATION_DENIED", 403, False, "The operation is not permitted."
    ),
}

_LIAISON_PREFIXES = (
    "/api/v1/liaison",
    "/api/v1/threads",
    "/api/v1/parked",
    "/api/v1/subscriptions",
    "/api/v1/channels",
)


def is_liaison_path(path: str) -> bool:
    """Return whether the path is governed by the conversational registry."""

    return path.startswith(_LIAISON_PREFIXES)


def _registered_code(detail: Any, status_code: int) -> str:
    candidate = str(detail).strip() if isinstance(detail, str) else ""
    if candidate in _ERRORS:
        return candidate
    return {
        400: "INVALID_REQUEST",
        401: "NOT_FOUND_OR_FORBIDDEN",
        403: "DELEGATION_DENIED",
        404: "NOT_FOUND_OR_FORBIDDEN",
        409: "REVISION_CONFLICT",
        410: "RETENTION_PURGED",
        422: "INVALID_REQUEST",
        503: "TEMPORARILY_UNAVAILABLE",
    }.get(status_code, "TEMPORARILY_UNAVAILABLE")


def response_for(code: str) -> JSONResponse:
    error = _ERRORS[code]
    return JSONResponse(
        status_code=error.http_status,
        content={
            "error": {
                "code": error.code,
                "message": error.safe_message,
                "retryable": error.retryable,
            }
        },
    )


async def liaison_http_exception_handler(request: Request, error: HTTPException) -> JSONResponse:
    """Hide framework/provider details behind the closed registry."""

    return response_for(_registered_code(error.detail, error.status_code))


async def liaison_validation_exception_handler(
    request: Request, error: RequestValidationError
) -> JSONResponse:
    """Return a stable validation failure without reflecting input values."""

    return response_for("INVALID_REQUEST")
