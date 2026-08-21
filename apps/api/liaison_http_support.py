"""The conversation API: governed reads, ledger writes, and explicit acts.

Conversation rows are mutable only through the typed, idempotent operations in
this module. The Liaison still has no production mutation capability: it reads
delegated projections, runs predicate/refusal gates, and may propose a steer
for coordinator adjudication, never dispatch or approve it.

Scope and principal are derived server-side and handed to the engine as a
grant; they never arrive in a request body or a model tool argument
(specification 14 §10.2).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from fastapi import HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from apps.api.liaison_reader import SnapshotProjectionReader
from solvan.application.liaison import (
    TemplateRegistry,
    TemplateRegistryError,
    load_registry,
    pin_registry,
)
from solvan.application.liaison.engine import (
    TurnResult,
    default_turn_budget,
    visible_parts,
)
from solvan.application.liaison.predicates import KNOWN_PREDICATES
from solvan.domain import Scope

_REGISTRY_PATH = Path(__file__).resolve().parents[2] / "config/liaison-claim-templates.yaml"
#: The exact registry the operator-facing sentence forms were reviewed at.
#: Changing config/liaison-claim-templates.yaml must change this in the same
#: commit; a mismatch refuses to serve rather than asserting new sentences.
_PINNED_REGISTRY_DIGEST = "sha256:d316cd6321de42ab7d94c89cbc20063c70a08781bf0d59ff2166e9326aab23c8"
_FINITE_REPLAY_PAGE_CEILING = 256
_CLIENT_EVENT_BUFFER_CEILING = 2_048

#: A refused thread reports why, without telling a stranger which of the four
#: reasons applied to a thread they cannot see: both absence and non-membership
#: are 404, so the endpoint is not an existence oracle.
_THREAD_STATUS = {
    "NOT_FOUND": status.HTTP_404_NOT_FOUND,
    "FORBIDDEN": status.HTTP_404_NOT_FOUND,
    "MISMATCHED": status.HTTP_409_CONFLICT,
    "CLOSED": status.HTTP_409_CONFLICT,
}


class AskRequest(BaseModel):
    """A question and its bounded conversation anchor. No principal or scope."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    question: str = Field(min_length=1, max_length=2_000)
    anchor_kind: Literal["RECORD", "SERVICE_WINDOW", "SCOPE"] = "RECORD"
    anchor_record_type: str | None = Field(default=None, min_length=1, max_length=40)
    anchor_record_id: str | None = Field(default=None, min_length=1, max_length=64)
    anchor_service_key: str | None = Field(default=None, min_length=1, max_length=120)
    anchor_window_start: datetime | None = None
    anchor_window_end: datetime | None = None
    #: Continues an existing conversation instead of opening one.
    thread_id: str | None = Field(default=None, pattern=r"^thr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    mentions: list[str] = Field(default_factory=list, max_length=16)

    @model_validator(mode="after")
    def validate_anchor(self) -> AskRequest:
        if self.anchor_kind == "RECORD":
            if not self.anchor_record_type or not self.anchor_record_id:
                raise ValueError("a record conversation requires record type and id")
            if self.anchor_service_key or self.anchor_window_start or self.anchor_window_end:
                raise ValueError("a record conversation carries no service window")
        elif self.anchor_kind == "SERVICE_WINDOW":
            if (
                not self.anchor_service_key
                or not self.anchor_window_start
                or not self.anchor_window_end
            ):
                raise ValueError("a service conversation requires a service and closed window")
            if self.anchor_record_type is not None or self.anchor_record_id is not None:
                raise ValueError("a service conversation carries no record")
            if self.anchor_window_end <= self.anchor_window_start:
                raise ValueError("a service window must end after it starts")
            if self.anchor_window_end - self.anchor_window_start > timedelta(hours=24):
                raise ValueError("a service window cannot exceed 24 hours")
            if self.thread_id is None:
                raise ValueError("a service conversation requires a receipt-opened thread")
        elif any(
            value is not None
            for value in (
                self.anchor_record_type,
                self.anchor_record_id,
                self.anchor_service_key,
                self.anchor_window_start,
                self.anchor_window_end,
            )
        ):
            raise ValueError("a scope conversation carries no client-supplied anchor")
        return self


class SteerRequest(BaseModel):
    """Draft a bounded read. The tool profile is validated server-side."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    thread_id: str = Field(pattern=r"^thr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    purpose: str = Field(min_length=1, max_length=400)
    anchor_record_type: str = Field(min_length=1, max_length=40)
    anchor_record_id: str = Field(min_length=1, max_length=64)
    tool_profile: list[str] = Field(min_length=1, max_length=8)


class DecideRequest(BaseModel):
    """Confirm or reject a parked request. Narrowing is allowed; widening is not."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    accept: bool
    decided_payload: dict[str, Any] | None = None
    answer: str | None = Field(default=None, min_length=1, max_length=2_000)


class ExactTurnRequest(BaseModel):
    """Attempt/generation fencing for cancel and abort."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    attempt: int = Field(ge=1)
    generation: int = Field(ge=1)


class StopAndSendRequest(ExactTurnRequest):
    replacement: str = Field(min_length=1, max_length=2_000)


class ReadCursorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    stream_sequence: int = Field(ge=0)


class ParticipantChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    principal: str = Field(min_length=1, max_length=320)
    role: Literal["OWNER", "PARTICIPANT"] = "PARTICIPANT"


class AccessRequestDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    approve: bool


class PartView(BaseModel):
    kind: str
    sequence: int
    payload: dict[str, Any]
    classification: str
    access_mode: str


class AskResponse(BaseModel):
    thread_id: str
    thread_anchor: str
    state: str
    user_message_id: str
    answer_message_id: str
    attempt: int
    generation: int
    queue_sequence: int | None = None
    model_calls: int = 0
    tool_calls: int = 0
    tokens: int = 0
    #: The ceilings this turn ran under, from the one configured source.
    budget: dict[str, int] = Field(default_factory=lambda: default_turn_budget().as_dict())
    parts: list[PartView]
    suggested: list[dict[str, str]]
    #: Counted composition defects, surfaced rather than buried in a log.
    defects: dict[str, int]


def liaison_registry() -> TemplateRegistry:
    """Load, pin and validate the template registry, or refuse to serve.

    A malformed or drifted registry is a startup-class failure: the surface
    would otherwise be free to assert whatever the file happens to permit.

    The pin lives here rather than in configuration on purpose. A deployment
    knob would let an edited template file reach production by setting the knob
    to whatever the file now says; a constant makes changing the operator-facing
    sentence forms and changing the pin one reviewed commit.
    """

    try:
        return pin_registry(
            load_registry(_REGISTRY_PATH, known_predicates=KNOWN_PREDICATES),
            _PINNED_REGISTRY_DIGEST,
        )
    except TemplateRegistryError as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"claim template registry is unusable: {error}",
        ) from error


def _operation_digest(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(encoded.encode()).hexdigest()}"


def _claim_json_operation(
    connection: Any,
    *,
    scope: Scope,
    key: str | None,
    operation: str,
    request: dict[str, Any],
) -> dict[str, Any] | None:
    """Claim a non-turn write or return its exact stored response."""

    if not key:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Idempotency-Key is required")
    request_hash = _operation_digest(request)
    params = {
        **scope.canonical_dict(),
        "key": key,
        "operation": operation,
        "request_hash": request_hash,
    }
    connection.execute(
        """INSERT INTO solvan_liaison.liaison_operation_ledger (
              organization_id,project_id,environment_id,idempotency_key,operation,
              request_hash,status,claim_token,expires_at)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(key)s,
              %(operation)s,%(request_hash)s,'PENDING',gen_random_uuid(),now()+interval '1 hour')
           ON CONFLICT (organization_id,project_id,environment_id,operation,idempotency_key)
           DO NOTHING""",
        params,
    )
    row = connection.execute(
        """SELECT status,response_ref,request_hash
             FROM solvan_liaison.liaison_operation_ledger
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND operation=%(operation)s
              AND idempotency_key=%(key)s FOR UPDATE""",
        params,
    ).fetchone()
    if row is None:
        raise RuntimeError("Liaison operation claim disappeared")
    if str(row[2]) != request_hash:
        raise HTTPException(status.HTTP_409_CONFLICT, "idempotency key request mismatch")
    if str(row[0]) == "COMPLETED" and row[1]:
        return dict(json.loads(str(row[1])))
    return None


def _complete_json_operation(
    connection: Any,
    *,
    scope: Scope,
    key: str,
    operation: str,
    response: dict[str, Any],
) -> None:
    connection.execute(
        """UPDATE solvan_liaison.liaison_operation_ledger
              SET status='COMPLETED',response_ref=%(response)s,completed_at=now()
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND operation=%(operation)s
              AND idempotency_key=%(key)s""",
        {
            **scope.canonical_dict(),
            "key": key,
            "operation": operation,
            "response": json.dumps(response, sort_keys=True),
        },
    )


def _view(result: TurnResult, reader: SnapshotProjectionReader, principal: str) -> list[PartView]:
    projected = visible_parts(
        result,
        reader_principal=principal,
        authorized_records=reader.authorized_records(),
        participants=(principal,),
    )
    return [
        PartView(
            kind=str(part.kind),
            sequence=part.sequence,
            payload=part.payload,
            classification=part.classification,
            access_mode=str(part.access_mode),
        )
        for part in projected
    ]
