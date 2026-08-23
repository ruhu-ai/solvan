"""Parked requests: one mechanism for every moment the engine waits on a human.

The whole design rests on one property — a decision is **linearizable**. Two
clients answering at once, an answer arriving after expiry, after a binding was
revoked, after the decider lost their role, or after the anchored entity moved
on: every one of those must lose, and exactly one terminal decision must exist.

So a decision is a single conditional UPDATE. Everything it must be true about
is in the WHERE clause, which means the database decides, not a read-then-write
sequence that can be overtaken between the read and the write.

Specification 14 §14, and fixtures 19-25.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from psycopg import Connection
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row

from solvan.application.liaison.grants import GrantError
from solvan.domain import Scope, new_identifier

#: A pending request expires no later than this, and often sooner — §14
#: computes the effective expiry as the earliest of several bounds.
PARKED_REQUEST_TTL = timedelta(hours=24)


class ParkedKind(StrEnum):
    QUESTION = "QUESTION"
    PERMISSION = "PERMISSION"
    STEER_CONFIRMATION = "STEER_CONFIRMATION"
    SUBSCRIPTION_CONFIRMATION = "SUBSCRIPTION_CONFIRMATION"


class DecisionOutcome(StrEnum):
    ACCEPTED = "ACCEPTED"
    #: The CAS lost. Something changed between display and decision.
    CONFLICT = "CONFLICT"
    #: An identical replay of a decision already made.
    REPLAYED = "REPLAYED"
    #: The decider is not permitted to answer this request.
    FORBIDDEN = "FORBIDDEN"
    #: A steer decision that widened what was displayed.
    WIDENED = "WIDENED"


@dataclass(frozen=True, slots=True)
class ParkedRequest:
    id: str
    thread_id: str
    message_id: str
    kind: ParkedKind
    payload: dict[str, Any]
    payload_hash: str
    row_version: int
    initiated_by_principal: str
    answer_audience: str
    named_answerer_principal: str | None
    expected_workflow_version: int | None
    expected_plan_version: int | None
    binding_id: str | None
    binding_epoch: int | None
    status: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class Decision:
    outcome: DecisionOutcome
    request_id: str
    #: What actually proceeds — the displayed payload, or a narrowed amendment.
    decided_payload: dict[str, Any] | None = None
    decided_payload_hash: str | None = None
    reason: str = ""


def payload_digest(payload: dict[str, Any]) -> str:
    """What was shown is what is decided, so the digest binds the display."""

    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return f"sha256:{hashlib.sha256(encoded.encode()).hexdigest()}"


def is_narrowing(displayed: dict[str, Any], decided: dict[str, Any]) -> bool:
    """A decision may shrink what was offered; it may never grow it.

    Narrowing is checked structurally rather than trusted: the key set must be
    exactly what was displayed, every scalar unchanged, and every collection a
    subset. A widened decision is refused and needs a fresh draft (§14).

    Dropping a key is not narrowing. A step that arrives at the coordinator
    without the field that bounded it — its tool profile, its budget, its
    anchor — is a step with no stated bound, which is the opposite of narrower.
    """

    if set(decided) != set(displayed):
        return False
    for key, value in decided.items():
        original = displayed[key]
        if isinstance(value, list) and isinstance(original, list):
            if not set(map(str, value)) <= set(map(str, original)):
                return False
        elif value != original:
            return False
    return True


class ParkedRequestStore:
    """Every decision is one CAS; nothing here reads-then-writes."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def park(
        self,
        *,
        scope: Scope,
        thread_id: str,
        message_id: str,
        kind: ParkedKind,
        payload: dict[str, Any],
        initiated_by_principal: str,
        answer_audience: str = "INITIATOR",
        named_answerer_principal: str | None = None,
        expected_workflow_version: int | None = None,
        expected_plan_version: int | None = None,
        binding_id: str | None = None,
        binding_epoch: int | None = None,
        expires_at: datetime | None = None,
        request_id: str | None = None,
    ) -> str:
        """Persist a request and the exact object the principal was shown."""

        request_id = request_id or new_identifier("prk")
        self._connection.execute(
            """INSERT INTO solvan_liaison.liaison_parked_requests (
                  organization_id, project_id, environment_id, id, thread_id,
                  message_id, kind, payload_json, payload_hash, answer_audience,
                  named_answerer_principal, initiated_by_principal,
                  expected_workflow_version, expected_plan_version,
                  binding_id, binding_epoch, status, expires_at)
               VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                  %(id)s, %(thread_id)s, %(message_id)s, %(kind)s, %(payload)s,
                  %(payload_hash)s, %(answer_audience)s, %(named)s, %(initiator)s,
                  %(workflow_version)s, %(plan_version)s, %(binding_id)s,
                  %(binding_epoch)s, 'PENDING', %(expires_at)s)""",
            {
                **scope.canonical_dict(),
                "id": request_id,
                "thread_id": thread_id,
                "message_id": message_id,
                "kind": str(kind),
                "payload": json.dumps(payload, default=str),
                "payload_hash": payload_digest(payload),
                "answer_audience": answer_audience,
                "named": named_answerer_principal,
                "initiator": initiated_by_principal,
                "workflow_version": expected_workflow_version,
                "plan_version": expected_plan_version,
                "binding_id": binding_id,
                "binding_epoch": binding_epoch,
                "expires_at": expires_at or datetime.now(UTC) + PARKED_REQUEST_TTL,
            },
        )
        return request_id

    def get(self, *, scope: Scope, request_id: str) -> ParkedRequest | None:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT * FROM solvan_liaison.liaison_parked_requests
                   WHERE organization_id = %(organization_id)s
                     AND project_id = %(project_id)s
                     AND environment_id = %(environment_id)s AND id = %(id)s""",
                {**scope.canonical_dict(), "id": request_id},
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return ParkedRequest(
            id=str(row["id"]),
            thread_id=str(row["thread_id"]),
            message_id=str(row["message_id"]),
            kind=ParkedKind(str(row["kind"])),
            payload=dict(row["payload_json"]),
            payload_hash=str(row["payload_hash"]),
            row_version=int(row["row_version"]),
            initiated_by_principal=str(row["initiated_by_principal"]),
            answer_audience=str(row["answer_audience"]),
            named_answerer_principal=row["named_answerer_principal"],
            expected_workflow_version=row["expected_workflow_version"],
            expected_plan_version=row["expected_plan_version"],
            binding_id=row["binding_id"],
            binding_epoch=row["binding_epoch"],
            status=str(row["status"]),
            expires_at=row["expires_at"],
        )

    def may_answer(self, request: ParkedRequest, principal: str) -> bool:
        """Who is permitted to decide, before any authority check on the anchor.

        The rule differs by kind, because the requests differ in nature. A
        clarifying question belongs to the person who was asked — a bystander
        answering on their behalf would put words in the turn's mouth. A steer
        confirmation belongs to *whoever holds operator role on the anchored
        entity*, which is a property of the anchor rather than of who drafted
        it; that role is checked by the caller before the CAS (§14).
        """

        if request.kind is ParkedKind.STEER_CONFIRMATION:
            return True
        if request.answer_audience == "NAMED":
            return principal in {request.initiated_by_principal, request.named_answerer_principal}
        return principal == request.initiated_by_principal

    def decide(
        self,
        *,
        scope: Scope,
        request_id: str,
        principal: str,
        accept: bool,
        decided_payload: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        feedback: str | None = None,
        current_workflow_version: int | None = None,
        current_plan_version: int | None = None,
        binding_epoch: int | None = None,
        now: datetime | None = None,
    ) -> Decision:
        """Resolve a parked request, exactly once.

        Everything that must still be true is in the WHERE clause: the row is
        pending, unexpired, at the version we read, its displayed payload
        unchanged, and — for a steer — the anchored entity has not moved on.
        """

        moment = now or datetime.now(UTC)
        request = self.get(scope=scope, request_id=request_id)
        if request is None:
            return Decision(DecisionOutcome.CONFLICT, request_id, reason="no such request")

        # A replay of the same decision returns the original outcome rather
        # than a conflict: the caller did nothing wrong.
        if request.status in {"ANSWERED", "REJECTED"} and idempotency_key:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    """SELECT decision_idempotency_key, decided_payload_json
                       FROM solvan_liaison.liaison_parked_requests
                       WHERE organization_id = %(organization_id)s
                         AND project_id = %(project_id)s
                         AND environment_id = %(environment_id)s AND id = %(id)s""",
                    {**scope.canonical_dict(), "id": request_id},
                )
                row = cursor.fetchone()
            if row and row[0] == idempotency_key:
                decided = dict(row[1]) if row[1] else request.payload
                return Decision(
                    DecisionOutcome.REPLAYED,
                    request_id,
                    decided_payload=decided,
                    decided_payload_hash=payload_digest(decided),
                )

        if not self.may_answer(request, principal):
            return Decision(
                DecisionOutcome.FORBIDDEN,
                request_id,
                reason="this request is not addressed to you",
            )

        payload = decided_payload if decided_payload is not None else request.payload
        if decided_payload is not None and not is_narrowing(request.payload, decided_payload):
            return Decision(
                DecisionOutcome.WIDENED,
                request_id,
                reason="a decision may narrow what was shown, never widen it",
            )

        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_liaison.liaison_parked_requests
                   SET status = %(status)s,
                       decided_payload_json = %(decided)s,
                       decided_payload_hash = %(decided_hash)s,
                       answer_json = %(answer)s,
                       answered_by_principal = %(principal)s,
                       decision_idempotency_key = %(key)s,
                       row_version = row_version + 1,
                       answered_at = now()
                   WHERE organization_id = %(organization_id)s
                     AND project_id = %(project_id)s
                     AND environment_id = %(environment_id)s
                     AND id = %(id)s
                     AND status = 'PENDING'
                     AND expires_at > %(now)s
                     AND row_version = %(row_version)s
                     AND payload_hash = %(payload_hash)s
                     -- A row that named a version demands one back. If the
                     -- caller could not read the anchor's current version, the
                     -- comparison is NULL and the CAS loses: absence refuses
                     -- rather than waving the guard through.
                     AND (
                       (binding_id IS NULL AND binding_epoch IS NULL)
                       OR (
                         binding_id IS NOT NULL
                         AND binding_epoch IS NOT NULL
                         AND binding_epoch = %(binding_epoch)s::bigint
                       )
                     )
                     AND (expected_workflow_version IS NULL
                          OR expected_workflow_version = %(workflow_version)s::bigint)
                     AND (expected_plan_version IS NULL
                          OR expected_plan_version = %(plan_version)s::integer)
                   RETURNING id""",
                {
                    **scope.canonical_dict(),
                    "id": request_id,
                    "status": "ANSWERED" if accept else "REJECTED",
                    "decided": json.dumps(payload, default=str),
                    "decided_hash": payload_digest(payload),
                    "answer": json.dumps({"feedback": feedback} if feedback else {}),
                    "principal": principal,
                    "key": idempotency_key,
                    "row_version": request.row_version,
                    "payload_hash": request.payload_hash,
                    "now": moment,
                    "binding_epoch": binding_epoch,
                    "workflow_version": current_workflow_version,
                    "plan_version": current_plan_version,
                },
            )
            won = cursor.fetchone() is not None

        if not won:
            return Decision(
                DecisionOutcome.CONFLICT,
                request_id,
                reason="the request expired, was already decided, or its context moved on",
            )
        # Accept and reject are both terminal decisions that won the CAS; the
        # difference is what the caller does next, not whether it succeeded.
        return Decision(
            DecisionOutcome.ACCEPTED,
            request_id,
            decided_payload=payload,
            decided_payload_hash=payload_digest(payload),
            reason="" if accept else "rejected by the decider",
        )

    def expire_due(self, *, scope: Scope, now: datetime | None = None) -> int:
        """Close requests nobody answered, so a turn is never parked forever."""

        moment = now or datetime.now(UTC)
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_liaison.liaison_parked_requests
                   SET status = 'EXPIRED'
                   WHERE organization_id = %(organization_id)s
                     AND project_id = %(project_id)s
                     AND environment_id = %(environment_id)s
                     AND status = 'PENDING' AND expires_at <= %(now)s
                   RETURNING id""",
                {**scope.canonical_dict(), "now": moment},
            )
            return len(cursor.fetchall())


def consume_steer_nonce(
    connection: Any,
    *,
    scope: Scope,
    nonce: str,
    grant_digest: str,
    parked_request_id: str,
    confirming_principal: str,
) -> None:
    """Spend a steer-grant nonce durably, or refuse a replay.

    The issuer's in-memory set survives neither a restart nor a second
    serving instance, so once-only was in truth borrowed from the parked
    decision's idempotency. This row is the grant's own guarantee: the
    primary key makes a second consumption a unique violation whichever
    instance attempts it, and the insert commits in the same transaction as
    the coordinator-inbox submission it authorizes.
    """

    try:
        connection.execute(
            """INSERT INTO solvan_liaison.liaison_consumed_steer_grants
                (organization_id, project_id, environment_id, nonce,
                 grant_digest, parked_request_id, confirming_principal)
               VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                 %(nonce)s, %(grant_digest)s, %(parked_request_id)s,
                 %(confirming_principal)s)""",
            {
                **scope.canonical_dict(),
                "nonce": nonce,
                "grant_digest": grant_digest,
                "parked_request_id": parked_request_id,
                "confirming_principal": confirming_principal,
            },
        )
    except UniqueViolation as error:
        raise GrantError("the steer submission grant has already been used") from error
