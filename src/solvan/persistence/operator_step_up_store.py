"""Durable, scoped operator presence proofs (specification 05 §4.2)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.operator_step_up import (
    ISSUANCE_WINDOW,
    MAX_ATTEMPTS,
    MAX_ISSUANCES_PER_WINDOW,
    IssuedPresenceCode,
    OperatorStepUpError,
)
from solvan.domain import Scope
from solvan.domain.identifiers import new_identifier


@dataclass(frozen=True, slots=True)
class LockedPresenceCode:
    code_id: str
    step_up_transaction_id: str
    requesting_session_id: str
    actor_id: str
    email: str
    verifier_hmac: str
    attempts: int
    delivery_status: str
    status: str
    expires_at: datetime


class OperatorStepUpStore:
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def verified_google_email(self, *, actor_id: str) -> str:
        row = self._connection.execute(
            """SELECT email FROM solvan_identity.external_identities
                WHERE actor_id=%s AND provider='GOOGLE'
                ORDER BY last_seen_at DESC LIMIT 1""",
            (actor_id,),
        ).fetchone()
        if row is None:
            raise OperatorStepUpError("the session is not backed by a Google identity")
        return str(row[0])

    def start(
        self,
        *,
        scope: Scope,
        step_up_transaction_id: str,
        requesting_session_id: str,
        actor_id: str,
        email: str,
        issued: IssuedPresenceCode,
        now: datetime,
    ) -> str:
        """Store a pending delivery after enforcing a durable issuance ceiling."""

        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT count(*) FROM solvan_identity.operator_step_up_codes
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND actor_id=%(actor)s AND created_at > %(window_start)s""",
                {
                    **scope.canonical_dict(),
                    "actor": actor_id,
                    "window_start": now - ISSUANCE_WINDOW,
                },
            )
            count = cursor.fetchone()
            if count is not None and int(count[0]) >= MAX_ISSUANCES_PER_WINDOW:
                raise OperatorStepUpError("too many step-up codes were requested; try later")

            # One browser session has one outstanding presence request. A new
            # request ends the prior one without erasing it, so the operator can
            # recover from a lost message and the rate limit remains auditable.
            cursor.execute(
                """UPDATE solvan_identity.operator_step_up_codes
                      SET status='TERMINAL', terminal_reason='SUPERSEDED',
                          terminal_at=%(now)s
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND requesting_session_id=%(session)s AND status='PENDING'""",
                {**scope.canonical_dict(), "session": requesting_session_id, "now": now},
            )
            code_id = new_identifier("sup")
            cursor.execute(
                """INSERT INTO solvan_identity.operator_step_up_codes
                     (id,step_up_transaction_id,requesting_session_id,actor_id,
                      organization_id,project_id,environment_id,email,verifier_hmac,
                      created_at,expires_at)
                   VALUES (%(id)s,%(step_up)s,%(session)s,%(actor)s,
                      %(organization_id)s,%(project_id)s,%(environment_id)s,%(email)s,
                      %(verifier)s,%(now)s,%(expires)s)""",
                {
                    **scope.canonical_dict(),
                    "id": code_id,
                    "step_up": step_up_transaction_id,
                    "session": requesting_session_id,
                    "actor": actor_id,
                    "email": email.strip().lower(),
                    "verifier": issued.verifier_hmac,
                    "now": now,
                    "expires": issued.expires_at,
                },
            )
            return code_id

    def mark_delivered(self, *, code_id: str, receipt: str, now: datetime) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_identity.operator_step_up_codes
                      SET delivery_status='DELIVERED', delivery_receipt=%s,
                          delivered_at=%s
                    WHERE id=%s AND status='PENDING' AND delivery_status='PENDING'""",
                (receipt, now, code_id),
            )
            if cursor.rowcount != 1:
                raise OperatorStepUpError("the step-up delivery is no longer pending")

    def mark_delivery_failed(self, *, code_id: str, now: datetime) -> None:
        self._connection.execute(
            """UPDATE solvan_identity.operator_step_up_codes
                  SET delivery_status='FAILED', status='TERMINAL',
                      terminal_reason='DELIVERY_FAILED', terminal_at=%s
                WHERE id=%s AND status='PENDING'""",
            (now, code_id),
        )

    def lock(self, *, scope: Scope, code_id: str) -> LockedPresenceCode | None:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,step_up_transaction_id,requesting_session_id,actor_id,
                          email,verifier_hmac,attempts,delivery_status,status,expires_at
                     FROM solvan_identity.operator_step_up_codes
                    WHERE id=%(id)s AND organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                    FOR UPDATE""",
                {**scope.canonical_dict(), "id": code_id},
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return LockedPresenceCode(
            code_id=str(row["id"]),
            step_up_transaction_id=str(row["step_up_transaction_id"]),
            requesting_session_id=str(row["requesting_session_id"]),
            actor_id=str(row["actor_id"]),
            email=str(row["email"]),
            verifier_hmac=str(row["verifier_hmac"]),
            attempts=int(row["attempts"]),
            delivery_status=str(row["delivery_status"]),
            status=str(row["status"]),
            expires_at=row["expires_at"],
        )

    def record_wrong_attempt(self, *, code_id: str, now: datetime) -> None:
        self._connection.execute(
            """UPDATE solvan_identity.operator_step_up_codes
                  SET attempts=attempts+1,
                      status=CASE WHEN attempts+1 >= %s THEN 'TERMINAL' ELSE status END,
                      terminal_reason=CASE WHEN attempts+1 >= %s
                        THEN 'ATTEMPTS_EXHAUSTED' ELSE terminal_reason END,
                      terminal_at=CASE WHEN attempts+1 >= %s THEN %s ELSE terminal_at END
                WHERE id=%s AND status='PENDING'""",
            (MAX_ATTEMPTS, MAX_ATTEMPTS, MAX_ATTEMPTS, now, code_id),
        )

    def end_expired(self, *, code_id: str, now: datetime) -> None:
        self._connection.execute(
            """UPDATE solvan_identity.operator_step_up_codes
                  SET status='TERMINAL', terminal_reason='EXPIRED', terminal_at=%s
                WHERE id=%s AND status='PENDING'""",
            (now, code_id),
        )

    def consume(self, *, code_id: str, now: datetime) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_identity.operator_step_up_codes
                      SET status='CONSUMED', consumed_at=%s
                    WHERE id=%s AND status='PENDING' AND delivery_status='DELIVERED'
                      AND expires_at > %s AND attempts < %s""",
                (now, code_id, now, MAX_ATTEMPTS),
            )
            if cursor.rowcount != 1:
                raise OperatorStepUpError("that step-up code is no longer usable")

    def record_presence(
        self,
        *,
        step_up_transaction_id: str,
        code_id: str,
        actor_id: str,
        requesting_session_id: str,
        resulting_session_id: str,
        now: datetime,
    ) -> str:
        presence_id = new_identifier("pev")
        self._connection.execute(
            """INSERT INTO solvan_identity.step_up_presence_events
                 (id,step_up_transaction_id,code_id,actor_id,requesting_session_id,
                  resulting_session_id,method,proven_at)
               VALUES (%s,%s,%s,%s,%s,%s,'EMAIL_OTP',%s)""",
            (
                presence_id,
                step_up_transaction_id,
                code_id,
                actor_id,
                requesting_session_id,
                resulting_session_id,
                now,
            ),
        )
        return presence_id


__all__ = ["LockedPresenceCode", "OperatorStepUpStore"]
