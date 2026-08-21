"""Persisted channel answers, idempotency, grants, and audit."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from psycopg import Connection

from apps.api.liaison_projection_sync import sync_projection
from apps.api.liaison_types import (
    EMPTY_DEFECTS,
    EMPTY_USAGE,
    IdempotencyConflict,
    TurnOutcome,
    request_digest,
)
from solvan.application.liaison import Anchor
from solvan.application.liaison.claims import CompositionDefects
from solvan.application.liaison.engine import TurnResult, TurnState, TurnUsage
from solvan.application.liaison.intents import (
    resolve_intent,
)
from solvan.application.liaison.parts import Part, PartKind
from solvan.application.liaison.redaction import Verdict
from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_manifest import canonical_hash
from solvan.persistence.liaison_policy import current_policy_epoch
from solvan.persistence.liaison_runtime import (
    prepare_turn,
)
from solvan.persistence.liaison_store import LiaisonStore, ThreadAccessError


class LiaisonChannelMixin:
    """Internal mixin; LiaisonService supplies the shared composition state."""

    _connect: Any
    reader: Any
    _resolve_follow_up_candidates: Any
    _source_versions: Any
    _drain_thread: Any
    _durable_state: Any

    def answer_persisted_channel_message(
        self,
        *,
        scope: Scope,
        principal: str,
        anchor: Anchor,
        thread_id: str,
        user_message_id: str,
        idempotency_key: str,
    ) -> TurnOutcome:
        """Accept an already-redacted channel message into the same turn lane."""

        reader = self.reader(principal=principal, scope=scope)
        if not reader.scope_authorized:
            raise ThreadAccessError("FORBIDDEN", "principal is not authorized for this scope")
        with self._connect() as connection, connection.transaction():
            store = LiaisonStore(connection)
            sync_projection(store, scope=scope, reader=reader)
            store.require_writable_thread(
                scope=scope, thread_id=thread_id, anchor=anchor, principal=principal
            )
            row = connection.execute(
                """SELECT m.classification,m.content_hash,p.payload_json
                    FROM solvan_liaison.liaison_messages m
                    JOIN solvan_liaison.liaison_message_parts p ON
                      (p.organization_id,p.project_id,p.environment_id,p.message_id)=
                      (m.organization_id,m.project_id,m.environment_id,m.id)
                    WHERE m.organization_id=%(organization_id)s
                      AND m.project_id=%(project_id)s AND m.environment_id=%(environment_id)s
                      AND m.id=%(message_id)s AND m.thread_id=%(thread_id)s
                      AND m.role='USER' AND m.author_principal=%(principal)s
                      AND m.deleted_at IS NULL AND p.sequence=0 AND p.kind='text'""",
                {
                    **scope.canonical_dict(),
                    "message_id": user_message_id,
                    "thread_id": thread_id,
                    "principal": principal,
                },
            ).fetchone()
            if row is None:
                raise IdempotencyConflict("channel message is not addressable")
            claimed = self._claim_operation(
                connection,
                scope=scope,
                key=idempotency_key,
                operation="liaison.channel.answer",
                request_hash=request_digest(
                    principal=principal,
                    anchor=anchor.label(),
                    question=str(row[1] or ""),
                    thread_id=thread_id,
                ),
            )
            if claimed is not None:
                return claimed
            if str(row[0]) == "RESTRICTED":
                from solvan.application.liaison.parts import refusal_part

                refusal = refusal_part(
                    sequence=0,
                    reason="Inbound content was withheld before persistence and model use.",
                    releasing_record=None,
                )
                answer_message = store.append_message(
                    scope=scope,
                    thread_id=thread_id,
                    role="LIAISON",
                    classification="INTERNAL",
                    in_reply_to=user_message_id,
                )
                store.append_parts(scope=scope, message_id=answer_message, parts=[refusal])
                result = TurnResult(
                    TurnState.COMPLETED, (refusal,), TurnUsage(), CompositionDefects()
                )
                self._complete_operation(
                    connection,
                    scope=scope,
                    key=idempotency_key,
                    operation="liaison.channel.answer",
                    response={
                        "thread_id": thread_id,
                        "user_message_id": user_message_id,
                        "answer_message_id": answer_message,
                        "durable_state": "COMPLETED",
                    },
                )
                return TurnOutcome(
                    thread_id,
                    user_message_id,
                    answer_message,
                    result,
                    durable_state="COMPLETED",
                )
            question = str(dict(row[2]).get("sentence", ""))
            has_prior = connection.execute(
                """SELECT 1 FROM solvan_liaison.liaison_messages
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND thread_id=%(thread_id)s
                      AND role='LIAISON' AND turn_state='COMPLETED' LIMIT 1""",
                {**scope.canonical_dict(), "thread_id": thread_id},
            ).fetchone()
            resolution = resolve_intent(question, has_prior_answer=has_prior is not None)
            resolved_references = self._resolve_follow_up_candidates(
                connection,
                scope=scope,
                thread_id=thread_id,
                principal=principal,
                question=question,
                intent=resolution.intent,
            )
            prepared = prepare_turn(
                connection,
                scope=scope,
                principal=principal,
                policy_epoch=current_policy_epoch(connection, scope=scope, principal=principal),
                thread_id=thread_id,
                user_message_id=user_message_id,
                intent=str(resolution.intent),
                authority_route=resolution.authority_route,
                resolved_references=resolved_references,
                source_versions=self._source_versions(anchor, principal=principal, scope=scope),
            )
            self._complete_operation(
                connection,
                scope=scope,
                key=idempotency_key,
                operation="liaison.channel.answer",
                response={
                    "thread_id": thread_id,
                    "user_message_id": user_message_id,
                    "answer_message_id": prepared.answer_message_id,
                    "durable_state": prepared.state,
                    "attempt": prepared.attempt,
                    "generation": prepared.generation,
                    "queue_sequence": prepared.queue_sequence,
                },
            )
        if prepared.state == "QUEUED":
            return TurnOutcome(
                thread_id,
                user_message_id,
                prepared.answer_message_id,
                TurnResult(TurnState.STREAMING, (), EMPTY_USAGE, EMPTY_DEFECTS),
                durable_state="QUEUED",
                queue_sequence=prepared.queue_sequence,
            )
        result = self._drain_thread(
            scope=scope, thread_id=thread_id, target_message_id=prepared.answer_message_id
        )
        return TurnOutcome(
            thread_id,
            user_message_id,
            prepared.answer_message_id,
            result,
            durable_state=self._durable_state(result.state),
        )

    # -- idempotency, grants, audit ----------------------------------------

    def _withheld_turn(
        self,
        connection: Connection[Any],
        *,
        scope: Scope,
        principal: str,
        thread_id: str,
        user_message: str,
        verdict: Verdict,
        idempotency_key: str | None,
    ) -> TurnOutcome:
        """Answer a withheld question without ever having read it.

        The model is not invoked and no grant is minted: there is nothing to
        answer, because the question was never admitted. What the reader gets is
        a typed refusal that names the detector class and not the match, so the
        transcript records why the surface stopped without re-stating the secret
        it stopped.
        """

        from solvan.application.liaison.parts import AccessMode as _AccessMode

        store = LiaisonStore(connection)
        answer_message = store.append_message(
            scope=scope,
            thread_id=thread_id,
            role="LIAISON",
            classification="INTERNAL",
            in_reply_to=user_message,
            turn_state="COMPLETED",
        )
        refusal = Part(
            kind=PartKind.REFUSAL,
            sequence=0,
            payload={
                "sentence": verdict.placeholder(),
                "held_reason": "inbound content classified RESTRICTED",
                "verdict_ref": verdict.verdict_ref,
                # The detector names, never the match.
                "findings": list(verdict.findings),
            },
            classification="INTERNAL",
            access_mode=_AccessMode.SYSTEM_PUBLIC,
        )
        store.append_parts(scope=scope, message_id=answer_message, parts=[refusal])
        self._audit(
            connection,
            scope=scope,
            principal=principal,
            action="liaison.withheld",
            detail={
                "thread": thread_id,
                "message": answer_message,
                "verdict_ref": verdict.verdict_ref,
                "digest": verdict.digest,
                "findings": list(verdict.findings),
            },
        )
        outcome = TurnOutcome(
            thread_id,
            user_message,
            answer_message,
            TurnResult(TurnState.COMPLETED, (refusal,), EMPTY_USAGE, EMPTY_DEFECTS),
        )
        if idempotency_key:
            self._complete_operation(
                connection,
                scope=scope,
                key=idempotency_key,
                operation="liaison.ask",
                response={
                    "thread_id": thread_id,
                    "user_message_id": user_message,
                    "answer_message_id": answer_message,
                },
            )
        return outcome

    def _claim_operation(
        self,
        connection: Connection[Any],
        *,
        scope: Scope,
        key: str | None,
        operation: str,
        request_hash: str,
    ) -> TurnOutcome | None:
        """Claim the key, or return the original result of a replay.

        The claim is taken in the same transaction as the work, so a concurrent
        replay waits for the winner rather than doing the work twice.

        The stored hash is of the request itself, not of the key. A key is
        chosen by the client, so hashing it proves only that the client reused
        a string — it cannot tell a genuine retry from a different question sent
        under a recycled key, and the second caller would be handed the first
        one's answer. Comparing the request refuses that outright.
        """

        if not key:
            return None
        operation_args = {
            **scope.canonical_dict(),
            "operation": operation,
            "key": key,
            "request_hash": request_hash,
        }
        # Insert first so the unique key is the concurrency gate. A conflicting
        # insert waits for the in-flight transaction; the row lock below then
        # observes the winner's committed hash and response.
        connection.execute(
            """INSERT INTO solvan_liaison.liaison_operation_ledger (
                  organization_id, project_id, environment_id, idempotency_key,
                  operation, request_hash, status, claim_token, expires_at)
               VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                  %(key)s, %(operation)s, %(request_hash)s, 'PENDING',
                  gen_random_uuid(), now() + interval '1 hour')
               ON CONFLICT (organization_id, project_id, environment_id, operation,
                  idempotency_key) DO NOTHING""",
            operation_args,
        )
        row = connection.execute(
            """SELECT status, response_ref, request_hash
               FROM solvan_liaison.liaison_operation_ledger
               WHERE organization_id = %(organization_id)s
                 AND project_id = %(project_id)s
                 AND environment_id = %(environment_id)s
                 AND operation = %(operation)s AND idempotency_key = %(key)s
               FOR UPDATE""",
            operation_args,
        ).fetchone()
        if row is None:  # pragma: no cover - insertion and read share one transaction
            raise RuntimeError("Liaison operation claim disappeared")
        if row is not None and str(row[2]) != request_hash:
            raise IdempotencyConflict(
                "this idempotency key was already used for a different request"
            )
        if row is not None and row[0] == "COMPLETED" and row[1]:
            stored = json.loads(str(row[1]))
            return TurnOutcome(
                stored["thread_id"],
                stored["user_message_id"],
                stored["answer_message_id"],
                TurnResult(TurnState.COMPLETED, (), EMPTY_USAGE, EMPTY_DEFECTS),
                durable_state=stored.get("durable_state", "COMPLETED"),
                attempt=int(stored.get("attempt", 1)),
                generation=int(stored.get("generation", 1)),
                queue_sequence=stored.get("queue_sequence"),
            )
        return None

    def _complete_operation(
        self,
        connection: Connection[Any],
        *,
        scope: Scope,
        key: str,
        operation: str,
        response: dict[str, Any],
    ) -> None:
        connection.execute(
            """UPDATE solvan_liaison.liaison_operation_ledger
               SET status = 'COMPLETED', response_ref = %(response)s, completed_at = now()
               WHERE organization_id = %(organization_id)s
                 AND project_id = %(project_id)s
                 AND environment_id = %(environment_id)s
                 AND operation = %(operation)s AND idempotency_key = %(key)s""",
            {
                **scope.canonical_dict(),
                "key": key,
                "operation": operation,
                "response": json.dumps(response),
            },
        )

    def _record_grant(
        self,
        connection: Connection[Any],
        *,
        scope: Scope,
        principal: str,
        thread_id: str,
        message_id: str,
    ) -> None:
        """Leave a receipt so a read can be audited after the fact (§10.2)."""

        turn = connection.execute(
            """SELECT x.attempt,x.generation,m.purpose,m.classification_ceiling,
                      m.membership_epoch
                 FROM solvan_liaison.liaison_turns x
                 JOIN solvan_liaison.liaison_turn_input_manifests m ON
                   (m.organization_id,m.project_id,m.environment_id,m.message_id,m.attempt)=
                   (x.organization_id,x.project_id,x.environment_id,x.message_id,x.attempt)
                WHERE x.organization_id=%(organization_id)s
                  AND x.project_id=%(project_id)s AND x.environment_id=%(environment_id)s
                  AND x.message_id=%(message_id)s
                ORDER BY x.attempt DESC LIMIT 1""",
            {**scope.canonical_dict(), "message_id": message_id},
        ).fetchone()
        if turn is None:
            raise RuntimeError("conversation read grant requires an exact turn attempt")
        grant_id = new_identifier("grt")
        policy_epoch = current_policy_epoch(connection, scope=scope, principal=principal)
        allowed_methods = ["read_projection"]
        grant_digest = canonical_hash(
            {
                "grant_id": grant_id,
                "principal": principal,
                "message_id": message_id,
                "attempt": int(turn[0]),
                "generation": int(turn[1]),
                "purpose": str(turn[2]),
                "classification_ceiling": str(turn[3]),
                "membership_epoch": int(turn[4]),
                "policy_epoch": policy_epoch,
                "audience": "PROJECTION_API",
                "allowed_projection_methods": allowed_methods,
            }
        )
        connection.execute(
            """INSERT INTO solvan_liaison.liaison_grant_receipts (
                  organization_id, project_id, environment_id, id, grant_kind,
                  principal, thread_id, message_id, attempt,generation,purpose,
                  classification_ceiling,membership_epoch,audience,
                  allowed_projection_methods,grant_digest,request_hash,policy_epoch,
                  issued_at,expires_at,audit_ref)
               VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                  %(id)s,'CONVERSATION_READ',%(principal)s,%(thread_id)s,
                  %(message_id)s,%(attempt)s,%(generation)s,%(purpose)s,
                  %(classification_ceiling)s,%(membership_epoch)s,'PROJECTION_API',
                  %(allowed_methods)s,%(grant_digest)s,%(request_hash)s,%(policy_epoch)s,now(),
                  now() + interval '10 minutes', %(audit)s)""",
            {
                **scope.canonical_dict(),
                "id": grant_id,
                "policy_epoch": policy_epoch,
                "principal": principal,
                "thread_id": thread_id,
                "message_id": message_id,
                "attempt": int(turn[0]),
                "generation": int(turn[1]),
                "purpose": str(turn[2]),
                "classification_ceiling": str(turn[3]),
                "membership_epoch": int(turn[4]),
                "allowed_methods": allowed_methods,
                "grant_digest": grant_digest,
                "request_hash": canonical_hash(
                    {"thread_id": thread_id, "message_id": message_id, "attempt": int(turn[0])}
                ),
                "audit": f"audit://liaison/grant/{message_id}",
            },
        )

    def _audit(
        self,
        connection: Connection[Any],
        *,
        scope: Scope,
        principal: str,
        action: str,
        detail: dict[str, Any],
    ) -> None:
        """Append to the same immutable audit sequence as everything else (§20).

        The payload is hashed rather than stored: an audit row records that a
        thing happened and who did it, never the words that were exchanged.
        """

        payload = json.dumps(detail, sort_keys=True, separators=(",", ":"), default=str)
        connection.execute(
            """INSERT INTO solvan.audit_events (
                  organization_id, project_id, environment_id, id, stream_type,
                  stream_id, event_type, actor_principal, payload_hash)
               VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                  %(id)s, 'LIAISON_THREAD', %(stream_id)s, %(event_type)s,
                  %(principal)s, %(payload_hash)s)""",
            {
                **scope.canonical_dict(),
                "id": new_identifier("aud"),
                "stream_id": str(detail.get("thread", "")),
                "event_type": action,
                "principal": principal,
                "payload_hash": f"sha256:{hashlib.sha256(payload.encode()).hexdigest()}",
            },
        )
