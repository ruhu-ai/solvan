"""Exact cancel, abort, and stop-and-send operations."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from apps.api.liaison_projection_sync import sync_projection
from apps.api.liaison_types import (
    IdempotencyConflict,
    TurnOutcome,
    request_digest,
)
from solvan.application.liaison.intents import (
    resolve_intent,
)
from solvan.application.liaison.redaction import classify
from solvan.domain import Scope
from solvan.persistence.liaison_manifest import canonical_hash
from solvan.persistence.liaison_policy import current_policy_epoch
from solvan.persistence.liaison_runtime import prepare_turn
from solvan.persistence.liaison_store import LiaisonStore, ThreadAccessError
from solvan.persistence.liaison_turn_control import interrupt_turn


class LiaisonTurnControlMixin:
    """Internal mixin; LiaisonService supplies the shared composition state."""

    _connect: Any
    reader: Any
    _claim_operation: Callable[..., TurnOutcome | None]
    _complete_operation: Any
    _resolve_follow_up_candidates: Any
    _source_versions: Any
    _drain_thread: Any
    _durable_state: Any

    def cancel_turn(
        self,
        *,
        scope: Scope,
        principal: str,
        thread_id: str,
        message_id: str,
        attempt: int,
        generation: int,
        idempotency_key: str,
    ) -> bool:
        """Cancel only the exact still-queued attempt."""

        with self._connect() as connection, connection.transaction():
            replay = self._claim_control_operation(
                connection,
                scope=scope,
                principal=principal,
                operation="liaison.turn.cancel",
                idempotency_key=idempotency_key,
                material={
                    "thread_id": thread_id,
                    "message_id": message_id,
                    "attempt": attempt,
                    "generation": generation,
                },
            )
            if replay is not None:
                return replay
            store = LiaisonStore(connection)
            thread = store.thread(scope=scope, thread_id=thread_id)
            if thread is None or principal not in store.participants(
                scope=scope, thread_id=thread_id
            ):
                interrupted = False
            else:
                interrupted = interrupt_turn(
                    connection,
                    scope=scope,
                    thread_id=thread_id,
                    message_id=message_id,
                    attempt=attempt,
                    generation=generation,
                    expected_state="QUEUED",
                    reason="USER_CANCELLED_BEFORE_START",
                )
            self._complete_control_operation(
                connection,
                scope=scope,
                operation="liaison.turn.cancel",
                idempotency_key=idempotency_key,
                interrupted=interrupted,
            )
            return interrupted

    def abort_turn(
        self,
        *,
        scope: Scope,
        principal: str,
        thread_id: str,
        message_id: str,
        attempt: int,
        generation: int,
        idempotency_key: str,
    ) -> bool:
        """Abort only the exact currently running generation."""

        with self._connect() as connection, connection.transaction():
            replay = self._claim_control_operation(
                connection,
                scope=scope,
                principal=principal,
                operation="liaison.turn.abort",
                idempotency_key=idempotency_key,
                material={
                    "thread_id": thread_id,
                    "message_id": message_id,
                    "attempt": attempt,
                    "generation": generation,
                },
            )
            if replay is not None:
                return replay
            store = LiaisonStore(connection)
            thread = store.thread(scope=scope, thread_id=thread_id)
            if thread is None or principal not in store.participants(
                scope=scope, thread_id=thread_id
            ):
                interrupted = False
            else:
                interrupted = interrupt_turn(
                    connection,
                    scope=scope,
                    thread_id=thread_id,
                    message_id=message_id,
                    attempt=attempt,
                    generation=generation,
                    expected_state="RUNNING",
                    reason="USER_ABORTED",
                )
            self._complete_control_operation(
                connection,
                scope=scope,
                operation="liaison.turn.abort",
                idempotency_key=idempotency_key,
                interrupted=interrupted,
            )
        if interrupted:
            self._drain_thread(scope=scope, thread_id=thread_id, target_message_id=message_id)
        return interrupted

    def _claim_control_operation(
        self,
        connection: Any,
        *,
        scope: Scope,
        principal: str,
        operation: str,
        idempotency_key: str,
        material: dict[str, Any],
    ) -> bool | None:
        if not idempotency_key:
            raise ValueError("Idempotency-Key is required")
        request_hash = canonical_hash({"principal": principal, **material})
        params = {
            **scope.canonical_dict(),
            "key": idempotency_key,
            "operation": operation,
            "request_hash": request_hash,
        }
        connection.execute(
            """INSERT INTO solvan_liaison.liaison_operation_ledger (
                  organization_id,project_id,environment_id,idempotency_key,operation,
                  request_hash,status,claim_token,expires_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(key)s,
                  %(operation)s,%(request_hash)s,'PENDING',gen_random_uuid(),
                  now()+interval '1 hour')
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
            raise RuntimeError("turn control operation claim disappeared")
        if str(row[2]) != request_hash:
            raise IdempotencyConflict("idempotency key request mismatch")
        if str(row[0]) == "COMPLETED" and row[1]:
            return bool(json.loads(str(row[1]))["interrupted"])
        return None

    @staticmethod
    def _complete_control_operation(
        connection: Any,
        *,
        scope: Scope,
        operation: str,
        idempotency_key: str,
        interrupted: bool,
    ) -> None:
        connection.execute(
            """UPDATE solvan_liaison.liaison_operation_ledger
                  SET status='COMPLETED',response_ref=%(response)s,completed_at=now()
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND operation=%(operation)s
                  AND idempotency_key=%(key)s""",
            {
                **scope.canonical_dict(),
                "operation": operation,
                "key": idempotency_key,
                "response": json.dumps({"interrupted": interrupted}),
            },
        )

    def stop_and_send(
        self,
        *,
        scope: Scope,
        principal: str,
        thread_id: str,
        running_message_id: str,
        attempt: int,
        generation: int,
        replacement: str,
        idempotency_key: str,
    ) -> TurnOutcome:
        """Interrupt one generation and commit its replacement atomically."""

        verdict = classify(replacement)
        if verdict.withheld:
            raise ValueError("a stop-and-send replacement was withheld by the inbound gate")
        reader = self.reader(principal=principal, scope=scope)
        if not reader.scope_authorized:
            raise ThreadAccessError("FORBIDDEN", "principal is not authorized for this scope")
        with self._connect() as connection, connection.transaction():
            store = LiaisonStore(connection)
            thread = store.thread(scope=scope, thread_id=thread_id)
            if thread is None or principal not in store.participants(
                scope=scope, thread_id=thread_id
            ):
                raise ValueError("thread is not writable by this principal")
            claimed = self._claim_operation(
                connection,
                scope=scope,
                key=idempotency_key,
                operation="liaison.stop_and_send",
                request_hash=request_digest(
                    principal=principal,
                    anchor=thread.anchor.label(),
                    question=verdict.digest,
                    thread_id=thread_id,
                ),
            )
            if claimed is not None:
                return claimed
            if not interrupt_turn(
                connection,
                scope=scope,
                thread_id=thread_id,
                message_id=running_message_id,
                attempt=attempt,
                generation=generation,
                expected_state="RUNNING",
                reason="STOP_AND_SEND",
                promote=False,
            ):
                raise IdempotencyConflict("the visible turn is no longer the running generation")
            sync_projection(store, scope=scope, reader=reader)
            user_message = store.append_message(
                scope=scope,
                thread_id=thread_id,
                role="USER",
                classification=str(verdict.classification),
                author_principal=principal,
                redaction_verdict_ref=verdict.verdict_ref,
                content_hash=verdict.digest,
            )
            from solvan.application.liaison.parts import user_part

            store.append_parts(
                scope=scope,
                message_id=user_message,
                parts=[
                    user_part(
                        verdict.text,
                        sequence=0,
                        author_principal=principal,
                        membership_epoch=store.current_membership_epoch(
                            scope=scope, thread_id=thread_id, principal=principal
                        ),
                        classification=str(verdict.classification),
                    )
                ],
            )
            has_prior = connection.execute(
                """SELECT 1 FROM solvan_liaison.liaison_messages
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND thread_id=%(thread_id)s
                      AND role='LIAISON' AND turn_state='COMPLETED' LIMIT 1""",
                {**scope.canonical_dict(), "thread_id": thread_id},
            ).fetchone()
            resolution = resolve_intent(replacement, has_prior_answer=has_prior is not None)
            resolved_references = self._resolve_follow_up_candidates(
                connection,
                scope=scope,
                thread_id=thread_id,
                principal=principal,
                question=replacement,
                intent=resolution.intent,
            )
            prepared = prepare_turn(
                connection,
                scope=scope,
                principal=principal,
                policy_epoch=current_policy_epoch(connection, scope=scope, principal=principal),
                thread_id=thread_id,
                user_message_id=user_message,
                intent=str(resolution.intent),
                authority_route=resolution.authority_route,
                resolved_references=resolved_references,
                source_versions=self._source_versions(
                    thread.anchor, principal=principal, scope=scope
                ),
            )
            self._complete_operation(
                connection,
                scope=scope,
                key=idempotency_key,
                operation="liaison.stop_and_send",
                response={
                    "thread_id": thread_id,
                    "user_message_id": user_message,
                    "answer_message_id": prepared.answer_message_id,
                    "durable_state": prepared.state,
                    "attempt": prepared.attempt,
                    "generation": prepared.generation,
                    "queue_sequence": prepared.queue_sequence,
                },
            )
        result = self._drain_thread(
            scope=scope,
            thread_id=thread_id,
            target_message_id=prepared.answer_message_id,
        )
        return TurnOutcome(
            thread_id,
            user_message,
            prepared.answer_message_id,
            result,
            durable_state=self._durable_state(result.state),
            attempt=prepared.attempt,
            generation=prepared.generation,
            queue_sequence=prepared.queue_sequence,
        )
