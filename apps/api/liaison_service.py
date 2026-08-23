"""The turn service: compose an answer and make it durable, in one place.

The API routes stay thin because the ordering here is load-bearing. A turn
writes its message header first, then its parts with their access envelopes in
the same transaction, so a crashed instance leaves a truncated-but-honest
transcript rather than a half-written one that reads as complete.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from psycopg import Connection

from apps.api.liaison_projection_sync import sync_projection as sync_projection
from apps.api.liaison_reader import SnapshotProjectionReader
from apps.api.liaison_service_channels import LiaisonChannelMixin
from apps.api.liaison_service_composition import (
    FreshnessRetry,
    LiaisonCompositionMixin,
    LiaisonPartStreamer,
)
from apps.api.liaison_service_turns import LiaisonTurnControlMixin
from apps.api.liaison_types import (
    EMPTY_DEFECTS,
    EMPTY_USAGE,
    TurnOutcome,
    request_digest,
)
from solvan.application.liaison import Anchor, GrantIssuer
from solvan.application.liaison.adk_composer import AdkQuestionComposer, AdkQuestionPlanner
from solvan.application.liaison.engine import (
    Composer,
    TurnResult,
    TurnState,
    default_daily_budget,
)
from solvan.application.liaison.intents import (
    ConversationIntent,
    IntentResolution,
    resolve_intent,
)
from solvan.application.liaison.parts import AccessMode, Part, PartKind
from solvan.application.liaison.questions import EnumeratedComposer
from solvan.application.liaison.redaction import classify
from solvan.application.liaison.templates import TemplateRegistry
from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_budget import daily_model_calls
from solvan.persistence.liaison_completion import finish_claimed_turn
from solvan.persistence.liaison_policy import current_policy_epoch
from solvan.persistence.liaison_retry import requeue_fresh_attempt
from solvan.persistence.liaison_runtime import (
    PreparedTurn,
    claim_ready_turn,
    prepare_turn,
)
from solvan.persistence.liaison_store import LiaisonStore, ThreadAccessError
from solvan.persistence.liaison_stream import append_stream_event
from solvan.platform.model_armor import GoogleModelArmorTextGate


class LiaisonService(LiaisonTurnControlMixin, LiaisonCompositionMixin, LiaisonChannelMixin):
    """Owns the durable side of a turn. Routes own request shape only."""

    def __init__(
        self,
        *,
        connect: Callable[[], Any],
        snapshot_provider: Callable[[], dict[str, Any]],
        registry_provider: Callable[[], TemplateRegistry],
    ) -> None:
        self._connect = connect
        self._snapshot = snapshot_provider
        self._registry = registry_provider
        self._issuer = GrantIssuer()
        self._service_revision = os.environ.get(
            "K_REVISION", os.environ.get("SOLVAN_SERVICE_REVISION", "local-unreleased")
        )
        self._process_boot_id = new_identifier("pbt")
        self._composer: Composer
        armor_template = os.environ.get("SOLVAN_MODEL_ARMOR_TEMPLATE")
        if os.environ.get("SOLVAN_LIAISON_COMPOSER", "DETERMINISTIC").upper() != "ADK":
            self._composer = EnumeratedComposer()
        elif not armor_template or armor_template == "UNCONFIGURED":
            # An unset template used to build the planner with
            # `safety_gate=None`, so one missing environment variable turned
            # both inbound and outbound Model Armor off while the model kept
            # answering -- the silent bypass §11.1 step 5 forbids.
            #
            # INV-C-17 degrades an *outage* to the deterministic path, and
            # `adk_composer` still does exactly that when a screening call
            # fails. This is the other case: a revision that asked for ADK
            # composition without configuring its only content screen is
            # misconfigured, not degraded. Degrading here would serve the
            # enumerated composer indefinitely while the deployment believed
            # the governed path was live, so the configuration error refuses
            # at construction instead. On Cloud Run that is the contained
            # outcome: the revision fails readiness and never takes traffic,
            # and the last healthy revision keeps serving.
            raise RuntimeError(
                "SOLVAN_LIAISON_COMPOSER=ADK requires SOLVAN_MODEL_ARMOR_TEMPLATE; "
                "refusing to construct a composer that would answer unscreened"
            )
        else:
            self._composer = AdkQuestionComposer(
                planner=AdkQuestionPlanner(
                    model_resource=os.environ.get("SOLVAN_MODEL_RESOURCE", "gemini-3.6-flash"),
                    safety_gate=GoogleModelArmorTextGate(
                        template=armor_template,
                        region=os.environ.get("SOLVAN_GCP_REGION", "europe-west1"),
                    ),
                )
            )

    def reader(
        self,
        *,
        principal: str | None = None,
        scope: Scope | None = None,
        connection: Connection[Any] | None = None,
    ) -> SnapshotProjectionReader:
        """Build a projection reader with an explicit scope authorization.

        The console snapshot is not an access-control list.  In the regional
        deployment a reader is usable only when the verified principal has an
        active operator/approver/admin binding for the exact scope.  Local
        development remains explicitly fixture-authorized; omitting a principal is
        reserved for internal projection synchronization, never a user read.
        """

        authorized = True
        if (
            principal is not None
            and scope is not None
            and os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE") == "GOOGLE_CLOUD_IAM"
        ):
            query = """
                    SELECT EXISTS (
                        SELECT 1
                          FROM solvan.actor_role_bindings
                         WHERE organization_id=%(organization_id)s
                           AND project_id=%(project_id)s
                           AND environment_id=%(environment_id)s
                           AND principal=%(principal)s
                           AND role IN ('OPERATOR','APPROVER','ADMIN')
                           AND (expires_at IS NULL OR expires_at > now())
                    )
                """
            params = {**scope.canonical_dict(), "principal": principal}
            if connection is not None:
                row = connection.execute(query, params).fetchone()
                authorized = bool(row and row[0])
            else:
                try:
                    with self._connect() as opened:
                        row = opened.execute(query, params).fetchone()
                    authorized = bool(row and row[0])
                except Exception:
                    # A missing policy store or an unavailable database is
                    # a refusal, never a permissive fallback.
                    authorized = False
        return SnapshotProjectionReader(
            self._snapshot(), connect=self._connect, scope_authorized=authorized
        )

    def sync_directory(self, connection: Connection[Any], scope: Scope) -> None:
        sync_projection(LiaisonStore(connection), scope=scope, reader=self.reader())

    def ask(
        self,
        *,
        scope: Scope,
        principal: str,
        anchor: Anchor,
        question: str,
        thread_id: str | None = None,
        mentions: tuple[str, ...] = (),
        idempotency_key: str | None = None,
        defer_execution: bool = False,
    ) -> TurnOutcome:
        """Accept one utterance durably, then execute only committed READY work.

        Acceptance and provider execution are deliberately separate
        transactions. A later send can therefore commit as QUEUED while this
        request is composing, and a provider failure cannot roll back what the
        person already sent.
        """

        reader = self.reader(principal=principal, scope=scope)
        if not reader.scope_authorized:
            raise ThreadAccessError("FORBIDDEN", "principal is not authorized for this scope")
        # Before the transaction, before the model, before anything is durable.
        # A gate that runs after the write is not a gate (§11.1).
        verdict = classify(question)

        prepared: PreparedTurn | None = None
        with self._connect() as connection:
            store = LiaisonStore(connection)
            with connection.transaction():
                sync_projection(store, scope=scope, reader=reader)

                claimed = self._claim_operation(
                    connection,
                    scope=scope,
                    key=idempotency_key,
                    operation="liaison.ask",
                    request_hash=request_digest(
                        principal=principal,
                        anchor=anchor.label(),
                        question=verdict.digest,
                        thread_id=thread_id,
                        mentions=mentions,
                    ),
                )
                if claimed is not None:
                    return claimed

                if thread_id is None:
                    resolved_thread = store.open_thread(
                        scope=scope, anchor=anchor, visibility="PARTICIPANTS", principal=principal
                    )
                else:
                    # A thread id from the client is a claim, not a credential.
                    existing = store.require_writable_thread(
                        scope=scope, thread_id=thread_id, anchor=anchor, principal=principal
                    )
                    resolved_thread = thread_id
                    # One anchor per turn. The fence above proves these are
                    # equal; taking the thread's own anchor from here on is
                    # what keeps them equal, because composition reads the
                    # thread row while the gates below read this variable. A
                    # turn gated as one anchor and composed as another is the
                    # hazard, not a hypothetical.
                    anchor = existing.anchor
                active_participants = store.participants(scope=scope, thread_id=resolved_thread)
                invalid_mentions = sorted(set(mentions) - set(active_participants))
                if invalid_mentions:
                    raise ThreadAccessError(
                        "FORBIDDEN",
                        "a message may mention only current thread participants",
                    )
                user_message = store.append_message(
                    scope=scope,
                    thread_id=resolved_thread,
                    role="USER",
                    classification=str(verdict.classification),
                    author_principal=principal,
                    redaction_verdict_ref=verdict.verdict_ref,
                    content_hash=verdict.digest,
                )
                # The question is the asker's own text, so it is participant
                # scoped after redaction rather than readable thread-wide. What
                # goes in is `verdict.text`, which for a restricted message is
                # empty — the placeholder is what a reader sees, and the words
                # themselves were never durable.
                from solvan.application.liaison.parts import user_part

                user_part_ids = store.append_parts(
                    scope=scope,
                    message_id=user_message,
                    parts=[
                        user_part(
                            verdict.placeholder() if verdict.withheld else verdict.text,
                            sequence=0,
                            author_principal=principal,
                            membership_epoch=store.current_membership_epoch(
                                scope=scope,
                                thread_id=resolved_thread,
                                principal=principal,
                            ),
                            classification=str(verdict.classification),
                            mentions=mentions,
                        )
                    ],
                )
                for mentioned_principal in sorted(set(mentions)):
                    append_stream_event(
                        connection,
                        scope=scope,
                        thread_id=resolved_thread,
                        event_type="message.part.completed",
                        message_id=user_message,
                        part_id=user_part_ids[0],
                        access_mode="AUTHOR_ONLY",
                        audience_principal=mentioned_principal,
                        payload={"kind": "mention", "author": principal},
                    )
                if verdict.withheld:
                    return self._withheld_turn(
                        connection,
                        scope=scope,
                        principal=principal,
                        thread_id=resolved_thread,
                        user_message=user_message,
                        verdict=verdict,
                        idempotency_key=idempotency_key,
                    )
                prior_answer = connection.execute(
                    """SELECT 1 FROM solvan_liaison.liaison_messages
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND thread_id=%(thread_id)s AND role='LIAISON'
                          AND turn_state='COMPLETED' LIMIT 1""",
                    {**scope.canonical_dict(), "thread_id": resolved_thread},
                ).fetchone()
                resolution = resolve_intent(question, has_prior_answer=prior_answer is not None)
                # The central scope chat reads only the current ledger. A vague
                # request cannot turn into a fresh telemetry read or an action:
                # the person must first select a narrower durable anchor.
                if anchor.kind.value == "SCOPE" and resolution.intent in {
                    ConversationIntent.STEER_DRAFT,
                    ConversationIntent.ACTION_REFERENCE,
                }:
                    resolution = IntentResolution(
                        ConversationIntent.OUT_OF_SCOPE,
                        "NONE",
                    )
                resolved_references = self._resolve_follow_up_candidates(
                    connection,
                    scope=scope,
                    thread_id=resolved_thread,
                    principal=principal,
                    question=question,
                    intent=resolution.intent,
                )
                policy_epoch = current_policy_epoch(connection, scope=scope, principal=principal)
                prepared = prepare_turn(
                    connection,
                    scope=scope,
                    principal=principal,
                    policy_epoch=policy_epoch,
                    thread_id=resolved_thread,
                    user_message_id=user_message,
                    intent=str(resolution.intent),
                    authority_route=resolution.authority_route,
                    resolved_references=resolved_references,
                    source_versions=self._source_versions(anchor, principal=principal, scope=scope),
                )
                if idempotency_key:
                    self._complete_operation(
                        connection,
                        scope=scope,
                        key=idempotency_key,
                        operation="liaison.ask",
                        response={
                            "thread_id": resolved_thread,
                            "user_message_id": user_message,
                            "answer_message_id": prepared.answer_message_id,
                            "durable_state": prepared.state,
                            "attempt": prepared.attempt,
                            "generation": prepared.generation,
                            "queue_sequence": prepared.queue_sequence,
                        },
                    )
        if prepared is None:  # pragma: no cover - every non-withheld acceptance prepares a turn
            raise RuntimeError("accepted Liaison question has no prepared turn")
        if prepared.state == "QUEUED" or defer_execution:
            return TurnOutcome(
                prepared.thread_id,
                prepared.user_message_id,
                prepared.answer_message_id,
                TurnResult(TurnState.STREAMING, (), EMPTY_USAGE, EMPTY_DEFECTS),
                durable_state=prepared.state,
                attempt=prepared.attempt,
                generation=prepared.generation,
                queue_sequence=prepared.queue_sequence,
            )
        result = self._drain_thread(
            scope=scope,
            thread_id=prepared.thread_id,
            target_message_id=prepared.answer_message_id,
        )
        return TurnOutcome(
            prepared.thread_id,
            prepared.user_message_id,
            prepared.answer_message_id,
            result,
            durable_state=self._durable_state(result.state),
            attempt=prepared.attempt,
            generation=prepared.generation,
            queue_sequence=prepared.queue_sequence,
        )

    def _daily_ceiling_reached(self, *, scope: Scope, claim: Any) -> str | None:
        """Name the UTC daily ceiling this turn would cross, or None."""

        ceilings = default_daily_budget()
        with self._connect() as connection:
            thread_calls, principal_calls = daily_model_calls(
                connection,
                scope=scope,
                thread_id=claim.thread_id,
                principal=claim.principal,
            )
        if thread_calls >= ceilings.thread_model_calls:
            return f"daily thread model-call ceiling of {ceilings.thread_model_calls}"
        if principal_calls >= ceilings.principal_model_calls:
            return f"daily model-call ceiling of {ceilings.principal_model_calls}"
        return None

    def _refuse_for_budget(self, *, scope: Scope, claim: Any, ceiling: str) -> TurnResult:
        """Close an over-budget turn honestly, with the ceiling that stopped it."""

        note = Part(
            kind=PartKind.BUDGET_NOTE,
            sequence=0,
            payload={"ceiling": ceiling, "reached": True},
            classification="INTERNAL",
            access_mode=AccessMode.SYSTEM_PUBLIC,
        )
        result = TurnResult(TurnState.ERROR, (note,), EMPTY_USAGE, EMPTY_DEFECTS)
        with self._connect() as connection, connection.transaction():
            finish_claimed_turn(
                connection,
                scope=scope,
                claim=claim,
                state="FAILED",
                terminal_reason="BUDGET_EXHAUSTED",
                parts=result.parts,
                model_calls=0,
                tool_calls=0,
                tokens=0,
            )
        return result

    def run_pending(self, *, scope: Scope, thread_id: str, target_message_id: str) -> None:
        """Background entry point; all authority remains in the durable claim."""

        self._drain_thread(scope=scope, thread_id=thread_id, target_message_id=target_message_id)

    def _drain_thread(self, *, scope: Scope, thread_id: str, target_message_id: str) -> TurnResult:
        """Run committed READY work serially until the lane is empty."""

        target_result: TurnResult | None = None
        while True:
            with self._connect() as connection, connection.transaction():
                claim = claim_ready_turn(
                    connection,
                    scope=scope,
                    thread_id=thread_id,
                    owner=f"api-{new_identifier('wrk')}",
                    service_revision=self._service_revision,
                    process_boot_id=self._process_boot_id,
                )
                if claim is not None and claim.authority_route == "ASK":
                    self._record_grant(
                        connection,
                        scope=scope,
                        principal=claim.principal,
                        thread_id=claim.thread_id,
                        message_id=claim.answer_message_id,
                    )
            if claim is None:
                break
            # A day's ceiling is checked after the claim and before the model,
            # so an exhausted budget is reported in the thread as its own
            # terminal turn rather than silently degraded around (§3.2).
            exhausted = self._daily_ceiling_reached(scope=scope, claim=claim)
            if exhausted is not None:
                refused = self._refuse_for_budget(scope=scope, claim=claim, ceiling=exhausted)
                if claim.answer_message_id == target_message_id:
                    target_result = refused
                continue
            committed = False
            result = TurnResult(TurnState.ERROR, (), EMPTY_USAGE, EMPTY_DEFECTS)
            part_stream = LiaisonPartStreamer(connect=self._connect, scope=scope, claim=claim)
            try:
                for _ in range(3):
                    result, input_state = self._compose_with_freshness(
                        scope=scope, claim=claim, part_stream=part_stream
                    )
                    durable_state, terminal_reason = self._completion_state(result.state)
                    refresh_after_transaction = False
                    with self._connect() as connection, connection.transaction():
                        current = self._current_input_state(
                            scope=scope, claim=claim, connection=connection
                        )
                        if current != input_state:
                            if part_stream.has_parts():
                                self._record_input_advanced(connection, scope=scope, claim=claim)
                                refresh_after_transaction = True
                            else:
                                self._record_input_advanced(connection, scope=scope, claim=claim)
                                continue
                        if not refresh_after_transaction:
                            committed = finish_claimed_turn(
                                connection,
                                scope=scope,
                                claim=claim,
                                state=durable_state,
                                terminal_reason=terminal_reason,
                                parts=result.parts,
                                model_calls=result.usage.model_calls,
                                tool_calls=result.usage.tool_calls,
                                tokens=result.usage.tokens,
                                streamed_part_ids=part_stream.part_ids(),
                            )
                            if committed:
                                self._audit(
                                    connection,
                                    scope=scope,
                                    principal=claim.principal,
                                    action="liaison.answer",
                                    detail={
                                        "thread": claim.thread_id,
                                        "message": claim.answer_message_id,
                                        "attempt": claim.attempt,
                                        "generation": claim.generation,
                                        "state": durable_state,
                                        "suppressed": result.defects.suppressed,
                                        "held": result.defects.held,
                                    },
                                )
                    if refresh_after_transaction:
                        raise FreshnessRetry("input changed during terminalization")
                    if committed:
                        break
            except FreshnessRetry:
                part_stream.discard()
                current_sources = self._source_versions(claim.anchor)
                refreshed_references = claim.resolved_references
                if claim.conversation_intent == "FOLLOW_UP":
                    with self._connect() as connection:
                        refreshed_references = self._resolve_follow_up_candidates(
                            connection,
                            scope=scope,
                            thread_id=claim.thread_id,
                            principal=claim.principal,
                            question=claim.question,
                            intent=ConversationIntent.FOLLOW_UP,
                        )
                with self._connect() as connection, connection.transaction():
                    requeue_fresh_attempt(
                        connection,
                        scope=scope,
                        claim=claim,
                        source_versions=current_sources,
                        resolved_references=refreshed_references,
                        policy_epoch=current_policy_epoch(
                            connection, scope=scope, principal=claim.principal
                        ),
                    )
                # The replacement is claimed by the top of the lane loop. It
                # owns a new manifest, grant, provider request, and generation.
                continue
            if not committed:
                part_stream.discard()
                error = Part(
                    kind=PartKind.ERROR,
                    sequence=0,
                    payload={"error": "The incident changed while I was reading it. Please retry."},
                    classification="INTERNAL",
                    access_mode=AccessMode.SYSTEM_PUBLIC,
                )
                result = TurnResult(TurnState.ERROR, (error,), EMPTY_USAGE, EMPTY_DEFECTS)
                with self._connect() as connection, connection.transaction():
                    finish_claimed_turn(
                        connection,
                        scope=scope,
                        claim=claim,
                        state="FAILED",
                        terminal_reason="PROVIDER_FAILURE",
                        parts=result.parts,
                        model_calls=0,
                        tool_calls=0,
                        tokens=0,
                    )
            if claim.answer_message_id == target_message_id:
                target_result = result
        return target_result or TurnResult(
            TurnState.INTERRUPTED,
            (),
            EMPTY_USAGE,
            EMPTY_DEFECTS,
        )
