"""Freshness-fenced Liaison composition and follow-up resolution."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Mapping
from dataclasses import replace
from typing import Any, ClassVar

from psycopg import Connection

from solvan.application.liaison import Anchor
from solvan.application.liaison.claims import CompositionDefects
from solvan.application.liaison.engine import TurnResult, TurnState, TurnUsage, run_turn
from solvan.application.liaison.intents import (
    ConversationIntent,
    deterministic_reply,
    scope_deterministic_reply,
)
from solvan.application.liaison.parts import AccessMode, Part, PartKind, connective_part
from solvan.application.skills_selection import PostgresSkillSelector
from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_completion import mark_provider_request_dispatched
from solvan.persistence.liaison_runtime import TurnClaim
from solvan.persistence.liaison_store import LiaisonStore
from solvan.persistence.liaison_stream import TurnConflict, append_stream_event


class FreshnessRetry(TurnConflict):
    """The current generation streamed data before its input changed."""


class LiaisonPartStreamer:
    """Persist gated typed parts for one claim; discard them on failed fencing."""

    def __init__(
        self,
        *,
        connect: Callable[[], Any],
        scope: Scope,
        claim: TurnClaim,
    ) -> None:
        self._connect = connect
        self._scope = scope
        self._claim = claim
        self._parts: dict[int, tuple[str, Part]] = {}
        with self._connect() as connection:
            row = connection.execute(
                """SELECT COALESCE(max(sequence) + 1, 0)
                     FROM solvan_liaison.liaison_message_parts
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND message_id=%(message_id)s AND status='COMPLETED'""",
                {**scope.canonical_dict(), "message_id": claim.answer_message_id},
            ).fetchone()
        self._sequence_base = int(row[0]) if row else 0

    def emit(self, part: Part) -> None:
        if part.sequence in self._parts:
            raise RuntimeError("a Liaison part sequence was streamed twice")
        with self._connect() as connection, connection.transaction():
            owned = connection.execute(
                """SELECT 1 FROM solvan_liaison.liaison_turns
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND message_id=%(message_id)s AND attempt=%(attempt)s
                      AND generation=%(generation)s AND status='RUNNING'
                      AND lease_token=%(lease_token)s::uuid
                    FOR UPDATE""",
                {
                    **self._scope.canonical_dict(),
                    "message_id": self._claim.answer_message_id,
                    "attempt": self._claim.attempt,
                    "generation": self._claim.generation,
                    "lease_token": self._claim.lease_token,
                },
            ).fetchone()
            if owned is None:
                raise TurnConflict("streaming part append lost its turn lease")
            stored_part = replace(part, sequence=self._sequence_base + part.sequence)
            part_id = LiaisonStore(connection).begin_streaming_part(
                scope=self._scope,
                message_id=self._claim.answer_message_id,
                attempt=self._claim.attempt,
                generation=self._claim.generation,
                part=stored_part,
                initiating_principal=self._claim.principal,
            )
        self._parts[part.sequence] = (part_id, stored_part)

    def discard(self) -> None:
        if not self._parts:
            return
        with self._connect() as connection, connection.transaction():
            LiaisonStore(connection).discard_streaming_parts(
                scope=self._scope,
                message_id=self._claim.answer_message_id,
                attempt=self._claim.attempt,
                generation=self._claim.generation,
            )
        self._parts.clear()

    def part_ids(self) -> dict[int, str]:
        return {sequence: part_id for sequence, (part_id, _) in self._parts.items()}

    def has_parts(self) -> bool:
        return bool(self._parts)


class LiaisonCompositionMixin:
    """Internal mixin; LiaisonService supplies the shared composition state."""

    _connect: Any
    _registry: Any
    _issuer: Any
    _composer: Any
    reader: Any

    _FOLLOW_UP_TEMPLATE_TO_QUESTION: ClassVar[dict[str, str]] = {
        "RECOVERY_VERIFIED": "IS_IT_FIXED",
        "RECORD_STATEMENT": "WHAT_HAPPENED",
        "MEASURED_VALUE": "WHAT_WAS_THE_IMPACT",
        "AWAITING_HUMAN": "WHAT_NEEDS_ME",
        "DATA_LOSS_ABSENT": "WAS_DATA_LOST",
        "BLAST_RADIUS_CONTAINED": "IS_ANYTHING_ELSE_AFFECTED",
        "CHANGE_DEPLOYED": "WAS_THE_CHANGE_APPLIED",
    }

    @staticmethod
    def _projection_version(record: dict[str, Any]) -> str:
        for key in ("workflow_version", "version", "revision", "updated_at"):
            if key in record:
                return str(record[key])
        return "content-addressed"

    @staticmethod
    def _projection_digest(record: dict[str, Any]) -> str:
        version = LiaisonCompositionMixin._projection_version(record)
        if version != "content-addressed":
            # Rendered ages and countdowns change without authoritative state.
            # Bind durable identity/version; manifests bind child versions.
            material: object = {
                "identity": record.get("machine_id", record.get("id")),
                "version": version,
            }
        else:
            material = record
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
        return f"sha256:{hashlib.sha256(encoded.encode()).hexdigest()}"

    def _source_versions(
        self,
        anchor: Anchor,
        *,
        principal: str | None = None,
        scope: Scope | None = None,
    ) -> tuple[dict[str, Any], ...]:
        """Bind the anchor's current authorized graph without persisting its content."""

        reader = self.reader(principal=principal, scope=scope)
        root = (
            (str(anchor.record_type), str(anchor.record_id))
            if anchor.record_type and anchor.record_id
            else None
        )
        if root is None:
            return ()
        allowed = set(reader.authorized_records())
        selected = {root}
        changed = True
        edges = reader.record_edges()
        while changed:
            changed = False
            for parent_type, parent_id, child_type, child_id, _ in edges:
                parent = (parent_type, parent_id)
                child = (child_type, child_id)
                if parent in selected and child in allowed and child not in selected:
                    selected.add(child)
                    changed = True
                if child in selected and parent in allowed and parent not in selected:
                    selected.add(parent)
                    changed = True
        versions: list[dict[str, Any]] = []
        for record_type, record_id in sorted(selected):
            value = reader.read(record_type, record_id)
            if value is None:
                continue
            record = dict(value)
            versions.append(
                {
                    "record_type": record_type,
                    "record_id": record_id,
                    "version": self._projection_version(record),
                    "digest": self._projection_digest(record),
                }
            )
        return tuple(versions)

    def _current_input_state(
        self, *, scope: Scope, claim: TurnClaim, connection: Connection[Any] | None = None
    ) -> tuple[tuple[tuple[str, str, str, str], ...], int]:
        reader = self.reader(principal=claim.principal, scope=scope)
        versions: list[tuple[str, str, str, str]] = []
        for source in claim.source_versions:
            record_type = str(source["record_type"])
            record_id = str(source["record_id"])
            value = reader.read(record_type, record_id)
            if value is None:
                versions.append((record_type, record_id, "missing", "missing"))
                continue
            record = dict(value)
            versions.append(
                (
                    record_type,
                    record_id,
                    self._projection_version(record),
                    self._projection_digest(record),
                )
            )
        if connection is None:
            with self._connect() as opened:
                row = opened.execute(
                    """SELECT COALESCE(next_sequence-1,0)
                         FROM solvan_liaison.scope_event_sequences
                        WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s""",
                    scope.canonical_dict(),
                ).fetchone()
        else:
            row = connection.execute(
                """SELECT COALESCE(next_sequence-1,0)
                     FROM solvan_liaison.scope_event_sequences
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s FOR SHARE""",
                scope.canonical_dict(),
            ).fetchone()
        return tuple(versions), int(row[0]) if row else 0

    @staticmethod
    def _manifest_input_state(
        claim: TurnClaim,
    ) -> tuple[tuple[tuple[str, str, str, str], ...], int]:
        versions = tuple(
            (
                str(source["record_type"]),
                str(source["record_id"]),
                str(source["version"]),
                str(source["digest"]),
            )
            for source in claim.source_versions
        )
        return versions, claim.scope_sequence_high_water

    def _record_input_advanced(
        self, connection: Connection[Any], *, scope: Scope, claim: TurnClaim
    ) -> None:
        owned = connection.execute(
            """SELECT 1 FROM solvan_liaison.liaison_turns
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND message_id=%(message_id)s
                  AND attempt=%(attempt)s AND generation=%(generation)s
                  AND status='RUNNING' AND lease_token=%(lease_token)s::uuid""",
            {
                **scope.canonical_dict(),
                "message_id": claim.answer_message_id,
                "attempt": claim.attempt,
                "generation": claim.generation,
                "lease_token": claim.lease_token,
            },
        ).fetchone()
        if owned is None:
            return
        append_stream_event(
            connection,
            scope=scope,
            thread_id=claim.thread_id,
            event_type="turn.activity",
            message_id=claim.answer_message_id,
            attempt=claim.attempt,
            generation=claim.generation,
            payload={
                "activity": "INPUT_PROJECTION_ADVANCED",
                "tool_identifier": "projection.refresh",
                "result_class": "REFRESH_REQUIRED",
                "timing_ms": 0,
            },
        )

    def _compose_with_freshness(
        self, *, scope: Scope, claim: TurnClaim, part_stream: LiaisonPartStreamer | None = None
    ) -> tuple[TurnResult, tuple[tuple[tuple[str, str, str, str], ...], int]]:
        baseline = self._current_input_state(scope=scope, claim=claim)
        if baseline != self._manifest_input_state(claim):
            with self._connect() as connection, connection.transaction():
                self._record_input_advanced(connection, scope=scope, claim=claim)
        for _ in range(2):
            result = self._compose_claimed(scope=scope, claim=claim, part_stream=part_stream)
            current = self._current_input_state(scope=scope, claim=claim)
            if current == baseline:
                return result, current
            if part_stream is not None and part_stream.has_parts():
                part_stream.discard()
                raise FreshnessRetry("input changed after a part was streamed")
            baseline = current
            with self._connect() as connection, connection.transaction():
                self._record_input_advanced(connection, scope=scope, claim=claim)
        return result, baseline

    def _compose_claimed(
        self,
        *,
        scope: Scope,
        claim: TurnClaim,
        part_stream: LiaisonPartStreamer | None = None,
    ) -> TurnResult:
        intent = ConversationIntent(claim.conversation_intent)
        reply = (
            scope_deterministic_reply(intent, claim.question)
            if claim.anchor.kind.value == "SCOPE"
            else deterministic_reply(intent, claim.question)
        )
        if reply is not None:
            template_id, phrase = reply
            connective = self._registry().connective(template_id)
            part = connective_part(connective.render(phrase), sequence=0, template_id=template_id)
            return TurnResult(TurnState.COMPLETED, (part,), TurnUsage(), CompositionDefects())
        if intent is ConversationIntent.STEER_DRAFT:
            part = Part(
                kind=PartKind.STEER_DRAFT,
                sequence=0,
                payload={
                    "missing": "A new bounded telemetry read is required.",
                    "proposed_step": claim.question,
                    "tool_profile": ["metrics.read", "logs.read", "traces.read"],
                    "requires_confirmation": True,
                },
                classification="INTERNAL",
                access_mode=AccessMode.SYSTEM_PUBLIC,
            )
            return TurnResult(TurnState.COMPLETED, (part,), TurnUsage(), CompositionDefects())
        reader = self.reader(principal=claim.principal, scope=scope)
        if intent is ConversationIntent.GUIDANCE_REFERENCE:
            try:
                with self._connect() as connection:
                    selector = PostgresSkillSelector(connection)
                    parsed, candidate = selector.resolve_for_principal(
                        scope=scope,
                        principal=claim.principal,
                        command=claim.question,
                        runtime_region=os.environ.get("SOLVAN_REGION", "europe-west1"),
                    )
                    membership_epoch = LiaisonStore(connection).current_membership_epoch(
                        scope=scope,
                        thread_id=claim.thread_id,
                        principal=claim.principal,
                    )
                    invocation = selector.record_invocation(
                        scope=scope,
                        thread_id=claim.thread_id,
                        answer_message_id=claim.answer_message_id,
                        anchor_kind=claim.anchor.kind.value,
                        anchor_record_type=claim.anchor.record_type,
                        anchor_record_id=claim.anchor.record_id,
                        parsed=parsed,
                        candidate=candidate,
                        principal=claim.principal,
                        membership_epoch=membership_epoch,
                        policy_epoch=claim.policy_epoch,
                    )
            except ValueError as error:
                code, _, detail = str(error).partition(":")
                sentence = (
                    f"That skill reference is ambiguous. Use one of: {detail}."
                    if code == "GUIDANCE_SELECTOR_AMBIGUOUS" and detail
                    else "I cannot select that skill under your current scope and policy."
                )
                part = Part(
                    kind=PartKind.REFUSAL,
                    sequence=0,
                    payload={
                        "sentence": sentence,
                        "held_reason": code,
                        "releasing_record": "approved guidance or reader grant",
                    },
                    classification="INTERNAL",
                    access_mode=AccessMode.AUTHOR_ONLY,
                    author_principal=claim.principal,
                )
                return TurnResult(TurnState.COMPLETED, (part,), TurnUsage(), CompositionDefects())
            if invocation.status == "REFUSED":
                part = Part(
                    kind=PartKind.REFUSAL,
                    sequence=0,
                    payload={
                        "sentence": "That skill conflicts with guidance already selected here.",
                        "held_reason": invocation.conflict_reason or "GUIDANCE_CONFLICT",
                        "releasing_record": "guidance invocation conflict",
                    },
                    classification="INTERNAL",
                    access_mode=AccessMode.AUTHOR_ONLY,
                    author_principal=claim.principal,
                )
            else:
                part = Part(
                    kind=PartKind.GUIDANCE_REF,
                    sequence=0,
                    payload={
                        "invocation_request_id": invocation.request_id,
                        "guidance_key": candidate.guidance_key,
                        "guidance_version": candidate.version,
                        "guidance_hash": candidate.revision_hash,
                        "status": invocation.status,
                    },
                    classification="INTERNAL",
                    access_mode=AccessMode.AUTHOR_ONLY,
                    author_principal=claim.principal,
                )
            return TurnResult(TurnState.COMPLETED, (part,), TurnUsage(), CompositionDefects())
        if intent is ConversationIntent.ACTION_REFERENCE:
            incident = (
                reader.read(str(claim.anchor.record_type), str(claim.anchor.record_id))
                if claim.anchor.record_type == "incident" and claim.anchor.record_id
                else None
            )
            actions = incident.get("actions") if incident is not None else None
            eligible = [
                action
                for action in actions or ()
                if isinstance(action, Mapping)
                and action.get("id")
                and str(action.get("status", "")).upper() == "AWAITING_APPROVAL"
            ]
            if len(eligible) != 1:
                part = Part(
                    kind=PartKind.REFUSAL,
                    sequence=0,
                    payload={
                        "sentence": (
                            "I cannot identify one approval-eligible action on this incident. "
                            "Open the Actions view to inspect the governed records."
                        ),
                        "held_reason": "No single anchor-bound action is approval-eligible.",
                        "releasing_record": "action",
                    },
                    classification="INTERNAL",
                    access_mode=AccessMode.SYSTEM_PUBLIC,
                )
                return TurnResult(TurnState.COMPLETED, (part,), TurnUsage(), CompositionDefects())
            part = Part(
                kind=PartKind.APPROVAL_REF,
                sequence=0,
                # The conversation carries a reference only. The console reads
                # the durable action and renders the same ApprovalPanel used by
                # the Actions view; channels turn this id into a deep link.
                payload={"action_id": str(eligible[0]["id"])},
                classification="INTERNAL",
                access_mode=AccessMode.SYSTEM_PUBLIC,
            )
            return TurnResult(TurnState.COMPLETED, (part,), TurnUsage(), CompositionDefects())
        question = claim.question
        if intent is ConversationIntent.FOLLOW_UP:
            resolved_question = self._resolved_follow_up_question(scope=scope, claim=claim)
            if resolved_question is None:
                parked_request_id = new_identifier("prk")
                candidates = [
                    reference
                    for reference in claim.resolved_references
                    if reference.get("kind") == "PART"
                ]
                part = Part(
                    kind=PartKind.PARKED_REQUEST,
                    sequence=0,
                    payload={
                        "kind": "QUESTION",
                        "request_id": parked_request_id,
                        "prompt": (
                            "Which earlier point do you mean? Reply with its number so I can "
                            "re-read the current ledger under your present access."
                        ),
                        "candidate_count": len(candidates),
                        "candidates": [
                            {
                                "number": index,
                                "part_ref": item["ref"],
                            }
                            for index, item in enumerate(candidates, start=1)
                        ],
                    },
                    classification="INTERNAL",
                    access_mode=AccessMode.AUTHOR_ONLY,
                    author_principal=claim.principal,
                )
                return TurnResult(TurnState.PARKED, (part,), TurnUsage(), CompositionDefects())
            question = resolved_question
        reader = self.reader(principal=claim.principal, scope=scope)
        scoped_reader = getattr(reader, "authorized_records_for_anchor", None)
        entity_set = tuple(scoped_reader(claim.anchor)) if scoped_reader is not None else ()
        entity_set_digest = hashlib.sha256(
            json.dumps(entity_set, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        grant = self._issuer.read_grant(
            principal=claim.principal,
            scope=scope,
            thread_id=claim.thread_id,
            message_id=claim.answer_message_id,
            attempt=claim.attempt,
            anchor_label=claim.anchor.label(),
            anchor_entity_set_digest=f"sha256:{entity_set_digest}",
            classification_ceiling="INTERNAL",
            policy_epoch=claim.policy_epoch,
        )
        with self._connect() as connection, connection.transaction():
            if not mark_provider_request_dispatched(connection, scope=scope, claim=claim):
                raise RuntimeError("exact Liaison provider request is no longer dispatchable")
        return run_turn(
            question=question,
            anchor=claim.anchor,
            reader=reader,
            registry=self._registry(),
            composer=self._composer,
            grant=grant,
            provider_input=claim.provider_input,
            part_sink=part_stream,
        )

    def _resolve_follow_up_candidates(
        self,
        connection: Connection[Any],
        *,
        scope: Scope,
        thread_id: str,
        principal: str,
        question: str,
        intent: ConversationIntent,
    ) -> tuple[dict[str, Any], ...]:
        """Resolve only reader-visible prior claim parts into manifest refs."""

        if intent is not ConversationIntent.FOLLOW_UP:
            return ()
        messages = LiaisonStore(connection).transcript(
            scope=scope,
            thread_id=thread_id,
            reader_principal=principal,
            authorized_records=self.reader(principal=principal, scope=scope).authorized_records(),
            limit=100,
        )
        prior = next(
            (
                message
                for message in reversed(messages)
                if message.role == "LIAISON" and message.turn_state == "COMPLETED"
            ),
            None,
        )
        if prior is None:
            return ()
        candidates: list[dict[str, Any]] = []
        for part in prior.parts:
            if part.kind is not PartKind.CLAIM:
                continue
            template_id = str(part.payload.get("template_id", ""))
            question_id = self._FOLLOW_UP_TEMPLATE_TO_QUESTION.get(template_id)
            # A candidate is a typed projection reference, not answer prose.
            # The question shape comes from the application-owned template
            # registry and is therefore safe to carry across a parked turn.
            if question_id is None:
                continue
            candidates.append(
                {
                    "kind": "PART",
                    "ref": f"{prior.id}:{part.sequence}",
                    "source_part_id": None,
                }
            )
        return tuple(candidates)

    def _resolved_follow_up_question(self, *, scope: Scope, claim: TurnClaim) -> str | None:
        candidates = [
            reference for reference in claim.resolved_references if reference.get("kind") == "PART"
        ]
        if len(candidates) == 1:
            return self._question_prompt_for_candidate(
                scope=scope, claim=claim, candidate=candidates[0], question=claim.question
            )
        answer_refs = [
            reference
            for reference in claim.resolved_references
            if reference.get("kind") == "MESSAGE"
            and str(reference.get("ref", "")).startswith("parked-answer:")
        ]
        if not answer_refs or not candidates:
            return None
        parked_id = str(answer_refs[-1]["ref"]).split(":", 2)[1]
        with self._connect() as connection:
            row = connection.execute(
                """SELECT answer_json FROM solvan_liaison.liaison_parked_requests
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND id=%(request_id)s
                      AND status='ANSWERED'""",
                {**scope.canonical_dict(), "request_id": parked_id},
            ).fetchone()
        if row is None:
            return None
        answer = str(dict(row[0] or {}).get("feedback", "")).strip().lower()
        words = {
            "first": 0,
            "1": 0,
            "one": 0,
            "second": 1,
            "2": 1,
            "two": 1,
            "third": 2,
            "3": 2,
            "three": 2,
        }
        selected = next((index for word, index in words.items() if word in answer.split()), None)
        if selected is None or selected >= len(candidates):
            return None
        return self._question_prompt_for_candidate(
            scope=scope, claim=claim, candidate=candidates[selected], question=claim.question
        )

    def _question_prompt_for_candidate(
        self, *, scope: Scope, claim: TurnClaim, candidate: Mapping[str, Any], question: str
    ) -> str | None:
        """Resolve a follow-up through its typed claim candidate.

        The candidate carries only a schema-approved message/sequence
        reference. Re-read that part through the current reader projection at
        composition time so a visibility change parks instead of leaking the
        old claim or trusting metadata supplied by the user.
        """

        ref = str(candidate.get("ref", ""))
        message_id, separator, sequence_text = ref.partition(":")
        if not separator or not sequence_text.isdigit():
            return None
        with self._connect() as connection:
            messages = LiaisonStore(connection).transcript(
                scope=scope,
                thread_id=claim.thread_id,
                reader_principal=claim.principal,
                authorized_records=self.reader(
                    principal=claim.principal, scope=scope
                ).authorized_records(),
                limit=100,
            )
        selected_part = next(
            (
                part
                for message in messages
                if message.id == message_id
                for part in message.parts
                if part.sequence == int(sequence_text) and part.kind is PartKind.CLAIM
            ),
            None,
        )
        if selected_part is None:
            return None
        question_id = self._FOLLOW_UP_TEMPLATE_TO_QUESTION.get(
            str(selected_part.payload.get("template_id", ""))
        )
        prompts = {
            "IS_IT_FIXED": "Is it fixed?",
            "WHAT_HAPPENED": "What happened?",
            "WHAT_WAS_THE_IMPACT": "What was the impact?",
            "WHAT_NEEDS_ME": "What needs a person?",
            "WAS_DATA_LOST": "Was any data lost?",
            "IS_ANYTHING_ELSE_AFFECTED": "Is anything else affected?",
            "WHAT_IS_THE_EVIDENCE": "What evidence is this based on?",
            "WAS_THE_CHANGE_APPLIED": "Was the change applied?",
        }
        return prompts.get(question_id) if question_id is not None else None

    @staticmethod
    def _normalize_follow_up(question: str) -> str:
        lowered = question.lower()
        if any(word in lowered for word in ("recover", "fixed", "safe", "after")):
            return "Is it fixed?"
        if any(word in lowered for word in ("impact", "customer", "bad")):
            return "What was the impact?"
        if any(word in lowered for word in ("action", "change", "applied")):
            return "Was the change applied?"
        return "What happened?"

    @staticmethod
    def _completion_state(state: TurnState) -> tuple[str, str | None]:
        return {
            TurnState.COMPLETED: ("COMPLETED", "ANSWER_COMPLETED"),
            TurnState.PARKED: ("PARKED", None),
            TurnState.INTERRUPTED: ("INTERRUPTED", "USER_ABORTED"),
            TurnState.ERROR: ("FAILED", "TURN_ERROR"),
            TurnState.STREAMING: ("FAILED", "TURN_ERROR"),
        }[state]

    @staticmethod
    def _durable_state(state: TurnState) -> str:
        return LiaisonCompositionMixin._completion_state(state)[0]
