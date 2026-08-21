"""Fenced Liaison provider dispatch and terminal turn persistence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from psycopg import Connection

from solvan.application.liaison.parts import Part
from solvan.domain import Scope
from solvan.persistence.liaison_budget import record_daily_usage
from solvan.persistence.liaison_parked import ParkedKind, ParkedRequestStore
from solvan.persistence.liaison_runtime import TurnClaim
from solvan.persistence.liaison_store import LiaisonStore
from solvan.persistence.liaison_stream import TurnConflict, append_stream_event


def mark_provider_request_dispatched(
    connection: Connection[Any], *, scope: Scope, claim: TurnClaim
) -> bool:
    """Record the exact external-call boundary before any provider bytes leave."""

    row = connection.execute(
        """UPDATE solvan_liaison.liaison_provider_requests
              SET state='DISPATCHED',dispatched_at=COALESCE(dispatched_at,now()),
                  dispatch_count=dispatch_count+1
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND id=%(request_id)s
              AND message_id=%(message_id)s AND attempt=%(attempt)s
              AND generation=%(generation)s AND provider_input_digest=%(input_digest)s
              AND state IN ('PREPARED','DISPATCHED')
        RETURNING id""",
        {
            **scope.canonical_dict(),
            "request_id": claim.provider_request_id,
            "message_id": claim.answer_message_id,
            "attempt": claim.attempt,
            "generation": claim.generation,
            "input_digest": claim.provider_input_digest,
        },
    ).fetchone()
    return row is not None


def finish_claimed_turn(
    connection: Connection[Any],
    *,
    scope: Scope,
    claim: TurnClaim,
    state: str,
    terminal_reason: str | None,
    parts: tuple[Part, ...],
    model_calls: int,
    tool_calls: int,
    tokens: int,
    streamed_part_ids: Mapping[int, str] | None = None,
) -> bool:
    """Commit parts and terminal state iff the provider still owns this attempt."""

    current = connection.execute(
        """SELECT 1 FROM solvan_liaison.liaison_turns
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND message_id=%(message_id)s
              AND attempt=%(attempt)s AND generation=%(generation)s
              AND status='RUNNING' AND lease_token=%(lease_token)s::uuid
            FOR UPDATE""",
        {
            **scope.canonical_dict(),
            "message_id": claim.answer_message_id,
            "attempt": claim.attempt,
            "generation": claim.generation,
            "lease_token": claim.lease_token,
        },
    ).fetchone()
    if current is None:
        return False
    provider_state = connection.execute(
        """SELECT state FROM solvan_liaison.liaison_provider_requests
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND id=%(request_id)s
              AND message_id=%(message_id)s AND attempt=%(attempt)s
              AND generation=%(generation)s FOR UPDATE""",
        {
            **scope.canonical_dict(),
            "request_id": claim.provider_request_id,
            "message_id": claim.answer_message_id,
            "attempt": claim.attempt,
            "generation": claim.generation,
        },
    ).fetchone()
    if provider_state is None:
        raise TurnConflict("claimed turn lost its exact provider-request receipt")
    sequence_base = 0
    if claim.attempt > 1:
        prior = connection.execute(
            """SELECT COALESCE(max(sequence)+1,0)
                 FROM solvan_liaison.liaison_message_parts
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND message_id=%(message_id)s
                  AND status='COMPLETED'""",
            {**scope.canonical_dict(), "message_id": claim.answer_message_id},
        ).fetchone()
        sequence_base = int(prior[0]) if prior else 0
    stored_parts = tuple(replace(part, sequence=sequence_base + part.sequence) for part in parts)
    store = LiaisonStore(connection)
    stream_ids = dict(streamed_part_ids or {})
    if stream_ids and set(stream_ids) != {part.sequence for part in parts}:
        raise TurnConflict("streamed part set does not match the terminal result")
    part_ids_list: list[str] = []
    pending_parts: list[Part] = []
    for original, stored in zip(parts, stored_parts, strict=True):
        part_id = stream_ids.get(original.sequence)
        if part_id is None:
            pending_parts.append(stored)
            part_ids_list.append("")
            continue
        completed = store.complete_streaming_part(
            scope=scope,
            message_id=claim.answer_message_id,
            part_id=part_id,
            attempt=claim.attempt,
            generation=claim.generation,
            part=stored,
            initiating_principal=claim.principal,
        )
        if not completed:
            raise TurnConflict("streamed part was already completed or discarded")
        part_ids_list.append(part_id)
    if pending_parts:
        pending_ids = store.append_parts(
            scope=scope,
            message_id=claim.answer_message_id,
            parts=pending_parts,
            attempt=claim.attempt,
            generation=claim.generation,
        )
        pending_iter = iter(pending_ids)
        part_ids_list = [item if item else next(pending_iter) for item in part_ids_list]
    part_ids = tuple(part_ids_list)
    if state == "PARKED":
        _persist_parked_request(connection, scope=scope, claim=claim, parts=stored_parts)
    terminal = state in {"COMPLETED", "INTERRUPTED", "FAILED"}
    connection.execute(
        """UPDATE solvan_liaison.liaison_turns SET status=%(state)s,
              terminal_reason=%(terminal_reason)s,lease_owner=NULL,lease_token=NULL,
              lease_expires_at=NULL,heartbeat_at=NULL,model_calls=%(model_calls)s,
              tool_calls=%(tool_calls)s,tokens=%(tokens)s,
              ended_at=CASE WHEN %(terminal)s THEN now() ELSE NULL END
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND message_id=%(message_id)s
              AND attempt=%(attempt)s AND generation=%(generation)s""",
        {
            **scope.canonical_dict(),
            "message_id": claim.answer_message_id,
            "attempt": claim.attempt,
            "generation": claim.generation,
            "state": state,
            "terminal_reason": terminal_reason,
            "terminal": terminal,
            "model_calls": model_calls,
            "tool_calls": tool_calls,
            "tokens": tokens,
        },
    )
    _terminalize_provider_request(
        connection,
        scope=scope,
        claim=claim,
        provider_state=str(provider_state[0]),
        turn_state=state,
    )
    connection.execute(
        """UPDATE solvan_liaison.liaison_messages SET turn_state=%(state)s,
              completed_at=CASE WHEN %(terminal)s THEN now() ELSE NULL END
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND id=%(message_id)s""",
        {
            **scope.canonical_dict(),
            "message_id": claim.answer_message_id,
            "state": state,
            "terminal": terminal,
        },
    )
    _publish_terminal_events(
        connection,
        scope=scope,
        claim=claim,
        state=state,
        terminal_reason=terminal_reason,
        stored_parts=stored_parts,
        part_ids=part_ids,
        model_calls=model_calls,
        tool_calls=tool_calls,
        tokens=tokens,
    )
    if terminal:
        record_daily_usage(
            connection,
            scope=scope,
            thread_id=claim.thread_id,
            principal=claim.principal,
            model_calls=model_calls,
            tool_calls=tool_calls,
            tokens=tokens,
        )
    if terminal or state == "PARKED":
        from solvan.persistence.liaison_turn_control import promote_next_turn

        promote_next_turn(connection, scope=scope, thread_id=claim.thread_id)
    return True


def _persist_parked_request(
    connection: Connection[Any],
    *,
    scope: Scope,
    claim: TurnClaim,
    parts: tuple[Part, ...],
) -> None:
    parked_parts = [part for part in parts if str(part.kind) == "parked_request"]
    if len(parked_parts) != 1:
        raise TurnConflict("a parked turn must carry exactly one parked-request part")
    parked_payload = dict(parked_parts[0].payload)
    try:
        parked_kind = ParkedKind(str(parked_payload.get("kind", "QUESTION")))
    except ValueError as error:
        raise TurnConflict("a parked turn names an unknown request kind") from error
    expected_workflow_version = None
    if parked_kind is ParkedKind.STEER_CONFIRMATION:
        source = next(
            (
                item
                for item in claim.source_versions
                if item.get("record_type") == claim.anchor.record_type
                and item.get("record_id") == claim.anchor.record_id
            ),
            None,
        )
        raw_version = None if source is None else source.get("version")
        if raw_version is not None and str(raw_version).isdigit():
            expected_workflow_version = int(str(raw_version))
    ParkedRequestStore(connection).park(
        scope=scope,
        thread_id=claim.thread_id,
        message_id=claim.answer_message_id,
        kind=parked_kind,
        payload=parked_payload,
        initiated_by_principal=claim.principal,
        expected_workflow_version=expected_workflow_version,
        binding_id=(
            f"principal:{claim.principal}" if parked_kind is ParkedKind.STEER_CONFIRMATION else None
        ),
        binding_epoch=(
            claim.policy_epoch if parked_kind is ParkedKind.STEER_CONFIRMATION else None
        ),
        request_id=str(parked_payload["request_id"]),
    )


def _terminalize_provider_request(
    connection: Connection[Any],
    *,
    scope: Scope,
    claim: TurnClaim,
    provider_state: str,
    turn_state: str,
) -> None:
    next_state = (
        "NOT_SENT"
        if provider_state == "PREPARED"
        else ("COMPLETED" if turn_state in {"COMPLETED", "PARKED"} else "FAILED")
    )
    connection.execute(
        """UPDATE solvan_liaison.liaison_provider_requests
              SET state=%(state)s,terminal_at=now()
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND id=%(request_id)s
              AND state=%(expected_state)s""",
        {
            **scope.canonical_dict(),
            "request_id": claim.provider_request_id,
            "state": next_state,
            "expected_state": provider_state,
        },
    )


def _publish_terminal_events(
    connection: Connection[Any],
    *,
    scope: Scope,
    claim: TurnClaim,
    state: str,
    terminal_reason: str | None,
    stored_parts: tuple[Part, ...],
    part_ids: tuple[str, ...],
    model_calls: int,
    tool_calls: int,
    tokens: int,
) -> None:
    for part, part_id in zip(stored_parts, part_ids, strict=True):
        event_access_mode = str(part.access_mode)
        event_audience = part.author_principal
        if event_access_mode == "DERIVED_SOURCES":
            event_access_mode = "AUTHOR_ONLY"
            event_audience = claim.principal
        append_stream_event(
            connection,
            scope=scope,
            thread_id=claim.thread_id,
            event_type="message.part.completed",
            message_id=claim.answer_message_id,
            part_id=part_id,
            attempt=claim.attempt,
            generation=claim.generation,
            classification=part.classification,
            access_mode=event_access_mode,
            audience_principal=event_audience,
            membership_epoch=part.membership_epoch,
            payload={"kind": str(part.kind), "sequence": part.sequence},
        )
    event_type = {
        "COMPLETED": "turn.completed",
        "PARKED": "turn.parked",
        "INTERRUPTED": "turn.interrupted",
        "FAILED": "turn.error",
    }[state]
    append_stream_event(
        connection,
        scope=scope,
        thread_id=claim.thread_id,
        event_type=event_type,
        message_id=claim.answer_message_id,
        attempt=claim.attempt,
        generation=claim.generation,
        payload={
            "state": state,
            "terminal_reason": terminal_reason,
            "usage": {
                "model_calls": model_calls,
                "tool_calls": tool_calls,
                "tokens": tokens,
            },
        },
    )
