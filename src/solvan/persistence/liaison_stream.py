"""Bounded, replayable public events for the conversational surface."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from psycopg import Connection

from solvan.domain import Scope, new_identifier


class TurnConflict(RuntimeError):
    """An exact conversational compare-and-swap or event append lost."""


@dataclass(frozen=True, slots=True)
class StreamEvent:
    sequence: int
    event_id: str
    event_type: str
    message_id: str | None
    attempt: int | None
    generation: int | None
    payload: dict[str, Any]


def _payload_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return f"sha256:{hashlib.sha256(encoded.encode()).hexdigest()}"


def append_stream_event(
    connection: Connection[Any],
    *,
    scope: Scope,
    thread_id: str,
    event_type: str,
    message_id: str | None = None,
    part_id: str | None = None,
    attempt: int | None = None,
    generation: int | None = None,
    payload: dict[str, Any] | None = None,
    classification: str = "INTERNAL",
    access_mode: str = "SYSTEM_PUBLIC",
    audience_principal: str | None = None,
    membership_epoch: int | None = None,
) -> StreamEvent:
    """Append one bounded public-protocol event under the thread lock."""

    sequence_row = connection.execute(
        """UPDATE solvan_liaison.liaison_threads
              SET next_stream_sequence = next_stream_sequence + 1
            WHERE organization_id=%(organization_id)s
              AND project_id=%(project_id)s AND environment_id=%(environment_id)s
              AND id=%(thread_id)s
        RETURNING next_stream_sequence - 1""",
        {**scope.canonical_dict(), "thread_id": thread_id},
    ).fetchone()
    if sequence_row is None:
        raise TurnConflict("thread disappeared while allocating an event sequence")
    sequence = int(sequence_row[0])
    event_id = new_identifier("lev")
    safe_payload = payload or {}
    connection.execute(
        """INSERT INTO solvan_liaison.liaison_stream_events (
              organization_id,project_id,environment_id,thread_id,stream_sequence,
              event_id,event_type,schema_version,message_id,part_id,attempt,generation,
              classification,access_mode,audience_principal,membership_epoch,
              payload_json,payload_hash)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(thread_id)s,
              %(sequence)s,%(event_id)s,%(event_type)s,1,%(message_id)s,%(part_id)s,
              %(attempt)s,%(generation)s,%(classification)s,%(access_mode)s,
              %(audience_principal)s,%(membership_epoch)s,%(payload)s::jsonb,%(payload_hash)s)""",
        {
            **scope.canonical_dict(),
            "thread_id": thread_id,
            "sequence": sequence,
            "event_id": event_id,
            "event_type": event_type,
            "message_id": message_id,
            "part_id": part_id,
            "attempt": attempt,
            "generation": generation,
            "classification": classification,
            "access_mode": access_mode,
            "audience_principal": audience_principal,
            "membership_epoch": membership_epoch,
            "payload": json.dumps(safe_payload, sort_keys=True, default=str),
            "payload_hash": _payload_hash(safe_payload),
        },
    )
    return StreamEvent(
        sequence, event_id, event_type, message_id, attempt, generation, safe_payload
    )
