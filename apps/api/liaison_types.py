"""Small shared Liaison service result and idempotency types."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from solvan.application.liaison.claims import CompositionDefects
from solvan.application.liaison.engine import TurnResult, TurnUsage

EMPTY_USAGE = TurnUsage()
EMPTY_DEFECTS = CompositionDefects()


class IdempotencyConflict(RuntimeError):
    """The same key arrived carrying a different request."""


def request_digest(
    *,
    principal: str,
    anchor: str,
    question: str,
    thread_id: str | None,
    mentions: tuple[str, ...] = (),
) -> str:
    material = json.dumps(
        {
            "principal": principal,
            "anchor": anchor,
            "question": question,
            "thread": thread_id,
            "mentions": sorted(set(mentions)),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{hashlib.sha256(material.encode()).hexdigest()}"


@dataclass(frozen=True, slots=True)
class TurnOutcome:
    thread_id: str
    user_message_id: str
    answer_message_id: str
    result: TurnResult
    durable_state: str | None = None
    attempt: int = 1
    generation: int = 1
    queue_sequence: int | None = None
