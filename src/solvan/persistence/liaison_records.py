"""Typed conversation records shared by stores and channel adapters."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from solvan.application.liaison.anchors import Anchor
from solvan.application.liaison.parts import Part


@dataclass(frozen=True, slots=True)
class ThreadRecord:
    id: str
    anchor: Anchor
    visibility: str
    status: str
    created_by_principal: str
    last_activity_at: datetime


@dataclass(frozen=True, slots=True)
class MessageRecord:
    id: str
    thread_id: str
    role: str
    author_principal: str | None
    turn_state: str
    classification: str
    created_at: datetime
    in_reply_to_message_id: str | None = None
    parts: tuple[Part, ...] = ()
