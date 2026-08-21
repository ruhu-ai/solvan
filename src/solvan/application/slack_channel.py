"""Strict Slack ingress authentication and event normalization.

Slack text is untrusted channel data.  This module proves only provider
authenticity and replay freshness; it never assigns a Solvan principal or
scope.  Those come from the durable channel binding.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class SlackIngressError(RuntimeError):
    pass


class SlackMessage(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    type: str
    user: str = Field(pattern=r"^[UW][A-Z0-9]{2,30}$")
    channel: str = Field(pattern=r"^[CDG][A-Z0-9]{2,30}$")
    ts: str = Field(pattern=r"^[0-9]{10,}\.[0-9]{6}$")
    text: str = Field(min_length=1, max_length=12_000)
    thread_ts: str | None = Field(default=None, pattern=r"^[0-9]{10,}\.[0-9]{6}$")
    subtype: str | None = None
    bot_id: str | None = None


class SlackEventsEnvelope(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    type: str
    team_id: str = Field(pattern=r"^T[A-Z0-9]{2,30}$")
    event_id: str = Field(pattern=r"^Ev[A-Z0-9]{2,80}$")
    event_time: int = Field(gt=0)
    event: SlackMessage


class SlackUrlVerification(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    type: str
    team_id: str = Field(pattern=r"^T[A-Z0-9]{2,30}$")
    challenge: str = Field(min_length=8, max_length=512)


VerifiedSlackRequest = SlackEventsEnvelope | SlackUrlVerification


def verify_slack_event(
    *,
    signing_secret: bytes,
    timestamp: str | None,
    signature: str | None,
    body: bytes,
    now: datetime | None = None,
) -> SlackEventsEnvelope:
    """Authenticate and normalize one Slack Events API message."""

    verified = verify_slack_request(
        signing_secret=signing_secret,
        timestamp=timestamp,
        signature=signature,
        body=body,
        now=now,
    )
    if not isinstance(verified, SlackEventsEnvelope):
        raise SlackIngressError("Slack request is not an event callback")
    return verified


def verify_slack_request(
    *,
    signing_secret: bytes,
    timestamp: str | None,
    signature: str | None,
    body: bytes,
    now: datetime | None = None,
) -> VerifiedSlackRequest:
    """Authenticate one event callback or URL verification challenge."""

    if not signing_secret:
        raise SlackIngressError("Slack signing secret is unavailable")
    if len(body) > 64 * 1024:
        raise SlackIngressError("Slack payload exceeds 64 KiB")
    if timestamp is None or signature is None or not signature.startswith("v0="):
        raise SlackIngressError("Slack signature material is missing")
    try:
        observed = int(timestamp)
    except ValueError as error:
        raise SlackIngressError("Slack timestamp is malformed") from error
    current = now or datetime.now(UTC)
    if abs(int(current.timestamp()) - observed) > 300:
        raise SlackIngressError("Slack request is outside the replay window")
    base = b"v0:" + timestamp.encode("ascii") + b":" + body
    expected = "v0=" + hmac.new(signing_secret, base, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise SlackIngressError("Slack signature verification failed")
    try:
        raw = json.loads(body)
        if not isinstance(raw, dict):
            raise SlackIngressError("Slack request body is not an object")
        if raw.get("type") == "url_verification":
            return SlackUrlVerification.model_validate(raw)
        envelope = SlackEventsEnvelope.model_validate(raw)
    except (json.JSONDecodeError, ValidationError) as error:
        raise SlackIngressError("Slack event contract is invalid") from error
    if envelope.type != "event_callback" or envelope.event.type != "message":
        raise SlackIngressError("Slack event kind is not supported")
    if envelope.event.subtype is not None or envelope.event.bot_id is not None:
        raise SlackIngressError("Slack bot and subtype messages are not accepted")
    return envelope


def peek_slack_team_id(body: bytes) -> str:
    """Select a configured installation before verification; grants no authority."""

    if len(body) > 64 * 1024:
        raise SlackIngressError("Slack payload exceeds 64 KiB")
    try:
        value = json.loads(body)
    except json.JSONDecodeError as error:
        raise SlackIngressError("Slack event contract is invalid") from error
    if not isinstance(value, dict):
        raise SlackIngressError("Slack request body is not an object")
    team_id = value.get("team_id")
    if (
        not isinstance(team_id, str)
        or len(team_id) < 3
        or len(team_id) > 31
        or not team_id.startswith("T")
        or not team_id[1:].isalnum()
        or team_id.upper() != team_id
    ):
        raise SlackIngressError("Slack team id is invalid")
    return team_id


def slack_channel_identity(*, team_id: str, user_id: str) -> str:
    """Return the enrollment key; it conveys no authority by itself."""

    return f"slack:{team_id}:{user_id}"


def slack_conversation_id(message: SlackMessage) -> str:
    """Canonical Slack conversation key; it carries no Solvan thread authority."""

    return f"slack:{message.channel}:{message.thread_ts or message.ts}"
