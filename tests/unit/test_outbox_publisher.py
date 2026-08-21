from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any, ClassVar
from uuid import uuid4

import pytest

from apps.publisher.main import OutboxPublisherRunner
from solvan.application import OutboxEnvelope
from solvan.application.ports import ClaimedEvent
from solvan.domain import Scope
from solvan.platform.pubsub import GooglePubSubPublisher, PublishReceipt

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)


class FakeResponse:
    status_code = 200
    headers: ClassVar[dict[str, str]] = {}

    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self.payload


class FakeSession:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((url, kwargs))
        return FakeResponse(self.payload)


def envelope() -> OutboxEnvelope:
    return OutboxEnvelope(
        event_id="evt_00000000000000000000000000",
        aggregate_type="INCIDENT",
        aggregate_id="inc_00000000000000000000000000",
        aggregate_version=1,
        topic="incidents",
        event_type="IncidentDetected",
        payload={"state": "DETECTED"},
        idempotency_key="incident-created:inc_00000000000000000000000000",
    )


def test_pubsub_publishes_stable_event_id_and_payload() -> None:
    session = FakeSession({"messageIds": ["google-message-1"]})
    receipt = GooglePubSubPublisher(
        project_id="solvan-demo", topic="solvan-workflow", session=session
    ).publish(envelope())

    assert receipt.message_id == "google-message-1"
    message = session.calls[0][1]["json"]["messages"][0]
    decoded = json.loads(base64.b64decode(message["data"]))
    assert decoded["outbox_event_id"] == envelope().event_id
    assert decoded["payload"] == {"state": "DETECTED"}
    assert message["attributes"]["idempotency_key"] == envelope().idempotency_key


def test_pubsub_rejects_missing_message_id() -> None:
    with pytest.raises(RuntimeError, match="message ID"):
        GooglePubSubPublisher(
            project_id="solvan-demo", topic="solvan-workflow", session=FakeSession({})
        ).publish(envelope())


class FakeRepository:
    def __init__(self) -> None:
        self.claim_value = ClaimedEvent(
            event_id=envelope().event_id,
            event_type=envelope().event_type,
            claim_token=uuid4(),
            claim_expires_at=datetime(2026, 8, 8, tzinfo=UTC),
        )
        self.completed: list[str] = []

    def claim(self, **_kwargs: object) -> tuple[ClaimedEvent, ...]:
        return (self.claim_value,)

    def load(self, **_kwargs: object) -> OutboxEnvelope:
        return envelope()

    def complete(self, **kwargs: object) -> None:
        claim = kwargs["claim"]
        assert isinstance(claim, ClaimedEvent)
        self.completed.append(claim.event_id)


class FakePublisher:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail

    def publish(self, value: OutboxEnvelope) -> PublishReceipt:
        if self.fail:
            raise RuntimeError("network failed")
        return PublishReceipt(message_id="message-1", event_id=value.event_id)


def test_runner_completes_only_after_publish_success() -> None:
    repository = FakeRepository()
    stats = OutboxPublisherRunner(
        scope=SCOPE,
        owner="publisher-1",
        repository=repository,
        publisher=FakePublisher(),
    ).run()
    assert stats.published == 1
    assert repository.completed == [envelope().event_id]

    failed_repository = FakeRepository()
    with pytest.raises(RuntimeError, match="network failed"):
        OutboxPublisherRunner(
            scope=SCOPE,
            owner="publisher-1",
            repository=failed_repository,
            publisher=FakePublisher(fail=True),
        ).run()
    assert failed_repository.completed == []
