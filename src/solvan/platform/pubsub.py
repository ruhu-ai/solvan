"""Google Pub/Sub REST publisher for stable durable-outbox event IDs."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import asdict, dataclass

from solvan.application import OutboxEnvelope
from solvan.platform.google_rest import GoogleRestSession

_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_TOPIC = re.compile(r"^[A-Za-z][A-Za-z0-9._~+%-]{2,254}$")


@dataclass(frozen=True, slots=True)
class PublishReceipt:
    message_id: str
    event_id: str


class GooglePubSubPublisher:
    def __init__(self, *, project_id: str, topic: str, session: GoogleRestSession) -> None:
        if not _PROJECT.fullmatch(project_id):
            raise ValueError("invalid Pub/Sub project ID")
        if not _TOPIC.fullmatch(topic):
            raise ValueError("invalid Pub/Sub topic name")
        self._project_id = project_id
        self._topic = topic
        self._session = session

    def publish(self, envelope: OutboxEnvelope) -> PublishReceipt:
        event = {
            "schema_version": 1,
            "outbox_event_id": envelope.event_id,
            **asdict(envelope),
        }
        content = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
        response = self._session.post(
            f"https://pubsub.googleapis.com/v1/projects/{self._project_id}"
            f"/topics/{self._topic}:publish",
            json={
                "messages": [
                    {
                        "data": base64.b64encode(content).decode(),
                        "attributes": {
                            "event_id": envelope.event_id,
                            "event_type": envelope.event_type,
                            "idempotency_key": envelope.idempotency_key,
                        },
                    }
                ]
            },
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()
        message_ids = payload.get("messageIds") if isinstance(payload, dict) else None
        if not isinstance(message_ids, list) or len(message_ids) != 1:
            raise RuntimeError("Pub/Sub publish returned no single message ID")
        message_id = message_ids[0]
        if not isinstance(message_id, str) or not message_id:
            raise RuntimeError("Pub/Sub message ID is invalid")
        return PublishReceipt(message_id=message_id, event_id=envelope.event_id)
