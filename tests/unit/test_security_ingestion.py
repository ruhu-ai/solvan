from __future__ import annotations

import base64
import json

import pytest

from apps.coordinator.contracts import PubSubMessage, PubSubPush
from apps.coordinator.security_ingestion import decode_security_log


def push(value: object) -> PubSubPush:
    data = base64.b64encode(json.dumps(value).encode()).decode()
    return PubSubPush(
        message=PubSubMessage(data=data, messageId="message-1"),
        subscription="security",
    )


def test_policy_denial_becomes_safe_hashed_security_event() -> None:
    event = decode_security_log(
        push(
            {
                "logName": "projects/demo/logs/cloudaudit.googleapis.com%2Fpolicy",
                "timestamp": "2026-08-08T12:00:00Z",
                "trace": "projects/demo/traces/0123456789abcdef0123456789abcdef",
                "protoPayload": {
                    "serviceName": "iap.googleapis.com",
                    "methodName": "AuthorizeAgentEgress",
                    "resourceName": "projects/demo/locations/europe-west1/services/actuator",
                    "status": {"code": 7, "message": "raw secret-like detail"},
                    "authenticationInfo": {"principalEmail": "agent@example.iam"},
                    "authorizationInfo": [{"permission": "iap.webServiceVersions.accessViaIAP"}],
                },
            }
        )
    )
    assert event.event_type == "AGENT_GATEWAY_IAP_DENIED"
    assert event.control == "AGENT_GATEWAY"
    assert event.severity == "HIGH"
    assert event.payload_hash.startswith("sha256:")
    assert "raw secret-like detail" not in event.safe_summary
    assert event.trace_id == "0123456789abcdef0123456789abcdef"


def test_model_armor_audit_operation_is_metadata_only() -> None:
    event = decode_security_log(
        push(
            {
                "timestamp": "2026-08-08T12:00:00Z",
                "protoPayload": {
                    "serviceName": "modelarmor.googleapis.com",
                    "methodName": "google.cloud.modelarmor.v1.ModelArmor.SanitizeUserPrompt",
                    "status": {},
                },
            }
        )
    )
    assert event.control == "MODEL_ARMOR"
    assert event.event_type == "MODEL_ARMOR_SANITIZE_OBSERVED"
    assert event.severity == "INFO"


def test_unrelated_log_entry_fails_closed() -> None:
    with pytest.raises(ValueError, match="outside the approved security controls"):
        decode_security_log(push({"timestamp": "2026-08-08T12:00:00Z"}))
