from pathlib import Path

import yaml

from apps.api.liaison import _CLIENT_EVENT_BUFFER_CEILING

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "specs" / "artifacts" / "liaison-errors.yaml"


def test_liaison_error_registry_is_closed_and_overflow_is_transport_only() -> None:
    value = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
    assert set(value) == {"schema_version", "status", "codes", "constants"}
    assert value["schema_version"] == 1
    assert value["status"] == "target"
    expected = {
        "REVISION_CONFLICT",
        "INVALID_REQUEST",
        "TEMPORARILY_UNAVAILABLE",
        "NOT_FOUND_OR_FORBIDDEN",
        "THREAD_ARCHIVED",
        "CURSOR_POLICY_CHANGED",
        "CURSOR_HISTORY_EXPIRED",
        "EVENT_BUFFER_OVERFLOW",
        "MANIFEST_INVALID",
        "PARKED_REQUEST_EXPIRED",
        "PARKED_REQUEST_ALREADY_DECIDED",
        "CHANNEL_BINDING_REVOKED",
        "RETENTION_PURGED",
        "DELEGATION_DENIED",
    }
    assert set(value["codes"]) == expected
    assert all(
        set(contract) == {"http_status", "retryable", "audit_class", "workflow_effect"}
        for contract in value["codes"].values()
    )
    assert value["codes"]["EVENT_BUFFER_OVERFLOW"] == {
        "http_status": 409,
        "retryable": True,
        "audit_class": "transport",
        "workflow_effect": "none",
    }
    assert value["constants"] == {"CLIENT_EVENT_BUFFER_CEILING": 2048}
    assert value["constants"]["CLIENT_EVENT_BUFFER_CEILING"] == _CLIENT_EVENT_BUFFER_CEILING
