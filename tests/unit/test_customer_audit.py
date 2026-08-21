from __future__ import annotations

import json

import httpx
import pytest

from solvan.application.actuator import CustomerAuditRecord
from solvan.domain import freeze_json
from solvan.platform.customer_audit import (
    CloudLoggingCustomerAuditSink,
    CustomerAuditUnavailable,
)


class TokenProvider:
    def token(self, *, scopes: tuple[str, ...]) -> str:
        assert scopes == ("https://www.googleapis.com/auth/logging.write",)
        return "audit-token"


def _record() -> CustomerAuditRecord:
    return CustomerAuditRecord(
        "dsp_00000000000000000000000000",
        "act_00000000000000000000000000",
        freeze_json({"result": "SUCCEEDED", "schema_version": 1}),
    )


def test_customer_audit_uses_stable_insert_id_and_content_hash() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        sink = CloudLoggingCustomerAuditSink(token_provider=TokenProvider(), client=client)
        first = sink.write(sink_ref="projects/solvan-test/logs/solvan-audit", record=_record())
        second = sink.write(sink_ref="projects/solvan-test/logs/solvan-audit", record=_record())

    assert first == second
    assert len(requests) == 2
    assert all(request.headers["authorization"] == "Bearer audit-token" for request in requests)
    payloads = [json.loads(request.content) for request in requests]
    assert payloads[0] == payloads[1]
    entry = payloads[0]["entries"][0]
    assert entry["insertId"] == _record().dispatch_id
    assert entry["jsonPayload"]["content_hash"] == _record().content_hash


def test_customer_audit_refusal_is_safe_and_content_free() -> None:
    with httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(503, text="secret"))
    ) as client:
        sink = CloudLoggingCustomerAuditSink(token_provider=TokenProvider(), client=client)
        with pytest.raises(CustomerAuditUnavailable, match="not acknowledged") as caught:
            sink.write(sink_ref="projects/solvan-test/logs/solvan-audit", record=_record())
    assert "secret" not in str(caught.value)


def test_customer_audit_rejects_untrusted_sink_reference_before_token_use() -> None:
    with httpx.Client() as client:
        sink = CloudLoggingCustomerAuditSink(token_provider=TokenProvider(), client=client)
        with pytest.raises(CustomerAuditUnavailable, match="reference is invalid"):
            sink.write(sink_ref="https://attacker.invalid/log", record=_record())
