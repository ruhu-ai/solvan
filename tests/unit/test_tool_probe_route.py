"""The Tool probe path refuses rather than inventing the facts it lacks.

A capability receipt is the only thing standing between a governed Tool and an
Agent that may call it, and the console's freshness check does not re-verify the
identity on that receipt. A receipt written with an unattested identity would
therefore render the Tool `Available` while `resolve_and_bind_run` still refused
to bind it — the console asserting a capability the coordinator denies.

These cover the refusals that make that impossible.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from apps.api.tool_probe import (
    ToolProbeRequest,
    _attested_gateway_policy,
    _attested_identity,
    probe_tool_capability_revision,
)
from solvan.domain import Scope

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
_REQUEST = ToolProbeRequest(
    schema_version=1,
    tool_key="cloud_monitoring_query",
    tool_version="1",
    agent_key="evidence-agent",
    connection_id="con_01J0000000000000000000000A",
)


def _clear(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    for name in names:
        monkeypatch.delenv(name, raising=False)


def test_an_undeployed_fleet_has_no_identity_a_receipt_could_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear(monkeypatch, "SOLVAN_AGENT_TOOL_BINDINGS_JSON", "SOLVAN_EVIDENCE_AGENT_RESOURCE")
    with pytest.raises(HTTPException) as raised:
        _attested_identity("evidence-agent")
    assert raised.value.status_code == 503
    assert "attested Agent Identity" in str(raised.value.detail)


def test_a_placeholder_runtime_resource_is_not_an_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "SOLVAN_INCIDENT_SUPERVISOR_RESOURCE",
        "SOLVAN_EVIDENCE_AGENT_RESOURCE",
        "SOLVAN_INFRASTRUCTURE_AGENT_RESOURCE",
        "SOLVAN_EXECUTION_AGENT_RESOURCE",
        "SOLVAN_VERIFICATION_AGENT_RESOURCE",
        "SOLVAN_WORKSPACE_AGENT_RESOURCE",
    ):
        monkeypatch.setenv(name, "UNCONFIGURED")
    monkeypatch.setenv("SOLVAN_AGENT_TOOL_BINDINGS_JSON", "{}")
    with pytest.raises(HTTPException) as raised:
        _attested_identity("evidence-agent")
    assert raised.value.status_code == 503


def test_an_absent_gateway_policy_refuses_rather_than_deriving_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear(monkeypatch, "SOLVAN_GATEWAY_POLICY_REFS_JSON")
    with pytest.raises(HTTPException) as raised:
        _attested_gateway_policy("monitoring.googleapis.com")
    assert raised.value.status_code == 503


def test_an_unparsable_gateway_policy_map_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOLVAN_GATEWAY_POLICY_REFS_JSON", "{not json")
    with pytest.raises(HTTPException) as raised:
        _attested_gateway_policy("monitoring.googleapis.com")
    assert raised.value.status_code == 503


def test_a_destination_absent_from_the_policy_map_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SOLVAN_GATEWAY_POLICY_REFS_JSON", '{"logging.googleapis.com": "gateway://policy/7"}'
    )
    with pytest.raises(HTTPException) as raised:
        _attested_gateway_policy("monitoring.googleapis.com")
    assert raised.value.status_code == 422


def test_an_attested_destination_returns_its_provisioned_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SOLVAN_GATEWAY_POLICY_REFS_JSON", '{"monitoring.googleapis.com": "gateway://policy/7"}'
    )
    assert _attested_gateway_policy("monitoring.googleapis.com") == "gateway://policy/7"


def test_the_route_refuses_before_reaching_the_database_or_the_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Identity is resolved first, so an undeployed fleet costs no read.

    Ordering is the assertion: the customer's project is never contacted, and no
    connection is loaded, for a probe whose result could not be committed.
    """

    monkeypatch.setenv("SOLVAN_DIRECT_GCP_READER_URL", "https://reader.invalid")
    _clear(monkeypatch, "SOLVAN_AGENT_TOOL_BINDINGS_JSON", "SOLVAN_EVIDENCE_AGENT_RESOURCE")

    def _forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("the probe path must not touch the database or the reader")

    monkeypatch.setattr("apps.api.tool_probe.connect_database", _forbidden)
    monkeypatch.setattr("apps.api.tool_probe.httpx.post", _forbidden)
    with pytest.raises(HTTPException) as raised:
        probe_tool_capability_revision(scope=SCOPE, request=_REQUEST)
    assert raised.value.status_code == 503


def test_an_unconfigured_reader_url_refuses_before_anything_else(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear(monkeypatch, "SOLVAN_DIRECT_GCP_READER_URL")
    with pytest.raises(HTTPException) as raised:
        probe_tool_capability_revision(scope=SCOPE, request=_REQUEST)
    assert raised.value.status_code == 503
    assert "reader is not configured" in str(raised.value.detail)


def test_a_plaintext_reader_url_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOLVAN_DIRECT_GCP_READER_URL", "http://reader.internal")
    with pytest.raises(HTTPException) as raised:
        probe_tool_capability_revision(scope=SCOPE, request=_REQUEST)
    assert raised.value.status_code == 503
