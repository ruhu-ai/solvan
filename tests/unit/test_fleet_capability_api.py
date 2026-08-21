"""The capability read API returns decisions, and says only what it can support.

`/api/fleet/agents/{key}/effective-tools` filtered the Tool catalog by the set of
revisions naming the Agent as an allowed requester. That is the declared set, not
the reachable one — the catalog names nine Tools for the Infrastructure Agent and
an approved profile offers it four — so an endpoint whose name asserts
effectiveness returned more than twice the capabilities the coordinator would
resolve.

These exercise the router directly through its injected providers, so they cover
the contract without a database or a scripted console fixture behind them.

Governing records: specification 16 §10, specification 06 §Capabilities & Policy,
PR-031, PR-032.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.fleet_operability import fleet_operability_router


def _decision(
    *,
    agent_key: str,
    tool_key: str,
    verdict: str,
    winning_layer: str = "GATEWAY_ROUTE",
) -> dict[str, Any]:
    return {
        "agent_key": agent_key,
        "agent": agent_key.replace("-", " ").title(),
        "tool_key": tool_key,
        "version": "1",
        "tool": tool_key.replace("_", " ").title(),
        "destination": f"{tool_key}.example.internal",
        "registry_resource": f"registry://solvan/tools/{tool_key}@1",
        "permission_class": "READ",
        "verdict": verdict,
        "winning_layer": winning_layer,
        "winning_reference": "profile://test@1",
        "layers": [],
    }


def _snapshot() -> dict[str, Any]:
    return {
        "fleet": {
            "agents": [
                {"key": "evidence-agent", "name": "Evidence Agent"},
                {"key": "workspace-agent", "name": "Workspace Agent"},
            ],
            "capabilities": [
                _decision(agent_key="evidence-agent", tool_key="allowed_read", verdict="ALLOWED"),
                _decision(
                    agent_key="evidence-agent",
                    tool_key="unprofiled_read",
                    verdict="NOT_REGISTERED",
                    winning_layer="PROFILE_MEMBERSHIP",
                ),
                _decision(
                    agent_key="evidence-agent", tool_key="unrouted_read", verdict="NOT_EVALUATED"
                ),
                _decision(
                    agent_key="infrastructure-agent", tool_key="other_read", verdict="ALLOWED"
                ),
            ],
        }
    }


class _UnusedConnection:
    """A session lookup must never happen on these cookie-less requests."""

    def __enter__(self) -> _UnusedConnection:
        raise AssertionError("a request offering no session must not open a connection")

    def __exit__(self, *_args: object) -> None:
        return None


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(
        fleet_operability_router(
            snapshot_provider=_snapshot,
            principal_provider=lambda _token: "user:reader@example.com",
            connect=_UnusedConnection,
        )
    )
    return TestClient(app)


def test_effective_tools_holds_only_capabilities_that_resolve_to_allowed(
    client: TestClient,
) -> None:
    response = client.get("/api/fleet/agents/evidence-agent/effective-tools")
    assert response.status_code == 200
    body = response.json()
    assert [item["tool_key"] for item in body["effective_tools"]] == ["allowed_read"]


def test_a_withheld_capability_is_returned_with_the_authority_that_withheld_it(
    client: TestClient,
) -> None:
    """Dropping them would answer "what can this Agent reach" by omission.

    An operator asking why a capability is missing needs the refusing layer, not
    a shorter list.
    """

    body = client.get("/api/fleet/agents/evidence-agent/effective-tools").json()
    withheld = {item["tool_key"]: item["winning_layer"] for item in body["capabilities"]}
    assert withheld["unprofiled_read"] == "PROFILE_MEMBERSHIP"
    assert withheld["unrouted_read"] == "GATEWAY_ROUTE"


def test_one_agent_never_sees_another_agents_capabilities(client: TestClient) -> None:
    body = client.get("/api/fleet/agents/evidence-agent/effective-tools").json()
    assert all(item["agent_key"] == "evidence-agent" for item in body["capabilities"])


def test_a_registered_agent_with_no_capability_is_not_a_missing_agent(
    client: TestClient,
) -> None:
    """Empty and absent are different answers.

    The Workspace Agent is registered and holds no capability in this scope. That
    is an empty result, not a lookup failure, and reporting 404 would tell an
    operator the Agent does not exist.
    """

    response = client.get("/api/fleet/agents/workspace-agent/effective-tools")
    assert response.status_code == 200
    assert response.json()["capabilities"] == []


def test_an_unregistered_agent_is_refused_rather_than_answered_empty(
    client: TestClient,
) -> None:
    assert client.get("/api/fleet/agents/not-an-agent/effective-tools").status_code == 404


def test_the_capability_route_returns_every_decision_with_its_provenance(
    client: TestClient,
) -> None:
    response = client.get("/api/fleet/capabilities")
    assert response.status_code == 200
    body = response.json()
    assert len(body["capabilities"]) == 4
    assert all(item["winning_layer"] for item in body["capabilities"])


@pytest.mark.parametrize(
    "path",
    ["/api/fleet/capabilities", "/api/fleet/agents/evidence-agent/effective-tools"],
)
def test_capability_reads_are_private_and_state_that_discovery_is_not_authorization(
    client: TestClient, path: str
) -> None:
    """Reading the catalog resolves nothing, and neither response may be cached."""

    response = client.get(path)
    assert response.headers["cache-control"] == "private, no-store"
    assert response.json()["notice"] == (
        "Discovery is not authorization; a run must bind an exact profile."
    )


def test_a_projection_without_capabilities_answers_empty_rather_than_failing(
    client: TestClient,
) -> None:
    """A console version that predates the decision must not 500 this route."""

    app = FastAPI()
    app.include_router(
        fleet_operability_router(
            snapshot_provider=lambda: {"fleet": {"agents": [], "tools": []}},
            principal_provider=lambda _token: "user:reader@example.com",
            connect=_UnusedConnection,
        )
    )
    with TestClient(app) as bare:
        assert bare.get("/api/fleet/capabilities").json()["capabilities"] == []
