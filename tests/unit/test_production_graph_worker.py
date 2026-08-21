from __future__ import annotations

import json
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

import apps.coordinator.production_graph as worker_module
from apps.coordinator.production_graph import ProductionGraphWorker
from solvan.application.production_graph_types import (
    GraphNode,
    GraphSourcePlanEntry,
    GraphSourceResult,
)
from solvan.domain import Scope
from solvan.persistence.production_graph import GraphPlacement, GraphRun
from solvan.platform.production_graph_sources import (
    GraphSourceConfigurationError,
    GraphSourceRegistry,
    GraphSourceUnavailable,
    configured_graph_sources,
)

HASH = "sha256:" + "a" * 64
SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)


class _Connection:
    def transaction(self) -> AbstractContextManager[None]:
        return nullcontext()


class _Adapter:
    def __init__(self, result: GraphSourceResult | Exception) -> None:
        self.result = result
        self.calls = 0

    def fetch(self, *, source_key: str, source_revision: int) -> GraphSourceResult:
        self.calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@dataclass
class _Repository:
    stale: bool = False

    def __post_init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.result: GraphSourceResult | None = None
        self.run = GraphRun(
            "request-0001",
            "cell-eu",
            3,
            "RUNNING",
            "00000000-0000-0000-0000-000000000001",
            datetime.now(UTC) + timedelta(minutes=10),
        )

    def get_run_identity(self, **_: Any) -> GraphRun:
        return GraphRun("request-0001", "cell-eu", 3, "PENDING")

    def run_source_plan(self, **_: Any) -> tuple[GraphSourcePlanEntry, ...]:
        return (GraphSourcePlanEntry("app_hub", 1, 1, True, HASH),)

    def current_placement(self, **_: Any) -> GraphPlacement:
        return GraphPlacement("cell-eu", 3, "europe-west1", "INTERNAL")

    def claim_run(self, **_: Any) -> GraphRun:
        self.calls.append(("claim", None))
        return self.run

    def lock_run_lease(self, **_: Any) -> None:
        self.calls.append(("lock", None))
        if self.stale:
            raise RuntimeError("stale")

    def current_approved_draft(self, **_: Any) -> None:
        return None

    def next_snapshot_version(self, **_: Any) -> int:
        return 1

    def create_draft(self, **values: Any) -> None:
        self.calls.append(("draft", values["snapshot_id"]))

    def record_observation(self, **values: Any) -> None:
        self.result = values["result"]
        self.calls.append(("observation", values["observation_id"]))

    def record_elements(self, **_: Any) -> None:
        self.calls.append(("elements", None))

    def record_tier_status(self, **values: Any) -> None:
        self.calls.append(("tier", (values["tier"], values["outcome"])))

    def record_diff(self, **_: Any) -> None:
        self.calls.append(("diff", None))

    def record_finding(self, **values: Any) -> None:
        self.calls.append(("finding", values["finding_kind"]))

    def finalize(self, **_: Any) -> None:
        self.calls.append(("finalize", None))

    def finish_run(self, **values: Any) -> None:
        self.calls.append(("finish", values["state"]))


def _complete() -> GraphSourceResult:
    node = GraphNode(
        node_key="service://run.googleapis.com/projects/acme-prod/locations/europe-west1/services/payments",
        node_kind="SERVICE",
        resource_ref="//run.googleapis.com/projects/acme-prod/locations/europe-west1/services/payments",
        external_project_id="acme-prod",
        owner_team="payments",
        declared_environment="prod",
        business_criticality="HIGH",
        data_classification="INTERNAL",
        authorization_boundary="payments",
        verification_profile="payments-v1",
        region="europe-west1",
        instrumentation_state="INSTRUMENTED",
        source_key="app_hub",
        source_revision=1,
    )
    return GraphSourceResult(
        "app_hub",
        1,
        1,
        True,
        "COMPLETE",
        True,
        nodes=(node,),
        response_digest=HASH,
    )


def test_worker_reads_once_then_commits_one_fenced_complete_draft(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _Repository()
    adapter = _Adapter(_complete())
    monkeypatch.setattr(worker_module, "ProductionGraphRepository", lambda _: repository)

    receipt = ProductionGraphWorker(
        registry=GraphSourceRegistry({"app_hub": adapter}),
        owner="coordinator:test",
    ).execute(_Connection(), scope=SCOPE, run_id="request-0001")  # type: ignore[arg-type]

    assert adapter.calls == 1
    assert receipt.state == "COMPLETED"
    assert receipt.completeness == "COMPLETE"
    names = [name for name, _ in repository.calls]
    assert names.index("lock") < names.index("draft") < names.index("finalize")
    assert repository.calls[-1] == ("finish", "COMPLETED")


def test_unavailable_source_is_not_misreported_as_empty_or_complete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _Repository()
    adapter = _Adapter(GraphSourceUnavailable("provider details must not persist"))
    monkeypatch.setattr(worker_module, "ProductionGraphRepository", lambda _: repository)

    receipt = ProductionGraphWorker(
        registry=GraphSourceRegistry({"app_hub": adapter}),
        owner="coordinator:test",
    ).execute(_Connection(), scope=SCOPE, run_id="request-0001")  # type: ignore[arg-type]

    assert receipt.state == "DEGRADED"
    assert repository.result is not None
    assert repository.result.outcome == "UNAVAILABLE"
    assert repository.result.nodes == ()
    assert repository.result.page_count == 0
    assert "provider details" not in repository.result.response_digest
    assert ("finding", "SOURCE_INCOMPLETE") in repository.calls


def test_stale_worker_writes_no_observation_or_draft(monkeypatch: pytest.MonkeyPatch) -> None:
    repository = _Repository(stale=True)
    adapter = _Adapter(_complete())
    monkeypatch.setattr(worker_module, "ProductionGraphRepository", lambda _: repository)

    with pytest.raises(RuntimeError, match="stale"):
        ProductionGraphWorker(
            registry=GraphSourceRegistry({"app_hub": adapter}),
            owner="coordinator:test",
        ).execute(_Connection(), scope=SCOPE, run_id="request-0001")  # type: ignore[arg-type]

    names = [name for name, _ in repository.calls]
    assert names.count("lock") == 2
    assert "draft" not in names
    assert "observation" not in names
    assert "finish" not in names


def test_deployment_source_configuration_refuses_invalid_or_empty_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SOLVAN_PRODUCTION_GRAPH_SOURCES_JSON", raising=False)
    assert configured_graph_sources(SCOPE) is None
    monkeypatch.setenv("SOLVAN_PRODUCTION_GRAPH_SOURCES_JSON", "[]")
    with pytest.raises(GraphSourceConfigurationError, match="must be an object"):
        configured_graph_sources(SCOPE)
    monkeypatch.setenv("SOLVAN_PRODUCTION_GRAPH_SOURCES_JSON", "not-json")
    with pytest.raises(GraphSourceConfigurationError, match="invalid"):
        configured_graph_sources(SCOPE)


def test_deployment_source_configuration_is_bound_to_exact_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources = {
        "asset_inventory": {
            "kind": "ASSET_INVENTORY",
            "search_scope": "projects/customer-project",
        }
    }
    envelope = {
        "schema_version": 1,
        "scope": SCOPE.canonical_dict(),
        "sources": sources,
    }
    monkeypatch.setenv("SOLVAN_PRODUCTION_GRAPH_SOURCES_JSON", json.dumps(envelope))
    assert configured_graph_sources(SCOPE) == sources

    other = Scope(
        "org_00000000000000000000000009",
        "prj_00000000000000000000000009",
        "env_00000000000000000000000009",
    )
    with pytest.raises(GraphSourceConfigurationError, match="active scope"):
        configured_graph_sources(other)


def test_deployment_source_configuration_refuses_unknown_outer_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = {
        "schema_version": 1,
        "scope": SCOPE.canonical_dict(),
        "sources": {"asset": {"kind": "ASSET_INVENTORY", "search_scope": "projects/p"}},
        "credential": "must-not-be-accepted",
    }
    monkeypatch.setenv("SOLVAN_PRODUCTION_GRAPH_SOURCES_JSON", json.dumps(envelope))
    with pytest.raises(GraphSourceConfigurationError, match="unknown or missing"):
        configured_graph_sources(SCOPE)
