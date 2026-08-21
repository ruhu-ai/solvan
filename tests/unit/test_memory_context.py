from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

import pytest

from apps.coordinator.contracts import CoordinatorSettings
from apps.coordinator.memory_context import EvidenceMemoryContextEnricher
from solvan.application import (
    MemoryBankUnavailable,
    MemoryHint,
    MemorySearchQuery,
    RuntimeDispatch,
)
from solvan.domain import MemoryScope, Scope, StepBudget

SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)


def dispatch() -> RuntimeDispatch:
    return RuntimeDispatch(
        "run-test",
        "inv-test",
        SCOPE,
        "incident-test",
        "plan-test",
        1,
        "step-test",
        "collect",
        "incident:test:collect",
        "evidence-agent",
        "projects/test/locations/europe-west1/reasoningEngines/evidence",
        "evidence-v1",
        "scope:primary-service",
        "inspect telemetry",
        ("cloud_monitoring_query",),
        1,
        datetime(2026, 8, 11, 13, tzinfo=UTC),
        StepBudget(60_000, 2, 2_000),
        "db://step",
        "sha256:input",
        "0" * 32,
        "0" * 16,
        {"incident_class": "connection_exhaustion", "service_key": "payments"},
    )


class SearchService:
    def __init__(self) -> None:
        self.query: MemorySearchQuery | None = None

    def search(self, *, query: MemorySearchQuery) -> tuple[MemoryHint, ...]:
        self.query = query
        return (
            MemoryHint(
                "projects/test/locations/europe-west1/reasoningEngines/memory/memories/1",
                "Prior verified connection-pool exhaustion pattern.",
                query.exact_scope,
                "revision-1",
                0.1,
                ("hyp_00000000000000000000000000",),
            ),
        )


def settings() -> CoordinatorSettings:
    value = SimpleNamespace(
        gcp_region="europe-west1",
        binding_for=lambda key: SimpleNamespace(data_classification="INTERNAL"),
    )
    return cast(CoordinatorSettings, value)


def test_evidence_memory_context_is_exact_scoped_reference_only() -> None:
    service = SearchService()
    enricher = EvidenceMemoryContextEnricher(
        settings=settings(), connection=cast(Any, None), service=cast(Any, service)
    )
    result = enricher.enrich(dispatch())["memory_recall"]
    assert result["authority"] == "REFERENCE_ONLY_UNTRUSTED_HISTORICAL_CONTEXT"
    assert (
        result["exact_scope"]
        == MemoryScope(SCOPE, "incident-patterns", "INTERNAL", "europe-west1").canonical_dict()
    )
    assert result["hints"][0]["source_refs"] == ["hyp_00000000000000000000000000"]
    assert service.query is not None
    assert service.query.read_grant.audience == "evidence-agent"


def test_non_evidence_agent_and_already_enriched_dispatch_do_not_search() -> None:
    service = SearchService()
    enricher = EvidenceMemoryContextEnricher(
        settings=settings(), connection=cast(Any, None), service=cast(Any, service)
    )
    assert enricher.enrich(replace(dispatch(), agent_key="infrastructure-agent")) == {}
    assert enricher.enrich(replace(dispatch(), context={"memory_recall": {}})) == {}
    assert service.query is None


def test_memory_client_initialization_outage_degrades_to_no_hints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> None:
        raise MemoryBankUnavailable("fixture client outage")

    monkeypatch.setattr(EvidenceMemoryContextEnricher, "_service_for", unavailable)
    enricher = EvidenceMemoryContextEnricher(
        settings=settings(),
        connection=cast(Any, None),
    )
    recall = enricher.enrich(dispatch())["memory_recall"]
    assert recall["hints"] == []
