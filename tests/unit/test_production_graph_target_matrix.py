"""Local bindings for the specification 20 acceptance fixtures.

These tests exercise deterministic reconciliation semantics only. Provider API,
customer-cell, movement, purge, and authorization receipts remain target
qualification work.
"""

from __future__ import annotations

from datetime import UTC, datetime

from solvan.persistence.production_graph import (
    GraphNode,
    GraphSourcePlanEntry,
    GraphSourceResult,
    ProductionGraphReconciler,
    TraceDependencyAdapter,
    TraceDependencyObservation,
    diff_graphs,
)

SOURCE_HASH = "sha256:" + "a" * 64


def _plan() -> tuple[GraphSourcePlanEntry, ...]:
    return (GraphSourcePlanEntry("app_hub", 1, 1, True, SOURCE_HASH),)


def _node(
    key: str = "service:payments",
    *,
    owner: str | None = "payments",
    environment: str = "PRODUCTION",
    criticality: str = "HIGH",
    instrumentation: str = "INSTRUMENTED",
) -> GraphNode:
    return GraphNode(
        node_key=key,
        node_kind="SERVICE",
        resource_ref=f"//run/{key.rsplit(':', 1)[-1]}",
        external_project_id="acme-payments-prod",
        owner_team=owner,
        declared_environment=environment,
        business_criticality=criticality,
        data_classification="INTERNAL",
        authorization_boundary="payments-boundary",
        verification_profile="payments-recovery-v1",
        region="europe-west1",
        instrumentation_state=instrumentation,
        source_key="app_hub",
        source_revision=1,
    )


class _Adapter:
    def __init__(self, result: GraphSourceResult) -> None:
        self.result = result

    def fetch(self, *, source_key: str, source_revision: int) -> GraphSourceResult:
        assert (source_key, source_revision) == (
            self.result.source_key,
            self.result.source_revision,
        )
        return self.result


def test_it_pg_pagination_001_requires_exhausted_required_tier() -> None:
    result = GraphSourceResult(
        "app_hub",
        1,
        1,
        True,
        "PARTIAL",
        False,
        nodes=(_node(),),
        response_digest="sha256:" + "a" * 64,
    )
    draft = ProductionGraphReconciler().reconcile(
        snapshot_id="snap-pagination",
        source_plan=_plan(),
        adapter=_Adapter(result),
    )
    assert draft.completeness == "INCOMPLETE"
    assert draft.findings == ("SOURCE_INCOMPLETE:app_hub:1",)


def test_it_pg_material_hash_001_tracks_decision_relevant_attributes() -> None:
    adapter = _Adapter(
        GraphSourceResult(
            "app_hub",
            1,
            1,
            True,
            "COMPLETE",
            True,
            nodes=(_node(),),
            response_digest="sha256:" + "b" * 64,
        )
    )
    baseline = ProductionGraphReconciler().reconcile(
        snapshot_id="snap-material-1",
        source_plan=_plan(),
        adapter=adapter,
    )
    changed = baseline.__class__(
        snapshot_id="snap-material-2",
        material_hash="sha256:" + "c" * 64,
        content_hash="sha256:" + "d" * 64,
        completeness="COMPLETE",
        nodes=(_node(owner="platform", environment="STAGING", criticality="LOW"),),
        edges=(),
        findings=(),
    )
    diff = diff_graphs(baseline, changed)
    assert diff.owner_changes == 1
    assert diff.environment_changes == 1
    assert diff.criticality_changes == 1
    assert diff.governed_change_count >= 3


def test_sec_pg_observed_authority_001_trace_adapter_emits_only_observed_edges() -> None:
    result = TraceDependencyAdapter(
        (
            TraceDependencyObservation(
                "service:payments",
                "service:orders",
                datetime(2026, 8, 12, 9, tzinfo=UTC),
                "europe-west1",
            ),
        )
    ).fetch(source_key="trace", source_revision=1)
    assert result.edges[0].edge_kind == "DEPENDS_ON_OBSERVED"
    assert result.edges[0].source_key == "trace"


def test_it_pg_uninstrumented_001_is_a_finding_without_erasing_source_completeness() -> None:
    result = GraphSourceResult(
        "app_hub",
        1,
        1,
        True,
        "COMPLETE",
        True,
        nodes=(_node(instrumentation="UNINSTRUMENTED"),),
        response_digest="sha256:" + "e" * 64,
    )
    draft = ProductionGraphReconciler().reconcile(
        snapshot_id="snap-instrumentation",
        source_plan=_plan(),
        adapter=_Adapter(result),
    )
    assert draft.completeness == "COMPLETE"
    assert draft.findings == ("UNINSTRUMENTED_COMPONENT:service:payments",)


def test_it_pg_orphaned_resource_001_is_explicitly_unknown_owner() -> None:
    result = GraphSourceResult(
        "app_hub",
        1,
        1,
        True,
        "COMPLETE",
        True,
        nodes=(_node(owner=None),),
        response_digest="sha256:" + "f" * 64,
    )
    draft = ProductionGraphReconciler().reconcile(
        snapshot_id="snap-orphan",
        source_plan=_plan(),
        adapter=_Adapter(result),
    )
    assert draft.completeness == "COMPLETE"
    assert draft.findings == ("ORPHANED_RESOURCE:service:payments",)
