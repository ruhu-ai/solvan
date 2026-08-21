from __future__ import annotations

from datetime import UTC, datetime

import pytest

from solvan.domain import Scope
from solvan.persistence.production_graph import (
    GraphDiff,
    GraphEdge,
    GraphNode,
    GraphSourcePlanEntry,
    GraphSourceResult,
    ProductionGraphReconciler,
    ProductionGraphRepository,
    TraceDependencyAdapter,
    TraceDependencyObservation,
    read_current_graph,
)


class _Result:
    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row

    def fetchall(self):
        return self._row or []


class _Connection:
    def __init__(self, row):
        self.row = row
        self.calls = []

    def execute(self, statement, params):
        self.calls.append((statement, params))
        return _Result(self.row)


class _ReviewConnection:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self._results = [
            (
                "snap-2",
                2,
                "DRAFT",
                "COMPLETE",
                "sha256:" + "a" * 64,
                "sha256:" + "b" * 64,
                False,
                datetime(2026, 8, 12, 9, 0, tzinfo=UTC),
                "cell-1",
                2,
            ),
            ("snap-1", "sha256:" + "a" * 64),
            ("sha256:" + "c" * 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "snap-1"),
            [(1, True, "COMPLETE", 1), (2, True, "COMPLETE", 1)],
            [
                (
                    "finding-1",
                    "UNINSTRUMENTED_COMPONENT",
                    "service:payments",
                    None,
                    "ref_finding",
                    "OPEN",
                )
            ],
            [],
        ]

    def execute(self, statement, params):
        self.calls.append((statement, params))
        return _Result(self._results.pop(0))


def test_graph_repository_uses_function_only_authority_boundaries() -> None:
    connection = _Connection(None)
    repository = ProductionGraphRepository(connection)  # type: ignore[arg-type]
    scope = Scope(
        "org_00000000000000000000000000",
        "prj_00000000000000000000000000",
        "env_00000000000000000000000000",
    )
    result = GraphSourceResult(
        source_key="apphub",
        source_revision=1,
        tier=1,
        required_for_complete=True,
        outcome="COMPLETE",
        pagination_complete=True,
        response_digest="sha256:" + "a" * 64,
    )

    repository.start_run(
        scope=scope,
        cell_id="cell-1",
        placement_epoch=2,
        run_id="run-1",
        source_plan=(GraphSourcePlanEntry("apphub", 1, 1, True, "sha256:" + "b" * 64),),
        requested_by="coordinator",
    )
    repository.record_observation(
        scope=scope,
        cell_id="cell-1",
        placement_epoch=2,
        run_id="run-1",
        observation_id="obs-1",
        result=result,
        tool_invocation_ref="tool-1",
        page_count=1,
        element_count=0,
        region="europe-west1",
    )
    repository.finalize(scope=scope, cell_id="cell-1", placement_epoch=2, snapshot_id="snap-1")
    repository.promote(
        scope=scope,
        cell_id="cell-1",
        placement_epoch=2,
        snapshot_id="snap-1",
        decision_id="decision-1",
        mode="HUMAN_APPROVED",
        principal="operator",
    )

    statements = [statement for statement, _ in connection.calls]
    assert "INSERT INTO solvan_graph.graph_reconciliation_runs" in statements[0]
    assert "graph_reconciliation_run_sources" in statements[1]
    assert "graph_finalize_snapshot" in statements[3]
    assert "graph_promote_snapshot" in statements[4]


def test_graph_review_material_is_scope_bound_and_hash_complete() -> None:
    connection = _ReviewConnection()
    repository = ProductionGraphRepository(connection)  # type: ignore[arg-type]
    scope = Scope(
        "org_00000000000000000000000000",
        "prj_00000000000000000000000000",
        "env_00000000000000000000000000",
    )

    material = repository.review_material(scope=scope, snapshot_id="snap-2")

    assert material is not None
    assert material.status == "DRAFT"
    assert material.content_hash == "sha256:" + "b" * 64
    assert material.predecessor_snapshot_id == "snap-1"
    assert material.governed_change_count == 0
    assert material.previous is not None
    assert material.previous.snapshot_id == "snap-1"
    assert material.tier_status[0]["outcome"] == "COMPLETE"
    assert material.findings[0]["detail_ref"] == "ref_finding"
    assert all(
        params.get("organization_id") == scope.organization_id
        and params.get("project_id") == scope.project_id
        and params.get("environment_id") == scope.environment_id
        for _, params in connection.calls
    )


def test_graph_review_material_returns_none_for_unknown_snapshot() -> None:
    connection = _ReviewConnection()
    connection._results[0] = None
    repository = ProductionGraphRepository(connection)  # type: ignore[arg-type]
    scope = Scope(
        "org_00000000000000000000000000",
        "prj_00000000000000000000000000",
        "env_00000000000000000000000000",
    )

    assert repository.review_material(scope=scope, snapshot_id="missing") is None


def test_current_graph_uses_derived_age_projection() -> None:
    reconciled_at = datetime(2026, 8, 12, 9, 0, tzinfo=UTC)
    connection = _Connection(
        ("pgs_1", 4, reconciled_at, 90, "COMPLETE", True, True, "cell_eu", 7, 3)
    )
    scope = Scope(
        "org_00000000000000000000000000",
        "prj_00000000000000000000000000",
        "env_00000000000000000000000000",
    )

    projection = read_current_graph(connection, scope=scope)  # type: ignore[arg-type]

    assert projection is not None
    assert projection.age_seconds == 90
    assert projection.autonomy_eligible
    assert projection.graph_policy_binding_epoch == 3
    assert "graph_read_current" in connection.calls[0][0]


def test_graph_repository_persists_tier_elements_diff_and_typed_finding() -> None:
    connection = _Connection(None)
    repository = ProductionGraphRepository(connection)  # type: ignore[arg-type]
    scope = Scope(
        "org_00000000000000000000000000",
        "prj_00000000000000000000000000",
        "env_00000000000000000000000000",
    )
    node = GraphNode(
        node_key="service:payments",
        node_kind="SERVICE",
        resource_ref="//run/payments",
        external_project_id="acme-payments-prod",
        owner_team="payments",
        declared_environment="prod",
        business_criticality="HIGH",
        data_classification="INTERNAL",
        authorization_boundary="payments",
        verification_profile="payments-recovery-v1",
        region="europe-west1",
        instrumentation_state="INSTRUMENTED",
        source_key="apphub",
        source_revision=1,
    )
    edge = GraphEdge(
        edge_key="payments->orders",
        from_node_key=node.node_key,
        to_node_key="service:orders",
        edge_kind="DEPENDS_ON_DECLARED",
        source_key="apphub",
        source_revision=1,
    )
    with pytest.raises(ValueError, match="same draft"):
        repository.record_elements(
            scope=scope,
            cell_id="cell-1",
            placement_epoch=2,
            snapshot_id="snap-1",
            nodes=(node,),
            edges=(edge,),
            observation_ids={("apphub", 1): "obs-1"},
        )
    repository.record_elements(
        scope=scope,
        cell_id="cell-1",
        placement_epoch=2,
        snapshot_id="snap-1",
        nodes=(node,),
        edges=(),
        observation_ids={("apphub", 1): "obs-1"},
    )
    repository.record_tier_status(
        scope=scope,
        cell_id="cell-1",
        placement_epoch=2,
        snapshot_id="snap-1",
        tier=1,
        required_for_complete=True,
        outcome="COMPLETE",
        observation_count=1,
    )
    repository.record_diff(
        scope=scope,
        cell_id="cell-1",
        placement_epoch=2,
        diff_id="diff-1",
        base_snapshot_id=None,
        candidate_snapshot_id="snap-1",
        diff=GraphDiff(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
    )
    repository.record_finding(
        scope=scope,
        cell_id="cell-1",
        placement_epoch=2,
        snapshot_id="snap-1",
        finding_id="finding-1",
        finding_kind="UNINSTRUMENTED_COMPONENT",
        detail_ref="ref_graph-detail",
        subject_node_key=node.node_key,
    )
    statements = [statement for statement, _ in connection.calls]
    assert any("graph_snapshot_tier_status" in statement for statement in statements)
    assert any("graph_nodes" in statement for statement in statements)
    assert any("graph_snapshot_diffs" in statement for statement in statements)
    assert any("graph_findings" in statement for statement in statements)


def test_graph_run_lease_is_claimed_and_terminalized_with_exact_token() -> None:
    connection = _Connection(("00000000-0000-0000-0000-000000000001", datetime.now(UTC)))
    repository = ProductionGraphRepository(connection)  # type: ignore[arg-type]
    scope = Scope(
        "org_00000000000000000000000000",
        "prj_00000000000000000000000000",
        "env_00000000000000000000000000",
    )
    claimed = repository.claim_run(
        scope=scope,
        cell_id="cell-1",
        placement_epoch=2,
        run_id="run-1",
        lease_owner="graph-coordinator",
    )
    assert claimed.state == "RUNNING"
    assert claimed.lease_token is not None
    repository.finish_run(
        scope=scope,
        cell_id="cell-1",
        placement_epoch=2,
        run_id="run-1",
        lease_token=claimed.lease_token,
        state="COMPLETED",
    )
    assert "lease_token=%(lease_token)s::uuid" in connection.calls[-1][0]


def test_trace_adapter_emits_only_non_authoritative_observed_edges() -> None:
    adapter = TraceDependencyAdapter(
        (
            TraceDependencyObservation(
                from_node_key="service:payments",
                to_node_key="service:orders",
                observed_at=datetime(2026, 8, 12, 9, 0, tzinfo=UTC),
                region="europe-west1",
            ),
        )
    )

    result = adapter.fetch(source_key="trace", source_revision=1)

    assert result.tier == 4
    assert not result.required_for_complete
    assert result.edges[0].edge_kind == "DEPENDS_ON_OBSERVED"
    assert result.response_digest.startswith("sha256:")


def test_reconciler_reports_observed_and_declared_dependency_disagreement() -> None:
    node = GraphNode(
        node_key="service:payments",
        node_kind="SERVICE",
        resource_ref="//run/payments",
        external_project_id="acme-payments-prod",
        owner_team="payments",
        declared_environment="prod",
        business_criticality="HIGH",
        data_classification="INTERNAL",
        authorization_boundary="payments",
        verification_profile="payments-recovery-v1",
        region="europe-west1",
        instrumentation_state="INSTRUMENTED",
        source_key="apphub",
        source_revision=1,
    )
    orders = node.__class__(
        node_key="service:orders",
        node_kind=node.node_kind,
        resource_ref="//run/orders",
        external_project_id="acme-orders-prod",
        owner_team="orders",
        declared_environment=node.declared_environment,
        business_criticality=node.business_criticality,
        data_classification=node.data_classification,
        authorization_boundary=node.authorization_boundary,
        verification_profile=node.verification_profile,
        region=node.region,
        instrumentation_state=node.instrumentation_state,
        source_key=node.source_key,
        source_revision=node.source_revision,
    )
    declared = GraphEdge(
        edge_key="declared:payments->orders",
        from_node_key=node.node_key,
        to_node_key=orders.node_key,
        edge_kind="DEPENDS_ON_DECLARED",
        source_key="asset",
        source_revision=1,
    )
    observed = GraphEdge(
        edge_key="observed:payments->orders",
        from_node_key=node.node_key,
        to_node_key=orders.node_key,
        edge_kind="DEPENDS_ON_OBSERVED",
        source_key="trace",
        source_revision=1,
    )

    class Adapter:
        def fetch(self, *, source_key: str, source_revision: int) -> GraphSourceResult:
            if source_key == "apphub":
                return GraphSourceResult(
                    "apphub", source_revision, 1, True, "COMPLETE", True, (node, orders)
                )
            if source_key == "asset":
                return GraphSourceResult(
                    "asset", source_revision, 3, True, "COMPLETE", True, edges=(declared,)
                )
            return GraphSourceResult(
                "trace", source_revision, 4, False, "COMPLETE", True, edges=(observed,)
            )

    draft = ProductionGraphReconciler().reconcile(
        snapshot_id="snap-1",
        source_plan=(
            GraphSourcePlanEntry("apphub", 1, 1, True, "sha256:" + "a" * 64),
            GraphSourcePlanEntry("asset", 1, 3, True, "sha256:" + "b" * 64),
            GraphSourcePlanEntry("trace", 1, 4, False, "sha256:" + "c" * 64),
        ),
        adapter=Adapter(),
    )
    assert "UNOBSERVED_DECLARATION:declared:payments->orders" not in draft.findings
    assert not any(item.startswith("UNDECLARED_DEPENDENCY:") for item in draft.findings)
