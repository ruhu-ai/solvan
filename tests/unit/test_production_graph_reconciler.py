from __future__ import annotations

import pytest

from solvan.persistence.production_graph import (
    GraphEdge,
    GraphNode,
    GraphSourcePlanEntry,
    GraphSourceResult,
    ProductionGraphReconciler,
    diff_graphs,
)

HASH = "sha256:" + "a" * 64


def _plan(key: str, tier: int, *, required: bool = True) -> GraphSourcePlanEntry:
    return GraphSourcePlanEntry(key, 1, tier, required, HASH)


def _node(key: str, *, instrumentation: str = "INSTRUMENTED") -> GraphNode:
    return GraphNode(
        node_key=key,
        node_kind="SERVICE",
        resource_ref=f"service/{key}",
        external_project_id="acme-payments-prod",
        owner_team="payments",
        declared_environment="prod",
        business_criticality="HIGH",
        data_classification="INTERNAL",
        authorization_boundary="customer-actuator",
        verification_profile="payments-recovery-v1",
        region="europe-west1",
        instrumentation_state=instrumentation,
        source_key="apphub",
        source_revision=1,
    )


class Adapter:
    def __init__(self, results: dict[str, GraphSourceResult]) -> None:
        self.results = results

    def fetch(self, *, source_key: str, source_revision: int) -> GraphSourceResult:
        return self.results[source_key]


def test_reconciliation_is_read_only_and_produces_incomplete_draft_on_missing_tier() -> None:
    adapter = Adapter(
        {
            "apphub": GraphSourceResult(
                "apphub", 1, 1, True, "COMPLETE", True, nodes=(_node("payments"),)
            ),
            "iam": GraphSourceResult("iam", 1, 2, True, "UNAVAILABLE", False),
        }
    )
    draft = ProductionGraphReconciler().reconcile(
        snapshot_id="snap-1",
        source_plan=(_plan("apphub", 1), _plan("iam", 2)),
        adapter=adapter,
    )
    assert draft.completeness == "INCOMPLETE"
    assert "SOURCE_INCOMPLETE:iam:1" in draft.findings
    assert draft.material_hash.startswith("sha256:")


def test_one_complete_source_cannot_cover_a_partial_peer_in_the_same_tier() -> None:
    adapter = Adapter(
        {
            "apphub": GraphSourceResult(
                "apphub", 1, 1, True, "COMPLETE", True, nodes=(_node("payments"),)
            ),
            "asset_inventory": GraphSourceResult("asset_inventory", 1, 1, True, "PARTIAL", False),
        }
    )

    draft = ProductionGraphReconciler().reconcile(
        snapshot_id="snap-same-tier",
        source_plan=(_plan("apphub", 1), _plan("asset_inventory", 1)),
        adapter=adapter,
    )

    assert draft.completeness == "INCOMPLETE"
    assert "SOURCE_INCOMPLETE:asset_inventory:1" in draft.findings


def test_source_response_must_match_the_frozen_policy_entry() -> None:
    adapter = Adapter({"apphub": GraphSourceResult("apphub", 1, 2, True, "COMPLETE", True)})

    with pytest.raises(ValueError, match="frozen policy entry"):
        ProductionGraphReconciler().reconcile(
            snapshot_id="snap-source-substitution",
            source_plan=(_plan("apphub", 1),),
            adapter=adapter,
        )


def test_reconciliation_rejects_edges_that_do_not_have_observed_endpoints() -> None:
    edge = GraphEdge("edge-1", "payments", "missing", "DEPENDS_ON", "apphub", 1)
    adapter = Adapter(
        {
            "apphub": GraphSourceResult(
                "apphub",
                1,
                1,
                True,
                "COMPLETE",
                True,
                nodes=(_node("payments"),),
                edges=(edge,),
            )
        }
    )
    draft = ProductionGraphReconciler().reconcile(
        snapshot_id="snap-2", source_plan=(_plan("apphub", 1),), adapter=adapter
    )
    assert draft.completeness == "INCOMPLETE"
    assert draft.findings == ("UNDECLARED_DEPENDENCY:edge-1",)


def test_diff_is_material_and_first_snapshot_cannot_be_auto_zero_change() -> None:
    adapter = Adapter(
        {
            "apphub": GraphSourceResult(
                "apphub", 1, 1, True, "COMPLETE", True, nodes=(_node("payments"),)
            )
        }
    )
    first = ProductionGraphReconciler().reconcile(
        snapshot_id="snap-1", source_plan=(_plan("apphub", 1),), adapter=adapter
    )
    diff = diff_graphs(None, first)
    assert diff.governed_change_count == 2
    assert diff.node_changes == 1
    changed = _node("payments", instrumentation="UNINSTRUMENTED")
    second = first.__class__(
        snapshot_id="snap-2",
        material_hash="sha256:" + "a" * 64,
        content_hash="sha256:" + "b" * 64,
        completeness="COMPLETE",
        nodes=(changed,),
        edges=(),
        findings=(),
    )
    assert diff_graphs(first, second).instrumentation_changes == 1


def test_overlapping_catalog_sources_choose_one_whole_richer_assertion() -> None:
    inventory = _node("payments")
    inventory = inventory.__class__(
        **{
            field: getattr(inventory, field)
            for field in inventory.__dataclass_fields__
            if field
            not in {
                "owner_team",
                "declared_environment",
                "business_criticality",
                "source_key",
            }
        },
        owner_team=None,
        declared_environment=None,
        business_criticality=None,
        source_key="asset_inventory",
    )
    app_hub = _node("payments")
    adapter = Adapter(
        {
            "asset_inventory": GraphSourceResult(
                "asset_inventory", 1, 1, True, "COMPLETE", True, nodes=(inventory,)
            ),
            "apphub": GraphSourceResult("apphub", 1, 1, True, "COMPLETE", True, nodes=(app_hub,)),
        }
    )

    draft = ProductionGraphReconciler().reconcile(
        snapshot_id="snap-overlap",
        source_plan=(_plan("asset_inventory", 1), _plan("apphub", 1)),
        adapter=adapter,
    )

    assert len(draft.nodes) == 1
    assert draft.nodes[0] == app_hub


def test_overlapping_catalog_sources_refuse_conflicting_governed_values() -> None:
    first = _node("payments")
    second = first.__class__(
        **{
            field: getattr(first, field)
            for field in first.__dataclass_fields__
            if field not in {"owner_team", "source_key"}
        },
        owner_team="different-team",
        source_key="asset_inventory",
    )
    adapter = Adapter(
        {
            "apphub": GraphSourceResult("apphub", 1, 1, True, "COMPLETE", True, nodes=(first,)),
            "asset_inventory": GraphSourceResult(
                "asset_inventory", 1, 1, True, "COMPLETE", True, nodes=(second,)
            ),
        }
    )

    with pytest.raises(ValueError, match="conflicting governed graph node"):
        ProductionGraphReconciler().reconcile(
            snapshot_id="snap-conflict",
            source_plan=(_plan("apphub", 1), _plan("asset_inventory", 1)),
            adapter=adapter,
        )
