from types import SimpleNamespace

import pytest

from solvan.application.production_graph_review import (
    GraphReviewMode,
    authorize_graph_review,
)
from solvan.application.saas_scale import ScaleRuntimeError


def _snapshot(
    snapshot_id: str,
    *,
    complete: str = "COMPLETE",
    material: str = "sha256:a",
    status: str = "DRAFT",
    content: str | None = None,
):
    return SimpleNamespace(
        snapshot_id=snapshot_id,
        status=status,
        completeness=complete,
        material_hash=material,
        content_hash=content or f"sha256:{snapshot_id}",
    )


def _diff(changes: int = 0):
    return SimpleNamespace(governed_change_count=changes)


def test_first_graph_snapshot_requires_human_reason() -> None:
    with pytest.raises(ScaleRuntimeError, match="first graph snapshot"):
        authorize_graph_review(
            candidate=_snapshot("snap-1"),
            previous=None,
            diff=_diff(),
            mode=GraphReviewMode.AUTO_PROMOTED,
            decision_id="dec-1",
        )
    decision = authorize_graph_review(
        candidate=_snapshot("snap-1"),
        previous=None,
        diff=_diff(),
        mode=GraphReviewMode.HUMAN_APPROVED,
        decision_id="dec-1",
        principal="operator@example.com",
        reason_ref="ref_review_1",
    )
    assert decision.principal == "operator@example.com"


def test_auto_promotion_requires_same_material_and_zero_governed_change() -> None:
    previous = _snapshot("snap-1")
    candidate = _snapshot("snap-2")
    decision = authorize_graph_review(
        candidate=candidate,
        previous=previous,
        diff=_diff(),
        mode=GraphReviewMode.AUTO_PROMOTED,
        decision_id="dec-2",
    )
    assert decision.mode is GraphReviewMode.AUTO_PROMOTED
    with pytest.raises(ScaleRuntimeError, match="zero governed"):
        authorize_graph_review(
            candidate=candidate,
            previous=previous,
            diff=_diff(1),
            mode=GraphReviewMode.AUTO_PROMOTED,
            decision_id="dec-3",
        )


def test_incomplete_or_rejected_graph_never_reaches_review() -> None:
    with pytest.raises(ScaleRuntimeError, match="incomplete"):
        authorize_graph_review(
            candidate=_snapshot("snap-3", complete="INCOMPLETE"),
            previous=_snapshot("snap-2"),
            diff=_diff(),
            mode=GraphReviewMode.HUMAN_APPROVED,
            decision_id="dec-4",
            principal="operator@example.com",
            reason_ref="ref_review_4",
        )
    rejected = _snapshot("snap-4")
    with pytest.raises(ScaleRuntimeError, match="rejected"):
        authorize_graph_review(
            candidate=rejected,
            previous=_snapshot("snap-2"),
            diff=_diff(),
            mode=GraphReviewMode.HUMAN_APPROVED,
            decision_id="dec-5",
            principal="operator@example.com",
            reason_ref="ref_review_5",
            previously_rejected_hashes=frozenset({rejected.content_hash}),
        )


def test_non_draft_or_unfinalized_graph_never_reaches_review() -> None:
    with pytest.raises(ScaleRuntimeError, match="only a draft"):
        authorize_graph_review(
            candidate=_snapshot("snap-approved", status="APPROVED"),
            previous=_snapshot("snap-previous", status="APPROVED"),
            diff=_diff(),
            mode=GraphReviewMode.HUMAN_APPROVED,
            decision_id="dec-6",
            principal="operator@example.com",
            reason_ref="ref_review_6",
        )
    with pytest.raises(ScaleRuntimeError, match="finalized"):
        authorize_graph_review(
            candidate=_snapshot("snap-unfinalized", material=None, content=None),
            previous=None,
            diff=_diff(),
            mode=GraphReviewMode.HUMAN_APPROVED,
            decision_id="dec-7",
            principal="operator@example.com",
            reason_ref="ref_review_7",
        )
