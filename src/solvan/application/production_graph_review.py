"""Pure review policy for the target Production Graph diff surface."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from solvan.application.saas_scale import ScaleRuntimeError


class GraphReviewMode(StrEnum):
    HUMAN_APPROVED = "HUMAN_APPROVED"
    AUTO_PROMOTED = "AUTO_PROMOTED"


@dataclass(frozen=True, slots=True)
class GraphReviewDecision:
    snapshot_id: str
    mode: GraphReviewMode
    decision_id: str
    principal: str | None
    reason_ref: str | None


def authorize_graph_review(
    *,
    candidate: Any,
    previous: Any | None,
    diff: Any,
    mode: GraphReviewMode,
    decision_id: str,
    principal: str | None = None,
    reason_ref: str | None = None,
    previously_rejected_hashes: frozenset[str] = frozenset(),
) -> GraphReviewDecision:
    """Return an exact review decision or refuse before any database write."""

    if not decision_id or candidate.content_hash in previously_rejected_hashes:
        raise ScaleRuntimeError("graph candidate is absent or was previously rejected")
    if getattr(candidate, "status", "DRAFT") != "DRAFT":
        raise ScaleRuntimeError("only a draft graph snapshot can be reviewed")
    if not candidate.material_hash or not candidate.content_hash:
        raise ScaleRuntimeError("graph candidate must be finalized before review")
    if candidate.completeness != "COMPLETE":
        raise ScaleRuntimeError("incomplete graph snapshot cannot be promoted")
    if mode is GraphReviewMode.HUMAN_APPROVED:
        if not principal or not reason_ref or not reason_ref.startswith("ref_"):
            raise ScaleRuntimeError("human graph review requires an identity and reason reference")
        return GraphReviewDecision(candidate.snapshot_id, mode, decision_id, principal, reason_ref)
    if previous is None:
        raise ScaleRuntimeError("first graph snapshot requires named human approval")
    if diff.governed_change_count != 0 or candidate.material_hash != previous.material_hash:
        raise ScaleRuntimeError("automatic graph promotion requires zero governed change")
    return GraphReviewDecision(candidate.snapshot_id, mode, decision_id, None, None)
