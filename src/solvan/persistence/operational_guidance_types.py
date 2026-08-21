"""Immutable result values for Operational Guidance persistence."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GuidanceLifecycleCommit:
    guidance_key: str
    version: str
    lifecycle: str
    digest: str
    decision_id: str | None
    created: bool


@dataclass(frozen=True, slots=True)
class GuidanceSelectedMaterial:
    selection_id: str
    guidance_key: str
    version: str
    guidance_hash: str
    content_ref: str
    content_hash: str
    classification: str
    selected: bool


@dataclass(frozen=True, slots=True)
class GuidanceStepVerdict:
    step_run_id: str
    step_key: str
    status: str
    predicate_ref: str
    cited_records: tuple[str, ...]
    reason_code: str | None
    created: bool
