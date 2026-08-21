"""Deterministic detection-rule comparison and durable streak semantics."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from itertools import pairwise
from math import isfinite
from typing import Any


class Comparator(StrEnum):
    GT = "GT"
    GTE = "GTE"
    LT = "LT"
    LTE = "LTE"


@dataclass(frozen=True, slots=True)
class DetectionSourceBinding:
    connection_id: str
    connection_epoch: int
    external_project_id: str
    workload_region: str
    solvan_delegator_principal: str
    customer_reader_principal: str
    token_lifetime_seconds: int

    def __post_init__(self) -> None:
        if not self.connection_id.startswith("con_") or self.connection_epoch < 1:
            raise ValueError("detection source binding has an invalid connection revision")
        if not self.external_project_id or not self.workload_region:
            raise ValueError("detection source binding has no exact workload location")
        if not self.solvan_delegator_principal.startswith("serviceAccount:"):
            raise ValueError("detection source binding has no Solvan delegator")
        if not self.customer_reader_principal.startswith("serviceAccount:"):
            raise ValueError("detection source binding has no customer reader")
        if not 1 <= self.token_lifetime_seconds <= 900:
            raise ValueError("detection source binding token lifetime is outside the bound")


@dataclass(frozen=True, slots=True)
class DetectionRule:
    rule_id: str
    version: int
    service_id: str
    service_key: str
    graph_snapshot_id: str
    incident_class: str
    signal_kind: str
    query: dict[str, Any]
    evaluation_interval_ms: int
    comparator: Comparator
    threshold: float
    sustained_windows: int
    severity: str
    deduplication_dimension: str
    action_budget: int
    repeated_action_limit: int
    source_binding: DetectionSourceBinding | None = None

    def __post_init__(self) -> None:
        if self.version < 1 or self.sustained_windows < 1:
            raise ValueError("detection rule versions and window counts must be positive")
        if not 20_000 <= self.evaluation_interval_ms <= 30_000:
            raise ValueError("detection interval must be between 20 and 30 seconds")
        if not isfinite(self.threshold):
            raise ValueError("detection threshold must be finite")

    def matches(self, observed_value: float) -> bool:
        if not isfinite(observed_value):
            raise ValueError("observed detection value must be finite")
        if self.comparator is Comparator.GT:
            return observed_value > self.threshold
        if self.comparator is Comparator.GTE:
            return observed_value >= self.threshold
        if self.comparator is Comparator.LT:
            return observed_value < self.threshold
        return observed_value <= self.threshold


@dataclass(frozen=True, slots=True)
class DetectionEvaluation:
    window_start: datetime
    window_end: datetime
    observed_value: float
    threshold_matched: bool

    def __post_init__(self) -> None:
        if self.window_start.tzinfo is None or self.window_end.tzinfo is None:
            raise ValueError("detection evaluation windows must be timezone-aware")
        if self.window_end < self.window_start:
            raise ValueError("detection evaluation window is reversed")
        if not isfinite(self.observed_value):
            raise ValueError("observed detection value must be finite")


def sustained_streak(rule: DetectionRule, newest_first: tuple[DetectionEvaluation, ...]) -> bool:
    """Require the configured number of matching, consecutive durable windows."""

    if len(newest_first) < rule.sustained_windows:
        return False
    selected = newest_first[: rule.sustained_windows]
    if not all(item.threshold_matched for item in selected):
        return False
    maximum_gap = timedelta(milliseconds=rule.evaluation_interval_ms * 1.5)
    return all(
        timedelta(0) < newer.window_end - older.window_end <= maximum_gap
        for newer, older in pairwise(selected)
    )
