"""Deterministic, bounded computations over already-authorized evidence."""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

_EVIDENCE_ID = r"^evd_[0-7][0-9A-HJKMNP-TV-Z]{25}$"
_SIGNATURE = r"^[a-zA-Z0-9_.:-]{1,80}$"


class MetricPoint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    observed_at: datetime
    value: float

    @model_validator(mode="after")
    def finite_value(self) -> MetricPoint:
        if not math.isfinite(self.value):
            raise ValueError("metric value must be finite")
        return self


class MetricSeries(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    evidence_ref: str = Field(pattern=_EVIDENCE_ID)
    signal_kind: str = Field(min_length=1, max_length=80, pattern=_SIGNATURE)
    points: tuple[MetricPoint, ...] = Field(min_length=3, max_length=1_000)

    @model_validator(mode="after")
    def chronological(self) -> MetricSeries:
        times = [point.observed_at for point in self.points]
        if any(value.tzinfo is None for value in times):
            raise ValueError("metric timestamps must be timezone-aware")
        if times != sorted(times) or len(set(times)) != len(times):
            raise ValueError("metric points must be unique and chronological")
        return self


class ComputeProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    method: str
    version: Literal["1"] = "1"
    input_evidence_refs: tuple[str, ...]
    parameters: dict[str, Any]


class BaselineComparison(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    baseline_mean: float
    incident_mean: float
    absolute_delta: float
    relative_delta: float | None
    baseline_sample_count: int
    incident_sample_count: int
    interpretation: Literal["INCREASED", "DECREASED", "UNCHANGED"]
    provenance: ComputeProvenance


def metric_baseline_compare(
    *, baseline: MetricSeries, incident: MetricSeries, unchanged_tolerance: float = 0.01
) -> BaselineComparison:
    """Compare two exact evidence series with arithmetic mean v1."""

    if baseline.signal_kind != incident.signal_kind:
        raise ValueError("baseline and incident signal kinds must match")
    if not 0 <= unchanged_tolerance <= 1:
        raise ValueError("unchanged_tolerance must be between zero and one")
    baseline_mean = statistics.fmean(point.value for point in baseline.points)
    incident_mean = statistics.fmean(point.value for point in incident.points)
    delta = incident_mean - baseline_mean
    relative = None if baseline_mean == 0 else delta / abs(baseline_mean)
    scale = max(abs(baseline_mean), 1.0)
    if abs(delta) <= unchanged_tolerance * scale:
        interpretation: Literal["INCREASED", "DECREASED", "UNCHANGED"] = "UNCHANGED"
    elif delta > 0:
        interpretation = "INCREASED"
    else:
        interpretation = "DECREASED"
    return BaselineComparison(
        baseline_mean=baseline_mean,
        incident_mean=incident_mean,
        absolute_delta=delta,
        relative_delta=relative,
        baseline_sample_count=len(baseline.points),
        incident_sample_count=len(incident.points),
        interpretation=interpretation,
        provenance=ComputeProvenance(
            method="ARITHMETIC_MEAN_DELTA",
            input_evidence_refs=(baseline.evidence_ref, incident.evidence_ref),
            parameters={"unchanged_tolerance": unchanged_tolerance},
        ),
    )


class ChangePointCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    observed_at: datetime
    before_mean: float
    after_mean: float
    normalized_delta: float


class ChangePointResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    candidates: tuple[ChangePointCandidate, ...]
    minimum_samples_satisfied: bool
    provenance: ComputeProvenance


def metric_change_point_detect(
    *, series: MetricSeries, minimum_segment_samples: int = 3, threshold: float = 2.0
) -> ChangePointResult:
    """Find bounded mean-shift candidates using pooled standard deviation v1."""

    if not 3 <= minimum_segment_samples <= 100:
        raise ValueError("minimum_segment_samples must be between 3 and 100")
    if not 0 < threshold <= 20:
        raise ValueError("threshold must be greater than zero and at most 20")
    points = series.points
    enough = len(points) >= minimum_segment_samples * 2
    candidates: list[ChangePointCandidate] = []
    if enough:
        values = [point.value for point in points]
        scale = statistics.pstdev(values)
        for index in range(minimum_segment_samples, len(points) - minimum_segment_samples + 1):
            before = statistics.fmean(values[:index])
            after = statistics.fmean(values[index:])
            normalized = abs(after - before) / scale if scale > 0 else 0.0
            if normalized >= threshold:
                candidates.append(
                    ChangePointCandidate(
                        observed_at=points[index].observed_at,
                        before_mean=before,
                        after_mean=after,
                        normalized_delta=normalized,
                    )
                )
    candidates.sort(key=lambda item: (-item.normalized_delta, item.observed_at))
    return ChangePointResult(
        candidates=tuple(candidates[:5]),
        minimum_samples_satisfied=enough,
        provenance=ComputeProvenance(
            method="POOLED_MEAN_SHIFT",
            input_evidence_refs=(series.evidence_ref,),
            parameters={
                "minimum_segment_samples": minimum_segment_samples,
                "threshold": threshold,
                "maximum_candidates": 5,
            },
        ),
    )


class CorrelationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    coefficient: float | None
    paired_sample_count: int
    interpretation: Literal["POSITIVE", "NEGATIVE", "NONE", "INSUFFICIENT_VARIANCE"]
    causation_warning: Literal["CORRELATION_DOES_NOT_ESTABLISH_CAUSATION"] = (
        "CORRELATION_DOES_NOT_ESTABLISH_CAUSATION"
    )
    provenance: ComputeProvenance


def metric_correlate(*, left: MetricSeries, right: MetricSeries) -> CorrelationResult:
    """Calculate Pearson correlation for exact timestamp intersections."""

    left_by_time = {point.observed_at: point.value for point in left.points}
    right_by_time = {point.observed_at: point.value for point in right.points}
    times = sorted(left_by_time.keys() & right_by_time.keys())
    if len(times) < 3:
        raise ValueError("correlation requires at least three timestamp-aligned samples")
    x = [left_by_time[value] for value in times]
    y = [right_by_time[value] for value in times]
    x_mean = statistics.fmean(x)
    y_mean = statistics.fmean(y)
    numerator = sum((a - x_mean) * (b - y_mean) for a, b in zip(x, y, strict=True))
    denominator = math.sqrt(sum((a - x_mean) ** 2 for a in x) * sum((b - y_mean) ** 2 for b in y))
    if denominator == 0:
        coefficient = None
        interpretation: Literal["POSITIVE", "NEGATIVE", "NONE", "INSUFFICIENT_VARIANCE"] = (
            "INSUFFICIENT_VARIANCE"
        )
    else:
        coefficient = max(-1.0, min(1.0, numerator / denominator))
        if coefficient >= 0.3:
            interpretation = "POSITIVE"
        elif coefficient <= -0.3:
            interpretation = "NEGATIVE"
        else:
            interpretation = "NONE"
    return CorrelationResult(
        coefficient=coefficient,
        paired_sample_count=len(times),
        interpretation=interpretation,
        provenance=ComputeProvenance(
            method="PEARSON_TIMESTAMP_INTERSECTION",
            input_evidence_refs=(left.evidence_ref, right.evidence_ref),
            parameters={"minimum_paired_samples": 3, "interpretation_threshold": 0.3},
        ),
    )


class NormalizedLogEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    observed_at: datetime
    signature_key: str = Field(pattern=_SIGNATURE)
    normalized_message: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def timestamp_is_aware(self) -> NormalizedLogEntry:
        if self.observed_at.tzinfo is None:
            raise ValueError("log timestamp must be timezone-aware")
        return self


class LogEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    evidence_ref: str = Field(pattern=_EVIDENCE_ID)
    entries: tuple[NormalizedLogEntry, ...] = Field(max_length=1_000)


class LogPatternCount(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    signature_key: str
    count: int
    first_seen: datetime
    last_seen: datetime


class LogPatternSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    patterns: tuple[LogPatternCount, ...]
    total_entries: int
    no_data: bool
    provenance: ComputeProvenance


def log_pattern_summary(*, evidence: LogEvidence) -> LogPatternSummary:
    grouped: dict[str, list[datetime]] = defaultdict(list)
    for entry in evidence.entries:
        grouped[entry.signature_key].append(entry.observed_at)
    patterns = [
        LogPatternCount(
            signature_key=key,
            count=len(values),
            first_seen=min(values),
            last_seen=max(values),
        )
        for key, values in grouped.items()
    ]
    patterns.sort(key=lambda item: (-item.count, item.signature_key))
    return LogPatternSummary(
        patterns=tuple(patterns[:100]),
        total_entries=len(evidence.entries),
        no_data=not evidence.entries,
        provenance=ComputeProvenance(
            method="REGISTERED_SIGNATURE_COUNT",
            input_evidence_refs=(evidence.evidence_ref,),
            parameters={"maximum_patterns": 100, "no_data_semantics": "UNKNOWN"},
        ),
    )


class LogSample(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    entries: tuple[NormalizedLogEntry, ...]
    source_entry_count: int
    provenance: ComputeProvenance


def log_sample_bounded(*, evidence: LogEvidence, maximum_entries: int = 20) -> LogSample:
    """Return a stable time-spread sample while retaining each rare signature."""

    if not 1 <= maximum_entries <= 100:
        raise ValueError("maximum_entries must be between 1 and 100")
    ordered = sorted(
        evidence.entries,
        key=lambda item: (item.observed_at, item.signature_key, item.normalized_message),
    )
    counts = Counter(item.signature_key for item in ordered)
    selected: list[NormalizedLogEntry] = []
    seen: set[tuple[datetime, str, str]] = set()

    def add(item: NormalizedLogEntry) -> None:
        key = (item.observed_at, item.signature_key, item.normalized_message)
        if key not in seen and len(selected) < maximum_entries:
            seen.add(key)
            selected.append(item)

    rarity_order = sorted(
        ordered, key=lambda value: (counts[value.signature_key], value.signature_key)
    )
    for item in rarity_order:
        add(item)
    remaining = maximum_entries - len(selected)
    if remaining > 0 and ordered:
        for offset in range(remaining):
            index = round(offset * (len(ordered) - 1) / max(remaining - 1, 1))
            add(ordered[index])
    selected.sort(key=lambda item: (item.observed_at, item.signature_key))
    return LogSample(
        entries=tuple(selected),
        source_entry_count=len(ordered),
        provenance=ComputeProvenance(
            method="RARE_SIGNATURE_THEN_TIME_SPREAD",
            input_evidence_refs=(evidence.evidence_ref,),
            parameters={"maximum_entries": maximum_entries},
        ),
    )


JsonScalar = Annotated[str | int | float | bool | None, Field()]


class RevisionProjection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    evidence_ref: str = Field(pattern=_EVIDENCE_ID)
    revision_ref: str = Field(min_length=1, max_length=512)
    fields: dict[str, JsonScalar] = Field(max_length=100)


class RevisionDifference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    field: str
    before: JsonScalar
    after: JsonScalar


class RevisionComparison(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    before_revision_ref: str
    after_revision_ref: str
    differences: tuple[RevisionDifference, ...]
    provenance: ComputeProvenance


def cloud_run_revision_compare(
    *, before: RevisionProjection, after: RevisionProjection
) -> RevisionComparison:
    keys = sorted(before.fields.keys() | after.fields.keys())
    differences = tuple(
        RevisionDifference(field=key, before=before.fields.get(key), after=after.fields.get(key))
        for key in keys
        if before.fields.get(key) != after.fields.get(key)
    )
    return RevisionComparison(
        before_revision_ref=before.revision_ref,
        after_revision_ref=after.revision_ref,
        differences=differences,
        provenance=ComputeProvenance(
            method="NORMALIZED_FIELD_DIFF",
            input_evidence_refs=(before.evidence_ref, after.evidence_ref),
            parameters={"field_count_ceiling": 100},
        ),
    )
