from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from solvan.application.operational_compute import (
    LogEvidence,
    MetricSeries,
    RevisionProjection,
    cloud_run_revision_compare,
    log_pattern_summary,
    log_sample_bounded,
    metric_baseline_compare,
    metric_change_point_detect,
    metric_correlate,
)

EVD_A = "evd_00000000000000000000000000"
EVD_B = "evd_00000000000000000000000001"


def metric(ref: str, values: list[float], *, signal: str = "http_5xx_ratio") -> MetricSeries:
    start = datetime(2026, 8, 10, 10, tzinfo=UTC)
    return MetricSeries.model_validate(
        {
            "evidence_ref": ref,
            "signal_kind": signal,
            "points": [
                {"observed_at": start + timedelta(minutes=index), "value": value}
                for index, value in enumerate(values)
            ],
        }
    )


def test_metric_compute_is_method_versioned_and_cites_exact_evidence() -> None:
    result = metric_baseline_compare(
        baseline=metric(EVD_A, [1, 1, 1]), incident=metric(EVD_B, [3, 3, 3])
    )
    assert result.interpretation == "INCREASED"
    assert result.relative_delta == 2
    assert result.provenance.method == "ARITHMETIC_MEAN_DELTA"
    assert result.provenance.version == "1"
    assert result.provenance.input_evidence_refs == (EVD_A, EVD_B)


def test_change_point_requires_samples_and_is_bounded() -> None:
    insufficient = metric_change_point_detect(series=metric(EVD_A, [1, 1, 1]))
    assert insufficient.minimum_samples_satisfied is False
    assert insufficient.candidates == ()
    result = metric_change_point_detect(series=metric(EVD_A, [1, 1, 1, 10, 10, 10]), threshold=1)
    assert result.minimum_samples_satisfied is True
    assert 0 < len(result.candidates) <= 5


def test_correlation_is_explicitly_not_causation() -> None:
    result = metric_correlate(
        left=metric(EVD_A, [1, 2, 3]), right=metric(EVD_B, [2, 4, 6], signal="latency")
    )
    assert result.coefficient == pytest.approx(1)
    assert result.interpretation == "POSITIVE"
    assert result.causation_warning == "CORRELATION_DOES_NOT_ESTABLISH_CAUSATION"


def test_correlation_refuses_unaligned_inputs() -> None:
    right = metric(EVD_B, [1, 2, 3]).model_copy(
        update={
            "points": tuple(
                point.model_copy(update={"observed_at": point.observed_at + timedelta(days=1)})
                for point in metric(EVD_B, [1, 2, 3]).points
            )
        }
    )
    with pytest.raises(ValueError, match="timestamp-aligned"):
        metric_correlate(left=metric(EVD_A, [1, 2, 3]), right=right)


def test_log_summary_declares_unknown_no_data_semantics() -> None:
    result = log_pattern_summary(evidence=LogEvidence(evidence_ref=EVD_A, entries=()))
    assert result.no_data is True
    assert result.provenance.parameters["no_data_semantics"] == "UNKNOWN"


def test_log_sample_is_deterministic_bounded_and_retains_rare_signature() -> None:
    start = datetime(2026, 8, 10, 10, tzinfo=UTC)
    evidence = LogEvidence.model_validate(
        {
            "evidence_ref": EVD_A,
            "entries": [
                {
                    "observed_at": start + timedelta(seconds=index),
                    "signature_key": "common" if index < 9 else "rare",
                    "normalized_message": f"message-{index}",
                }
                for index in range(10)
            ],
        }
    )
    first = log_sample_bounded(evidence=evidence, maximum_entries=3)
    second = log_sample_bounded(evidence=evidence, maximum_entries=3)
    assert first == second
    assert len(first.entries) <= 3
    assert "rare" in {item.signature_key for item in first.entries}


def test_cloud_run_revision_diff_is_normalized_and_provenance_bearing() -> None:
    before = RevisionProjection(
        evidence_ref=EVD_A,
        revision_ref="projects/p/locations/europe-west1/services/s/revisions/a",
        fields={"image": "sha256:a", "concurrency": 80},
    )
    after = RevisionProjection(
        evidence_ref=EVD_B,
        revision_ref="projects/p/locations/europe-west1/services/s/revisions/b",
        fields={"image": "sha256:b", "concurrency": 80},
    )
    result = cloud_run_revision_compare(before=before, after=after)
    assert [item.field for item in result.differences] == ["image"]
    assert result.provenance.input_evidence_refs == (EVD_A, EVD_B)
