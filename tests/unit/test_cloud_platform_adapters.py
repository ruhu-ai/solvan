from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from solvan.application.detection import Comparator, DetectionRule
from solvan.platform.cloud_monitoring import CloudMonitoringReader, ResourceAttributionError
from solvan.platform.evidence_objects import GcsEvidenceWriter


class FakeResponse:
    def __init__(
        self, payload: dict[str, Any], request_id: str = "request-1", status_code: int = 200
    ) -> None:
        self.payload = payload
        self.content = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        self.headers = {"x-request-id": request_id}
        self.status_code = status_code

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
        return self.payload


class FakeSession:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(("GET", url, kwargs))
        return self.responses.pop(0)

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(("POST", url, kwargs))
        return self.responses.pop(0)

    def delete(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(("DELETE", url, kwargs))
        return self.responses.pop(0)


def rule(**query_overrides: object) -> DetectionRule:
    query = {"gcp_project_id": "solvan-demo", "resource_name": "solvan-payments"}
    query.update(query_overrides)
    return DetectionRule(
        rule_id="payments-http-5xx",
        version=1,
        service_id="svc_00000000000000000000000000",
        service_key="payments-api",
        graph_snapshot_id="pgs_00000000000000000000000000",
        incident_class="connection_exhaustion",
        signal_kind="HTTP_5XX_RATIO",
        query=query,
        evaluation_interval_ms=25_000,
        comparator=Comparator.GT,
        threshold=0.05,
        sustained_windows=2,
        severity="SEV2",
        deduplication_dimension="http-5xx",
        action_budget=2,
        repeated_action_limit=1,
    )


def points(value: float) -> dict[str, Any]:
    return {"timeSeries": [{"points": [{"value": {"doubleValue": value}}]}]}


def attributed(value: float, project: str, **labels: str) -> dict[str, Any]:
    """One series carrying the monitored resource that produced it."""
    return {
        "timeSeries": [
            {
                "resource": {
                    "type": "cloud_run_revision",
                    "labels": {"project_id": project, **labels},
                },
                "points": [{"value": {"doubleValue": value}}],
            }
        ]
    }


def test_monitoring_ratio_uses_typed_filters_not_freeform_query() -> None:
    session = FakeSession([FakeResponse(points(100), "total"), FakeResponse(points(8), "5xx")])
    end = datetime(2026, 8, 8, tzinfo=UTC)

    observation = CloudMonitoringReader(session).observe(
        rule(), window_start=end - timedelta(minutes=1), window_end=end
    )

    assert observation.value == 0.08
    assert observation.request_ids == ("total", "5xx")
    assert 'response_code_class"="5xx' in session.calls[1][2]["params"]["filter"]


def test_monitoring_pins_its_project_and_keeps_the_grouping_that_proves_it() -> None:
    """Specification 13 §4.2.

    A reducer with no grouping field collapses every matching series and drops
    the labels that say where the number came from, so the project must be both
    pinned in the filter and grouped in the response.
    """
    session = FakeSession([FakeResponse(points(100), "total"), FakeResponse(points(8), "5xx")])
    end = datetime(2026, 8, 8, tzinfo=UTC)

    CloudMonitoringReader(session).observe(
        rule(), window_start=end - timedelta(minutes=1), window_end=end
    )

    params = session.calls[0][2]["params"]
    assert 'resource.label."project_id"="solvan-demo"' in params["filter"]
    assert "resource.label.project_id" in params["aggregation.groupByFields"]


def test_monitoring_refuses_to_sum_series_from_two_projects() -> None:
    """A cross-project reduction produces a number describing no real service.

    Without the §4.2 check this returns 100 + 400 as one value and an incident
    fires on a figure that belongs to neither project.
    """
    spanning = {
        "timeSeries": [
            attributed(100, "solvan-demo")["timeSeries"][0],
            attributed(400, "solvan-other")["timeSeries"][0],
        ]
    }
    session = FakeSession([FakeResponse(spanning, "total")])
    end = datetime(2026, 8, 8, tzinfo=UTC)

    with pytest.raises(ResourceAttributionError, match="wider than"):
        CloudMonitoringReader(session).observe(
            rule(), window_start=end - timedelta(minutes=1), window_end=end
        )


def test_monitoring_refuses_a_response_from_a_project_it_did_not_address() -> None:
    session = FakeSession([FakeResponse(attributed(100, "solvan-other"), "total")])
    end = datetime(2026, 8, 8, tzinfo=UTC)

    with pytest.raises(ResourceAttributionError, match="addressed to solvan-demo"):
        CloudMonitoringReader(session).observe(
            rule(), window_start=end - timedelta(minutes=1), window_end=end
        )


def test_monitoring_keeps_every_observed_label_as_provenance() -> None:
    """§4.2: the rest of the labels are cited and displayed, never interpreted."""
    session = FakeSession(
        [
            FakeResponse(attributed(100, "solvan-demo", revision_name="payments-004"), "total"),
            FakeResponse(attributed(8, "solvan-demo", revision_name="payments-004"), "5xx"),
        ]
    )
    end = datetime(2026, 8, 8, tzinfo=UTC)

    observation = CloudMonitoringReader(session).observe(
        rule(), window_start=end - timedelta(minutes=1), window_end=end
    )

    assert observation.value == 0.08
    assert observation.resource.project_id == "solvan-demo"
    assert observation.resource.as_provenance() == {
        "project_id": "solvan-demo",
        "resource_type": "cloud_run_revision",
        "revision_name": "payments-004",
    }


def test_monitoring_rejects_filter_breakout_in_resource_name() -> None:
    with pytest.raises(ValueError, match="safe string"):
        CloudMonitoringReader(FakeSession([])).observe(
            rule(resource_name='payments" OR true'),
            window_start=datetime(2026, 8, 8, tzinfo=UTC),
            window_end=datetime(2026, 8, 8, 0, 1, tzinfo=UTC),
        )


def test_gcs_evidence_writer_is_create_only_and_content_addressed() -> None:
    session = FakeSession([FakeResponse({"generation": "42"})])
    receipt = GcsEvidenceWriter(bucket="solvan-evidence", session=session).put_json(
        object_name="detections/rule/window.json", value={"value": 0.08}
    )

    assert receipt.uri == "gs://solvan-evidence/detections/rule/window.json"
    assert receipt.content_hash.startswith("sha256:")
    assert session.calls[0][2]["params"]["ifGenerationMatch"] == "0"


def test_gcs_evidence_writer_recovers_idempotent_create_race() -> None:
    session = FakeSession(
        [
            FakeResponse({}, status_code=412),
            FakeResponse({"generation": "42"}),
            FakeResponse({"value": 0.08}),
        ]
    )
    receipt = GcsEvidenceWriter(bucket="solvan-evidence", session=session).put_json(
        object_name="detections/rule/sha256-content.json", value={"value": 0.08}
    )

    assert receipt.generation == "42"
    assert session.calls[1][0] == "GET"
    assert session.calls[2][2]["timeout"] == 30


def test_gcs_evidence_writer_rejects_existing_object_with_other_content() -> None:
    session = FakeSession(
        [
            FakeResponse({}, status_code=412),
            FakeResponse({"generation": "42"}),
            FakeResponse({"value": 0.99}),
        ]
    )
    with pytest.raises(RuntimeError, match="does not match"):
        GcsEvidenceWriter(bucket="solvan-evidence", session=session).put_json(
            object_name="detections/rule/sha256-content.json", value={"value": 0.08}
        )


def test_gcs_evidence_reader_verifies_bucket_hash_and_size() -> None:
    from hashlib import sha256

    from solvan.platform.evidence_objects import GcsEvidenceReader

    response = FakeResponse({"canonical_event": {"rule_id": "rule-1"}})
    reader = GcsEvidenceReader(
        allowed_buckets=frozenset({"solvan-evidence"}),
        session=FakeSession([response]),
    )
    value = reader.get_json(
        uri="gs://solvan-evidence/detections/event.json",
        expected_hash=f"sha256:{sha256(response.content).hexdigest()}",
    )
    assert value["canonical_event"] == {"rule_id": "rule-1"}

    with pytest.raises(ValueError, match="outside"):
        reader.get_json(
            uri="gs://attacker-bucket/event.json",
            expected_hash=f"sha256:{sha256(response.content).hexdigest()}",
        )


def test_gcs_evidence_deleter_uses_generation_fence_and_accepts_absence() -> None:
    from solvan.platform.evidence_objects import GcsEvidenceDeleter

    session = FakeSession([FakeResponse({}, status_code=404)])
    receipt = GcsEvidenceDeleter(
        allowed_buckets=frozenset({"solvan-evidence"}), session=session
    ).delete(uri="gs://solvan-evidence/skills/source.bin", expected_generation="42")
    assert "status=404" in receipt
    assert session.calls[0][0] == "DELETE"
    assert session.calls[0][2]["params"] == {"ifGenerationMatch": "42"}
