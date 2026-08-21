"""A Tool probe answers only what it observed.

These cover the claims the Fleet `Tools` tab makes about capability evidence:
that `PASSED` is written only for a real successful read, that every other
result names its reason and the grant that would fix it, that the probe asks the
Tool's own declared capability rather than the connection's, and that the
coverage row and the receipt can be joined because they carry one reference.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from solvan.application.tenant_integration import ConnectionPolicyError
from solvan.platform.tool_capability_probe import (
    PROBE_FRESHNESS,
    ToolProbeTarget,
    probe_tool_capability,
)

_MONITORING = ToolProbeTarget(
    tool_key="cloud_monitoring_query",
    tool_version="1",
    capability="monitoring.timeSeries.list",
    provider="CLOUD_MONITORING",
    gcp_project_id="acme-prod",
)


@dataclass
class _Response:
    status_code: int


class _Transport:
    """Records every request so a probe cannot silently mutate or page."""

    def __init__(self, status_code: int = 200) -> None:
        self._status_code = status_code
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: Any) -> _Response:
        self.calls.append(("GET", url, kwargs))
        return _Response(self._status_code)

    def post(self, url: str, **kwargs: Any) -> _Response:
        self.calls.append(("POST", url, kwargs))
        return _Response(self._status_code)


def test_a_successful_read_is_the_only_thing_that_records_passed() -> None:
    observed = probe_tool_capability(_Transport(200), target=_MONITORING)
    assert observed.available is True
    assert observed.outcome == "GRANTED"
    assert observed.probe_outcome == "PASSED"
    assert observed.missing_grant is None
    assert observed.reason_code is None


@pytest.mark.parametrize(
    ("status_code", "outcome", "reason_code"),
    [
        (403, "DENIED", "GRANT_MISSING"),
        (401, "DENIED", "GRANT_MISSING"),
        (404, "MISCONFIGURED", "API_NOT_ENABLED"),
        (500, "UNREACHABLE", "PROVIDER_ERROR"),
    ],
)
def test_no_unsuccessful_response_can_be_stored_as_a_pass(
    status_code: int, outcome: str, reason_code: str
) -> None:
    observed = probe_tool_capability(_Transport(status_code), target=_MONITORING)
    assert observed.available is False
    assert observed.outcome == outcome
    assert observed.reason_code == reason_code
    assert observed.probe_outcome == "FAILED"
    # The receipt table refuses a FAILED row without both fields, so the probe
    # must always supply them rather than leaving the writer to invent one.
    assert observed.missing_grant


def test_a_denial_names_the_grant_that_would_fix_it() -> None:
    observed = probe_tool_capability(_Transport(403), target=_MONITORING)
    assert observed.missing_grant == "roles/monitoring.viewer"


def test_an_unreachable_provider_is_never_reported_as_a_denial() -> None:
    class _Broken:
        def get(self, url: str, **kwargs: Any) -> _Response:
            raise TimeoutError("network unreachable")

        def post(self, url: str, **kwargs: Any) -> _Response:
            raise TimeoutError("network unreachable")

    observed = probe_tool_capability(_Broken(), target=_MONITORING)
    assert observed.outcome == "UNREACHABLE"
    assert observed.reason_code == "PROVIDER_UNREACHABLE"
    # Sending an operator to grant a role they already hold is the failure this
    # separation exists to prevent.
    assert observed.missing_grant is not None
    assert "could not reach the provider" in observed.missing_grant


def test_a_capability_with_no_probe_is_reported_rather_than_assumed() -> None:
    observed = probe_tool_capability(
        _Transport(200),
        target=ToolProbeTarget(
            tool_key="kubernetes_metadata_read",
            tool_version="1",
            capability="metadata.list",
            provider="KUBERNETES",
            gcp_project_id="acme-prod",
        ),
    )
    assert observed.available is False
    assert observed.outcome == "NOT_PROBED"
    assert observed.reason_code == "CAPABILITY_HAS_NO_PROBE"


def test_the_probe_asks_the_tools_own_capability_not_the_connections() -> None:
    transport = _Transport(200)
    probe_tool_capability(transport, target=_MONITORING)
    (method, url, kwargs) = transport.calls[0]
    assert method == "GET"
    # `metricDescriptors` is what the connection probe reads. A Tool that
    # declares `timeSeries.list` must be observed on `timeSeries`, or a narrower
    # custom role would leave the console asserting a capability the Tool lacks.
    assert url.endswith("/projects/acme-prod/timeSeries")
    assert "metricDescriptors" not in url


def test_the_probe_is_bounded_and_read_only() -> None:
    transport = _Transport(200)
    probe_tool_capability(transport, target=_MONITORING)
    params = transport.calls[0][2]["params"]
    assert params["pageSize"] == 1
    # HEADERS returns series identity with no data points: the question is
    # permission, never the customer's telemetry.
    assert params["view"] == "HEADERS"
    assert params["interval.startTime"] < params["interval.endTime"]
    assert all(call[0] == "GET" for call in transport.calls)
    assert len(transport.calls) == 1


def test_one_observation_yields_one_reference_for_coverage_and_receipt() -> None:
    observed = probe_tool_capability(_Transport(200), target=_MONITORING)
    # `resolve_and_bind_run` joins coverage.probe_receipt_ref to the receipt's
    # receipt_ref. Both come from here, so they cannot disagree.
    assert observed.receipt_ref.startswith(
        "probe://tool/cloud_monitoring_query/monitoring.timeSeries.list#sha256:"
    )
    assert observed.receipt_hash.startswith("sha256:")
    assert observed.receipt_ref.endswith(observed.receipt_hash.removeprefix("sha256:"))


def test_an_observation_expires_so_a_revoked_grant_stops_binding_new_work() -> None:
    observed = probe_tool_capability(_Transport(200), target=_MONITORING)
    assert observed.expires_at - observed.observed_at == PROBE_FRESHNESS
    assert observed.expires_at > observed.observed_at


def test_an_available_observation_cannot_also_carry_a_missing_grant() -> None:
    observed = probe_tool_capability(_Transport(200), target=_MONITORING)
    with pytest.raises(ConnectionPolicyError):
        type(observed)(
            tool_revision=observed.tool_revision,
            capability=observed.capability,
            available=True,
            outcome="GRANTED",
            missing_grant="roles/monitoring.viewer",
            reason_code=None,
            receipt_ref=observed.receipt_ref,
            receipt_hash=observed.receipt_hash,
            observed_at=observed.observed_at,
            expires_at=observed.expires_at,
        ).validated()


def test_a_denied_observation_cannot_be_constructed_as_available() -> None:
    observed = probe_tool_capability(_Transport(403), target=_MONITORING)
    with pytest.raises(ConnectionPolicyError):
        type(observed)(
            tool_revision=observed.tool_revision,
            capability=observed.capability,
            available=True,
            outcome="DENIED",
            missing_grant=None,
            reason_code=None,
            receipt_ref=observed.receipt_ref,
            receipt_hash=observed.receipt_hash,
            observed_at=observed.observed_at,
            expires_at=observed.expires_at,
        ).validated()
