"""Observe what one governed Tool revision can actually do, one bounded call.

This is deliberately not the connection probe. `capability_probe` asks whether a
connection holds a capability *class* — "can this credential read metrics at
all" — and its answer backs the connection's own availability. This module asks
the narrower question specification 16 §10.1 defines as Tool evidence: whether
*the exact capability the Tool declares* was observed and remains fresh.

Deriving one from the other would be wrong rather than merely imprecise.
`cloud_monitoring_query` declares `monitoring.timeSeries.list`; the connection
probe exercises `monitoring.metricDescriptors.list`. Both sit under
`roles/monitoring.viewer` today, so the derivation would agree with reality
until a customer grants a narrower custom role — and from then on the console
would assert a capability the Tool does not hold, and the coordinator would bind
a Tool that cannot run.

A probe never mutates, never pages, and never returns provider payloads. It
records availability and, on denial, the exact grant the customer must add.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from urllib.parse import quote

from solvan.application.tool_capability_evidence import (
    PROBE_FRESHNESS,
    ToolCapabilityObservation,
    ToolProbeOutcome,
    ToolProbeTarget,
)
from solvan.platform.capability_probe import ProbeTransport

#: The observation window a metric probe asks for. The question is "am I
#: permitted", so the window is the smallest one the API accepts rather than one
#: chosen to contain data: an empty result from a permitted read is a pass.
_PROBE_WINDOW = timedelta(minutes=5)


@dataclass(frozen=True, slots=True)
class _BoundedRequest:
    method: Literal["GET", "POST"]
    url_template: str
    params: dict[str, Any]
    required_grant: str


#: One bounded read per *declared Tool capability*, keyed exactly as the Tool
#: revision declares it. A capability absent from this table is reported
#: NOT_PROBED, never assumed available, so adding a Tool cannot silently grant
#: itself a pass by having no probe.
_TOOL_PROBES: dict[str, _BoundedRequest] = {
    "monitoring.timeSeries.list": _BoundedRequest(
        method="GET",
        url_template="https://monitoring.googleapis.com/v3/projects/{project}/timeSeries",
        # `view=HEADERS` returns series headers with no data points, which is
        # the smallest response the API can produce. A syntactically valid
        # filter that matches nothing still answers the permission question:
        # 200 with an empty set proves the read was allowed.
        params={
            "filter": 'metric.type = "compute.googleapis.com/instance/cpu/utilization"',
            "interval.startTime": "{window_start}",
            "interval.endTime": "{window_end}",
            "view": "HEADERS",
            "pageSize": 1,
        },
        required_grant="roles/monitoring.viewer",
    ),
}


def _receipt(target: ToolProbeTarget, started: datetime) -> tuple[str, str]:
    """The reference and hash the coverage row and the receipt both carry.

    `resolve_and_bind_run` joins coverage to the receipt on this exact
    reference, so it is derived from the observation rather than minted
    independently: two records that disagree here would silently never bind.
    """

    digest = hashlib.sha256(
        json.dumps(
            {
                "tool": target.tool_revision,
                "capability": target.capability,
                "provider": target.provider,
                "project": target.gcp_project_id,
                "started_at": started.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return (
        f"probe://tool/{target.tool_key}/{target.capability}#sha256:{digest}",
        f"sha256:{digest}",
    )


def _resolved(value: Any, *, project: str, window_start: str, window_end: str) -> Any:
    if not isinstance(value, str):
        return value
    return (
        value.replace("{project}", project)
        .replace("{window_start}", window_start)
        .replace("{window_end}", window_end)
    )


def probe_tool_capability(
    transport: ProbeTransport, *, target: ToolProbeTarget
) -> ToolCapabilityObservation:
    """Observe the exact capability one Tool revision declares, once."""

    started = datetime.now(UTC)
    receipt_ref, receipt_hash = _receipt(target, started)

    def observation(
        *,
        available: bool,
        outcome: ToolProbeOutcome,
        missing_grant: str | None,
        reason_code: str | None,
    ) -> ToolCapabilityObservation:
        return ToolCapabilityObservation(
            tool_revision=target.tool_revision,
            capability=target.capability,
            available=available,
            outcome=outcome,
            missing_grant=missing_grant,
            reason_code=reason_code,
            receipt_ref=receipt_ref,
            receipt_hash=receipt_hash,
            observed_at=started,
            expires_at=started + PROBE_FRESHNESS,
        ).validated()

    request = _TOOL_PROBES.get(target.capability)
    if request is None:
        return observation(
            available=False,
            outcome="NOT_PROBED",
            missing_grant=f"no automated probe exists for {target.capability}",
            reason_code="CAPABILITY_HAS_NO_PROBE",
        )

    window_end = started
    window_start = started - _PROBE_WINDOW
    params = {
        key: _resolved(
            value,
            project=target.gcp_project_id,
            window_start=window_start.isoformat().replace("+00:00", "Z"),
            window_end=window_end.isoformat().replace("+00:00", "Z"),
        )
        for key, value in request.params.items()
    }
    url = request.url_template.format(project=quote(target.gcp_project_id))
    try:
        if request.method == "GET":
            response = transport.get(url, params=params, timeout=15)
        else:
            response = transport.post(url, json=params, timeout=15)
    except Exception:
        # A transport failure is not a permission answer. Recording it as a
        # denial would send the customer to grant a role they already hold.
        return observation(
            available=False,
            outcome="UNREACHABLE",
            missing_grant=f"{request.required_grant} (probe could not reach the provider)",
            reason_code="PROVIDER_UNREACHABLE",
        )

    status_code = int(getattr(response, "status_code", 0))
    if 200 <= status_code < 300:
        return observation(available=True, outcome="GRANTED", missing_grant=None, reason_code=None)
    if status_code in (401, 403):
        return observation(
            available=False,
            outcome="DENIED",
            missing_grant=request.required_grant,
            reason_code="GRANT_MISSING",
        )
    if status_code == 404:
        return observation(
            available=False,
            outcome="MISCONFIGURED",
            missing_grant=f"{request.required_grant} (API not enabled on the project)",
            reason_code="API_NOT_ENABLED",
        )
    return observation(
        available=False,
        outcome="UNREACHABLE",
        missing_grant=f"{request.required_grant} (provider returned {status_code})",
        reason_code="PROVIDER_ERROR",
    )
