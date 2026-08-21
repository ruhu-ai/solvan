"""Observe what a customer connection can actually do, one bounded call each.

Capability is never inferred from configuration. Every entry in the console's
capability matrix is the recorded outcome of a real, minimal, read-only request
against the customer's own project, so a missing grant is discovered here
rather than during an incident.

A probe never mutates, never pages, and never returns provider payloads: it
records availability and, on denial, the exact grant the customer must add.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import quote

from solvan.application.tenant_integration import (
    PROVIDER_CAPABILITIES,
    CapabilityObservation,
    ConnectionPolicyError,
)


class ProbeTransport(Protocol):
    """The minimal surface a probe needs. Implemented by GoogleRestSession."""

    def get(self, url: str, **kwargs: Any) -> Any: ...

    def post(self, url: str, **kwargs: Any) -> Any: ...


@dataclass(frozen=True, slots=True)
class ProbeTarget:
    """Everything a probe may know. Deliberately excludes any credential."""

    provider: str
    gcp_project_id: str


#: One bounded read per capability. Each request asks for the smallest possible
#: result — a single page of one item, or a metadata descriptor — because the
#: question is "am I permitted", never "what is the data".
_PROBES: dict[str, tuple[str, str, dict[str, Any]]] = {
    "metrics.read": (
        "GET",
        "https://monitoring.googleapis.com/v3/projects/{project}/metricDescriptors",
        {"pageSize": 1},
    ),
    "logs.read": (
        "GET",
        "https://logging.googleapis.com/v2/projects/{project}/logs",
        {"pageSize": 1},
    ),
    "audit.read": (
        "POST",
        "https://logging.googleapis.com/v2/entries:list",
        {
            "resourceNames": ["projects/{project}"],
            "filter": 'logName:"cloudaudit.googleapis.com%2Factivity"',
            "pageSize": 1,
        },
    ),
    "errors.read": (
        "GET",
        "https://clouderrorreporting.googleapis.com/v1beta1/projects/{project}/groupStats",
        {"timeRange.period": "PERIOD_1_HOUR", "pageSize": 1},
    ),
    "traces.read": (
        "GET",
        "https://cloudtrace.googleapis.com/v1/projects/{project}/traces",
        {"pageSize": 1},
    ),
    "inventory.read": (
        "GET",
        "https://cloudasset.googleapis.com/v1/projects/{project}:searchAllResources",
        {"pageSize": 1},
    ),
    "promql.read": (
        "GET",
        "https://monitoring.googleapis.com/v1/projects/{project}/location/global/prometheus"
        "/api/v1/labels",
        {},
    ),
}

#: Providers whose capability cannot be established by calling a Google API.
#: A collector reports its own reachability; a vendor key is exercised by its
#: own adapter. Probing them here would fabricate a result.
_NOT_GOOGLE_PROBEABLE = frozenset(
    {"SOLVAN_COLLECTOR", "DATADOG", "PROMETHEUS", "GRAFANA", "NEW_RELIC"}
)


def _receipt_ref(target: ProbeTarget, capability: str, started: datetime) -> str:
    digest = hashlib.sha256(
        json.dumps(
            {
                "provider": target.provider,
                "project": target.gcp_project_id,
                "capability": capability,
                "started_at": started.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return f"probe://{target.provider.lower()}/{capability}#sha256:{digest}"


def _observe(
    transport: ProbeTransport,
    *,
    target: ProbeTarget,
    capability: str,
    required_grant: str,
) -> CapabilityObservation:
    started = datetime.now(UTC)
    receipt = _receipt_ref(target, capability, started)
    probe = _PROBES.get(capability)
    if probe is None:
        # An unprobeable capability is reported unavailable with the reason,
        # never assumed available.
        return CapabilityObservation(
            capability=capability,
            available=False,
            missing_grant=f"{required_grant} (no automated probe; verify manually)",
            probe_receipt_ref=receipt,
            outcome="NOT_PROBED",
        ).validated()

    method, template, payload = probe
    url = template.format(project=quote(target.gcp_project_id))
    try:
        if method == "GET":
            response = transport.get(url, params=payload, timeout=15)
        else:
            body = json.loads(json.dumps(payload).replace("{project}", target.gcp_project_id))
            response = transport.post(url, json=body, timeout=15)
    except Exception:
        # A transport failure is not a permission answer. Report unavailable
        # and say so, rather than recording a denial the customer cannot fix.
        return CapabilityObservation(
            capability=capability,
            available=False,
            missing_grant=f"{required_grant} (probe could not reach the provider)",
            probe_receipt_ref=receipt,
            outcome="UNREACHABLE",
        ).validated()

    status_code = int(getattr(response, "status_code", 0))
    if 200 <= status_code < 300:
        return CapabilityObservation(
            capability=capability,
            available=True,
            missing_grant=None,
            probe_receipt_ref=receipt,
            outcome="GRANTED",
        ).validated()
    if status_code in (401, 403):
        return CapabilityObservation(
            capability=capability,
            available=False,
            missing_grant=required_grant,
            probe_receipt_ref=receipt,
            outcome="DENIED",
        ).validated()
    if status_code == 404:
        return CapabilityObservation(
            capability=capability,
            available=False,
            missing_grant=f"{required_grant} (API not enabled on the project)",
            probe_receipt_ref=receipt,
            outcome="MISCONFIGURED",
        ).validated()
    # An unclassified status is not a permission answer either. Treating it as
    # a denial would send the customer to grant a role that is already granted.
    return CapabilityObservation(
        capability=capability,
        available=False,
        missing_grant=f"{required_grant} (provider returned {status_code})",
        probe_receipt_ref=receipt,
        outcome="UNREACHABLE",
    ).validated()


def probe_connection(
    transport: ProbeTransport, *, target: ProbeTarget
) -> tuple[CapabilityObservation, ...]:
    """Observe every capability declared for the provider, one bounded call each."""

    declared = PROVIDER_CAPABILITIES.get(target.provider)
    if not declared:
        raise ConnectionPolicyError(f"provider {target.provider} declares no capability")
    if target.provider in _NOT_GOOGLE_PROBEABLE:
        return tuple(
            CapabilityObservation(
                capability=capability,
                available=False,
                missing_grant=f"{grant} (reported by the provider, not probed here)",
                probe_receipt_ref=_receipt_ref(target, capability, datetime.now(UTC)),
                outcome="NOT_PROBED",
            ).validated()
            for capability, grant in declared
        )
    return tuple(
        _observe(
            transport,
            target=target,
            capability=capability,
            required_grant=grant,
        )
        for capability, grant in declared
    )
