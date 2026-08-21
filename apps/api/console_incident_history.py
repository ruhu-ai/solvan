"""Settled incidents, kept so the queue reads as a queue rather than one card.

Closed work carries the same shape as open work — the same evidence index, the
same causal chain, the same verification — because a history that dropped the
provenance would teach the reader that provenance is a live-incident decoration
rather than the record itself.
"""

from __future__ import annotations

from typing import Any


def closed_incident(
    *,
    display_id: str,
    title: str,
    service: str,
    severity: str,
    age: str,
    impact_summary: str,
    mechanism: str,
    mitigation: str,
) -> dict[str, Any]:
    """A settled incident, kept so the queue reads as a queue rather than a card.

    Closed work carries the same shape as open work: the same evidence index,
    the same causal chain, the same verification. A history that drops the
    provenance would teach the reader that provenance is a live-incident
    decoration rather than the record.
    """

    reference = f"evd_…{display_id[-4:]}"
    return {
        "id": display_id,
        "machine_id": f"inc_{display_id.replace('-', '').upper()}",
        "title": title,
        "severity": severity,
        "service": service,
        "state": "CLOSED",
        "owner": "Closed · no owner required",
        "age": age,
        "next_action": "None; the case is closed",
        "impact_summary": impact_summary,
        "waiting_on_human": False,
        "environment": "development · europe-west1",
        "workflow_version": 21,
        "detected_at": "—",
        "agent_council": [],
        "causal_chain": [
            {
                "label": "Mechanism",
                "detail": mechanism,
                "status": "observed",
                "source": "Evidence Agent · citation-resolved",
            },
            {
                "label": "Impact",
                "detail": impact_summary,
                "status": "observed",
                "source": "Cloud Monitoring · archived",
            },
            {
                "label": "Bounded recovery",
                "detail": f"{mitigation}; the effect was reconciled once.",
                "status": "action",
                "source": "Execution receipt · archived",
            },
            {
                "label": "Current outcome",
                "detail": "Recovery was independently verified and the case is closed.",
                "status": "verified",
                "source": "Immutable verification profile",
            },
        ],
        "brief": {
            "situation": f"{title}. Closed after independent verification.",
            "impact": impact_summary,
            "impact_lines": [],
            "customer_window": "",
            "data_loss": "",
            "last_verified": "Independent verification passed before closure.",
            "root_cause": f"Confirmed: {mechanism}",
            "attention": "None. This incident is closed.",
            "next": "No further action.",
            "freshness": "Archived record",
            "citations": [reference],
            "memories": [],
        },
        "evidence_index": [
            {
                "ref": reference,
                "kind": "metric",
                "label": impact_summary,
                "source": f"Cloud Monitoring · {service}",
                "window": "archived",
                "freshness": "immutable · archived",
                "classification": "INTERNAL",
                "content_ref": f"gs://scripted-demo/evidence/{display_id.lower()}.json",
            }
        ],
        "feed": {"sequence": "v1 to v21", "last_event": 21, "lease": "Released on closure"},
        "plan": {"version": 1, "progress": "closed", "steps": []},
        "findings": {"validated": [], "inferred": []},
        "hypotheses": [],
        "actions": [],
        "verification": {
            "id": f"VER-{display_id[-4:]}",
            "verdict": "PASSED",
            "profile": "archived immutable profile",
            "owner": service,
            "binding": "archived",
            "intervals": [],
            "threshold": "archived immutable profile",
            "synthetic": "archived",
        },
        "phase_rail": [],
        "timeline": [
            {
                "time": "—",
                "actor": "Case scheduler",
                "event": f"{mitigation}; verified and closed.",
                "state": "CLOSED · v21",
                "kind": "success",
            }
        ],
    }
