"""How an incident explains itself: who worked it, what it stands on, and why.

Split from the incident projection because these three answers are read
together and change together. Each is derived from committed records only —
nothing here asks a model what happened.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from apps.api.projection_format import _age, _short

_AGENT_ROLES: tuple[tuple[str, str, str, str], ...] = (
    (
        "Incident Supervisor Agent",
        "incident-supervisor",
        "Investigation planning and hypothesis ranking",
        "model",
    ),
    ("Evidence Agent", "evidence-agent", "Bounded metrics, logs, and traces", "model"),
    ("Infrastructure Agent", "infrastructure-agent", "Revision and resource metadata", "model"),
    ("Execution Agent", "execution-agent", "Authorized bounded actuator", "action"),
    ("Verification Agent", "verification-agent", "Independent recovery oracle", "verification"),
    ("Workspace Agent", "workspace-agent", "Durable repair proposal", "model"),
)


def _agent_council(
    plan_rows: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    verification: dict[str, Any] | None,
) -> list[dict[str, str]]:
    """Expose the bounded identities participating in this incident.

    This is a read-only projection. It intentionally reports the coordinator's
    durable step/action state rather than asking a model which agents ran.
    """

    council: list[dict[str, str]] = []
    for name, identity, role, kind in _AGENT_ROLES:
        matching = [
            row
            for row in plan_rows
            if str(row["agent_key"] or "").lower() == identity
            or identity.removesuffix("-agent") in str(row["agent_key"] or "").lower()
        ]
        statuses = {str(row["status"]) for row in matching}
        if kind == "action":
            complete = any(
                str(item["status"]) in {"SUCCEEDED", "VERIFIED", "RECONCILED"} for item in actions
            )
            active = any(str(item["status"]) in {"AUTHORIZED", "EXECUTING"} for item in actions)
            status = "COMPLETE" if complete else "ACTIVE" if active else "READY"
            detail = (
                "Mutation receipt reconciled."
                if complete
                else "Waiting for an exact authorized action."
            )
            budget = "0/0 model · bounded action only"
        elif kind == "verification":
            status = (
                "COMPLETE"
                if verification is not None and str(verification["verdict"]) == "PASSED"
                else "RUNNING"
                if verification is not None
                else "READY"
            )
            detail = (
                "Independent verdict committed."
                if status == "COMPLETE"
                else "Observation window in progress."
                if status == "RUNNING"
                else "Waiting for a reconciled mutation."
            )
            budget = "0/1 model · bounded read tools"
        elif not matching:
            status = "READY"
            detail = "Registered and available to the coordinator."
            budget = "Not dispatched"
        elif statuses <= {"SUCCEEDED", "COMPLETED"}:
            status = "COMPLETE"
            detail = "Assigned durable step completed."
            budget = "Model/tool budget recorded on plan"
        elif statuses & {"DISPATCHED", "RUNNING"}:
            status = "ACTIVE"
            detail = "Assigned durable step is running."
            budget = "Model/tool budget recorded on plan"
        else:
            status = "READY"
            detail = "Assigned when its dependencies are satisfied."
            budget = "Model/tool budget recorded on plan"
        council.append(
            {
                "name": name,
                "role": role,
                "status": status,
                "detail": detail,
                "identity": identity,
                "budget": budget,
            }
        )
    return council


#: Map a stored evidence source onto the kind the console renders. A source we
#: have no mapping for is shown as a generic record rather than guessed at,
#: because an icon that claims the wrong kind is worse than no icon.
_EVIDENCE_KIND: dict[str, str] = {
    "CLOUD_MONITORING": "metric",
    "MANAGED_PROMETHEUS": "metric",
    "CLOUD_LOGGING": "log",
    "CLOUD_AUDIT": "log",
    "ERROR_REPORTING": "log",
    "CLOUD_TRACE": "trace",
    "CLOUD_RUN": "config",
    "CLOUD_ASSET": "config",
    "REPOSITORY": "code",
    "EXECUTION_RECEIPT": "receipt",
    "SYNTHETIC_PROBE": "synthetic",
}


def _freshness(expires_at: datetime | None) -> str:
    """Say whether a record may still be relied on, in the reader's terms."""

    if expires_at is None:
        return "immutable"
    remaining = (expires_at - datetime.now(UTC)).total_seconds()
    if remaining <= 0:
        return "stale · re-read required"
    return f"fresh · expires in {_age(expires_at)}"


def _evidence_index(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Resolve every cited evidence ref to a typed, human-readable record."""

    index: list[dict[str, str]] = []
    for row in rows:
        source_kind = str(row["source_kind"])
        window_start = row["window_start"].astimezone(UTC).strftime("%H:%M:%S")
        window_end = row["window_end"].astimezone(UTC).strftime("%H:%M:%S")
        redaction = " · redacted" if row["redaction_manifest_ref"] else ""
        index.append(
            {
                "ref": _short(row["id"]),
                "kind": _EVIDENCE_KIND.get(source_kind, "record"),
                "label": f"{source_kind.replace('_', ' ').title()} on {row['source_resource']}",
                "source": str(row["source_resource"]),
                "window": f"{window_start} to {window_end} UTC",
                "freshness": _freshness(row["freshness_expires_at"]),
                "classification": f"{row['classification']}{redaction}",
                "content_ref": str(row["content_ref"]),
            }
        )
    return index


def _causal_chain(
    incident: dict[str, Any],
    confirmed: dict[str, Any] | None,
    actions: list[dict[str, Any]],
    verification: dict[str, Any] | None,
) -> list[dict[str, str]]:
    """Turn committed records into a concise operator-readable causal chain."""

    incident_class = str(incident["incident_class"]).replace("_", " ").lower()
    mechanism = (
        "Awaiting a confirmed mechanism." if confirmed is None else str(confirmed["statement"])
    )
    recovery = next(
        (
            item
            for item in actions
            if str(item["status"]) in {"VERIFIED", "RECONCILED", "SUCCEEDED"}
        ),
        actions[0] if actions else None,
    )
    recovery_detail = (
        "No mutation has been proposed yet."
        if recovery is None
        else f"{recovery['name']} · {recovery['status'].replace('_', ' ').lower()}."
    )
    outcome = (
        "Independent verification is pending."
        if verification is None
        else (
            f"{verification['verdict']} under {verification['profile_id']} "
            f"v{verification['profile_version']}."
        )
    )
    return [
        {
            "label": "Fault",
            "detail": f"The {incident_class} signal crossed its committed threshold.",
            "status": "observed",
            "source": "Incident record",
        },
        # Mechanism precedes impact: the mechanism explains the fault, so a
        # reader who meets impact first is given the consequence before its
        # cause.
        {
            "label": "Mechanism",
            "detail": mechanism,
            "status": "observed" if confirmed is not None else "inferred",
            "source": "Stored hypothesis",
        },
        {
            "label": "Impact",
            "detail": f"{incident['severity']} impact is recorded on {incident['service_key']}.",
            "status": "observed",
            "source": "Incident record",
        },
        {
            "label": "Recovery action",
            "detail": recovery_detail,
            "status": "action",
            "source": "Action projection",
        },
        {
            "label": "Current outcome",
            "detail": outcome,
            "status": "verified" if verification is not None else "inferred",
            "source": "Verification projection",
        },
    ]
