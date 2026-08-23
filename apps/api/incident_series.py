"""The annotated incident axis.

Split from `incident_projection` because it is a self-contained projection with
its own rule: every point and every annotation comes from a durable record, and
nothing is drawn that was not observed.
"""

from __future__ import annotations

from datetime import UTC
from typing import Any


def json_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def series_view(
    evidence_rows: list[dict[str, Any]],
    *,
    incident: dict[str, Any],
    action_rows: list[dict[str, Any]],
    verification: dict[str, Any] | None,
) -> dict[str, Any]:
    """One axis, composed from consecutive bounded evidence items.

    An evidence window is capped at fifteen minutes because a provider task is
    bounded and stateless, so an incident-length axis is several items
    concatenated rather than one wide read. Each item carried its own
    authorization, classification, redaction and content hash, which makes the
    provenance N citable windows instead of one.

    Points are not interpolated across a gap between items. A gap is a real gap
    in observation, and a line drawn through it would assert a measurement that
    was never taken.

    Every annotation comes from a durable record. There is deliberately no
    deploy marker: no deployment record exists in the schema, and inventing one
    to match a design mock is exactly the assertion section 6 of specification
    6 prohibits.
    """
    series: list[dict[str, Any]] = []
    citations: list[str] = []
    signal_kind = ""
    revisions: list[dict[str, str]] = []
    for row in sorted(evidence_rows, key=lambda item: item["window_start"]):
        projection = row.get("projection_json")
        if not isinstance(projection, dict):
            continue
        if projection.get("kind") == "service_revision":
            revision, changed_at = projection.get("revision"), projection.get("changed_at")
            if isinstance(revision, str) and isinstance(changed_at, str):
                revisions.append({"revision": revision, "changed_at": changed_at})
            continue
        if projection.get("kind") != "metric_series":
            continue
        points = projection.get("points")
        if not isinstance(points, list) or not points:
            continue
        signal_kind = signal_kind or str(projection.get("signal_kind", ""))
        if str(projection.get("signal_kind", "")) != signal_kind:
            # A second signal is a second axis, not more of this one.
            continue
        citations.append(str(row["id"]))
        for point in points:
            if not isinstance(point, dict):
                continue
            observed_at, value = point.get("observed_at"), point.get("value")
            if not isinstance(observed_at, str) or not isinstance(value, int | float):
                continue
            series.append({"observed_at": observed_at, "value": float(value)})
    series.sort(key=lambda point: point["observed_at"])

    markers: list[dict[str, str]] = [
        {
            "kind": "detected",
            "label": "Breach detected",
            "at": incident["detected_at"].astimezone(UTC).isoformat(),
            "committed": "true",
        }
    ]
    # The observed service revision, and when it arrived. This is the marker
    # the design mock called "deploy": it is named for what was observed --
    # Cloud Run reporting that the service last changed -- rather than for a
    # deployment event nobody recorded.
    for observed in {item["changed_at"]: item for item in revisions}.values():
        markers.append(
            {
                "kind": "revision",
                "label": f"revision {observed['revision'].rsplit('/', 1)[-1]}",
                "at": observed["changed_at"],
                "committed": "true",
            }
        )
    for action in action_rows:
        started = action.get("receipt_started_at")
        if started is not None:
            markers.append(
                {
                    "kind": "executed",
                    "label": f"{action['id']} executed",
                    "at": started.astimezone(UTC).isoformat(),
                    "committed": "true",
                }
            )
        elif action.get("created_at") is not None:
            # Proposed and not executed. Drawn dashed, because it has not
            # happened and the axis must not imply that it has.
            markers.append(
                {
                    "kind": "proposed",
                    "label": f"{action['id']} proposed",
                    "at": action["created_at"].astimezone(UTC).isoformat(),
                    "committed": "false",
                }
            )

    band = None
    objective = ""
    if verification is not None:
        band = {
            "start": verification["window_start"].astimezone(UTC).isoformat(),
            "end": verification["window_end"].astimezone(UTC).isoformat(),
            "label": "Verification window",
        }
        for item in json_list(verification.get("required_signals_json")):
            if not isinstance(item, dict):
                continue
            if str(item.get("provider_signal_kind", "")) == signal_kind:
                objective = f"{item.get('comparator', '')} {item.get('threshold', '')}".strip()
                break

    return {
        "signal_kind": signal_kind,
        "points": series,
        "markers": sorted(markers, key=lambda marker: marker["at"]),
        "window_band": band,
        "objective": objective,
        "evidence_refs": citations,
    }
