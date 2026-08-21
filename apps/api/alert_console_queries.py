"""Query validation and error mapping for the Alert console API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, NoReturn

from fastapi import HTTPException, Request, status

from solvan.application.alert_list import AlertListFilter
from solvan.persistence.alert_policy_errors import AlertPolicyProductError

_ALLOWED_LIST_KEYS = frozenset({"filter", "cursor"})


def validate_alert_list_query(request: Request) -> None:
    for key in request.query_params:
        if key not in _ALLOWED_LIST_KEYS:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "INVALID_ALERT_FILTER")
        if len(request.query_params.getlist(key)) != 1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "INVALID_ALERT_FILTER")


def filter_alert_fixture_rows(
    rows: list[dict[str, Any]], value: AlertListFilter
) -> list[dict[str, Any]]:
    selected = list(rows)
    if value.view == "ACTIVE":
        selected = [
            row
            for row in selected
            if row["investigation_state"]
            in {"OPEN", "WAITING", "TRIAGING", "TRIAGED", "ESCALATED", "ATTACHED"}
        ]
    elif value.view == "NEEDS_REVIEW":
        selected = [row for row in selected if row["required_human_attention"]]
    elif value.view == "INVESTIGATING":
        selected = [
            row for row in selected if row["investigation_state"] in {"WAITING", "TRIAGING"}
        ]
    predicates = (
        (value.severity, "severity"),
        (value.episode_state, "investigation_state"),
        (value.source_provider, "source_provider"),
        (value.connection_id, "connection_id"),
        (value.target_key, "target_key"),
        (value.mode, "mode"),
        (value.provider_state, "provider_state"),
        (value.disposition, "disposition"),
    )
    for accepted, key in predicates:
        if accepted:
            selected = [row for row in selected if row.get(key) in accepted]
    if value.policy_key:
        selected = [
            row
            for row in selected
            if str(row.get("policy", "")).split("@", 1)[0] in value.policy_key
        ]
    if value.incident_link == "LINKED":
        selected = [row for row in selected if row.get("incident") is not None]
    elif value.incident_link == "UNLINKED":
        selected = [row for row in selected if row.get("incident") is None]
    if value.source_time_from:
        selected = [
            row
            for row in selected
            if datetime.fromisoformat(row["last_seen_at"].replace("Z", "+00:00"))
            >= value.source_time_from
        ]
    if value.source_time_to:
        selected = [
            row
            for row in selected
            if datetime.fromisoformat(row["last_seen_at"].replace("Z", "+00:00"))
            < value.source_time_to
        ]
    if value.query:
        selected = [
            row
            for row in selected
            if value.query
            in " ".join(
                str(row.get(key, ""))
                for key in (
                    "title",
                    "target",
                    "target_key",
                    "alert_episode_id",
                    "source_provider",
                    "policy",
                )
            ).casefold()
        ]
    return selected[: value.limit]


def raise_alert_projection_error(error: Exception) -> NoReturn:
    if isinstance(error, ValueError):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "INVALID_ALERT_FILTER") from error
    raise HTTPException(
        status.HTTP_503_SERVICE_UNAVAILABLE, "alert projection is not installed"
    ) from error


def raise_alert_policy_product_error(error: AlertPolicyProductError) -> NoReturn:
    code = str(error)
    if code.endswith("NOT_FOUND"):
        raise HTTPException(404, code) from error
    if code in {"SIMULATION_SCOPE_DENIED", "SIMULATION_CLASSIFICATION_DENIED"}:
        raise HTTPException(403, code) from error
    raise HTTPException(409, code) from error
