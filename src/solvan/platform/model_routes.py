"""Fail-closed model-route contracts for the competition release."""

from __future__ import annotations

FAST_FLEET_MODEL_RESOURCE = "gemini-3.6-flash"
FAST_FLEET_MODEL_LOCATION = "eu"
FAST_FLEET_MODEL_ENDPOINT = "https://aiplatform.eu.rep.googleapis.com"
DEEP_WORKSPACE_MODEL_RESOURCE = "gemini-3.1-pro-preview"
DEEP_WORKSPACE_MODEL_LOCATION = "global"
DEEP_WORKSPACE_MODEL_ENDPOINT = "https://aiplatform.googleapis.com"

_QUALIFIED_MODEL_ROUTES = {
    (FAST_FLEET_MODEL_RESOURCE, FAST_FLEET_MODEL_LOCATION): FAST_FLEET_MODEL_ENDPOINT,
    (DEEP_WORKSPACE_MODEL_RESOURCE, DEEP_WORKSPACE_MODEL_LOCATION): (DEEP_WORKSPACE_MODEL_ENDPOINT),
}


def qualified_model_endpoint(*, model: str, location: str) -> str:
    """Return the exact qualified endpoint or reject the route before dispatch."""

    try:
        return _QUALIFIED_MODEL_ROUTES[(model, location)]
    except KeyError as error:
        raise ValueError("model and inference location are not a qualified pair") from error


def validate_fast_fleet_route(*, model: str, location: str, endpoint: str) -> None:
    """Reject a route that could silently leave the qualified EU inference path."""

    expected = (
        FAST_FLEET_MODEL_RESOURCE,
        FAST_FLEET_MODEL_LOCATION,
        FAST_FLEET_MODEL_ENDPOINT,
    )
    if (model, location, endpoint.rstrip("/")) != expected:
        raise ValueError(
            "release topology fast-fleet inference must use exact gemini-3.6-flash "
            "at the EU REP endpoint"
        )
