from __future__ import annotations

import pytest

from solvan.platform.model_routes import (
    qualified_model_endpoint,
    validate_fast_fleet_route,
)


def test_qualified_routes_bind_exact_jurisdictional_and_global_endpoints() -> None:
    assert (
        qualified_model_endpoint(model="gemini-3.6-flash", location="eu")
        == "https://aiplatform.eu.rep.googleapis.com"
    )
    assert (
        qualified_model_endpoint(model="gemini-3.1-pro-preview", location="global")
        == "https://aiplatform.googleapis.com"
    )


@pytest.mark.parametrize(
    ("model", "location"),
    (
        ("gemini-3.6-flash", "atlantis"),
        ("gemini-3.6-flash", "global"),
        ("gemini-3.1-pro-preview", "eu"),
        ("gemini-3.5-pro", "global"),
    ),
)
def test_unqualified_model_location_pair_is_rejected_before_dispatch(
    model: str, location: str
) -> None:
    with pytest.raises(ValueError, match="not a qualified pair"):
        qualified_model_endpoint(model=model, location=location)


def test_fast_fleet_rejects_global_hostname_even_with_eu_in_resource_path() -> None:
    with pytest.raises(ValueError, match="EU REP endpoint"):
        validate_fast_fleet_route(
            model="gemini-3.6-flash",
            location="eu",
            endpoint="https://aiplatform.googleapis.com",
        )
