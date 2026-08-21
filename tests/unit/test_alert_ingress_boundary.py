"""The provider push surface must not leak back into the general API."""

from __future__ import annotations

from apps.alert_ingress.main import app as ingress_app
from apps.api.main import create_app

PUSH_PATH = "/api/internal/alert-sources/cloud-monitoring/pubsub-push/{connection_id}"


def _paths(app) -> set[str]:  # type: ignore[no-untyped-def]
    paths: set[str] = set()
    for route in app.routes:
        if hasattr(route, "path"):
            paths.add(route.path)
        original = getattr(route, "original_router", None)
        if original is not None:
            paths.update(child.path for child in original.routes if hasattr(child, "path"))
    return paths


def test_only_the_dedicated_alert_ingress_process_mounts_pubsub_push() -> None:
    assert PUSH_PATH in _paths(ingress_app)
    assert PUSH_PATH not in _paths(create_app())


def test_alert_ingress_exposes_no_operator_or_connection_administration_routes() -> None:
    paths = _paths(ingress_app)
    assert paths <= {PUSH_PATH, "/healthz"}
