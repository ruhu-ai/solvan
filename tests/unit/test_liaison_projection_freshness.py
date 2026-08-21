from apps.api.liaison_selection_routes import _record_revision
from apps.api.liaison_service_composition import LiaisonCompositionMixin


def test_versioned_projection_digest_ignores_presentation_clock_drift() -> None:
    first = {
        "id": "INC-1042",
        "machine_id": "inc_11111111111111111111111111",
        "workflow_version": 7,
        "age": "59m",
        "brief": {"customer_window": "Impact has been open for 59m."},
    }
    later = {
        **first,
        "age": "1h",
        "brief": {"customer_window": "Impact has been open for 1h."},
    }

    assert LiaisonCompositionMixin._projection_digest(
        first
    ) == LiaisonCompositionMixin._projection_digest(later)


def test_versioned_projection_digest_changes_with_authoritative_version() -> None:
    first = {
        "machine_id": "inc_11111111111111111111111111",
        "workflow_version": 7,
        "age": "59m",
    }
    changed = {**first, "workflow_version": 8}

    assert LiaisonCompositionMixin._projection_digest(
        first
    ) != LiaisonCompositionMixin._projection_digest(changed)


def test_record_selection_revision_ignores_presentation_clock_drift() -> None:
    first = {"machine_id": "inc_1", "workflow_version": 7, "age": "59m"}
    later = {**first, "age": "1h"}

    assert _record_revision(first) == _record_revision(later)
