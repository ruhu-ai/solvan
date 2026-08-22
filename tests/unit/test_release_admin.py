from __future__ import annotations

import hashlib
import json

import pytest

import tools.release_admin as release_admin
from solvan.domain import Scope
from tests.unit.test_seed_demo import receipt_value
from tools.release_admin import (
    _catalog_publication_transaction,
    _catalog_stage,
    validate_calibration_receipt,
)


class _Context:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *_args: object) -> None:
        return None


class _Connection:
    def __init__(self) -> None:
        self.statements: list[tuple[str, tuple[object, ...] | None]] = []

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def transaction(self) -> _Context:
        return _Context()

    def execute(self, statement: str, parameters: tuple[object, ...] | None = None) -> None:
        self.statements.append((statement, parameters))


def _raw() -> bytes:
    return json.dumps(receipt_value(), default=str, sort_keys=True).encode()


def test_release_admin_binds_seed_to_hash_and_project() -> None:
    raw = _raw()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    receipt, actual = validate_calibration_receipt(
        raw, expected_hash=digest, project_id="solvan-demo"
    )
    assert receipt.project_id == "solvan-demo"
    assert actual == digest


def test_release_admin_rejects_changed_receipt() -> None:
    with pytest.raises(RuntimeError, match="hash"):
        validate_calibration_receipt(
            _raw(), expected_hash="sha256:" + "0" * 64, project_id="solvan-demo"
        )


def test_release_admin_rejects_cross_project_receipt() -> None:
    raw = _raw()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    with pytest.raises(RuntimeError, match="another GCP project"):
        validate_calibration_receipt(raw, expected_hash=digest, project_id="other-project")


def test_catalog_stage_is_derived_from_google_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOLVAN_CLOUD_DEPLOY_EVALUATION_TARGET", "catalog-evaluation")
    monkeypatch.setenv("SOLVAN_CLOUD_DEPLOY_PUBLICATION_TARGET", "catalog-publication")
    monkeypatch.setenv(
        "CLOUD_DEPLOY_TARGET",
        "projects/demo/locations/europe-west1/targets/catalog-evaluation",
    )
    assert _catalog_stage() == "EVALUATION"

    monkeypatch.setenv(
        "CLOUD_DEPLOY_TARGET",
        "projects/demo/locations/europe-west1/targets/catalog-publication",
    )
    assert _catalog_stage() == "PUBLICATION"


def test_catalog_stage_refuses_unknown_google_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOLVAN_CLOUD_DEPLOY_EVALUATION_TARGET", "catalog-evaluation")
    monkeypatch.setenv("SOLVAN_CLOUD_DEPLOY_PUBLICATION_TARGET", "catalog-publication")
    monkeypatch.setenv("CLOUD_DEPLOY_TARGET", "catalog-other")
    with pytest.raises(RuntimeError, match="unknown target"):
        _catalog_stage()


def test_catalog_publication_scope_binding_is_removed_before_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _Connection()
    scope = Scope(
        "org_01M0GSK47F1GQM7ZH77QNKSQAQ",
        "prj_01M0GSK47F5VQ4D2W12Y959N8F",
        "env_01M0GSK47FHBCSJY9BT1VG7SZC",
    )
    monkeypatch.setattr(release_admin, "connect_database", lambda: connection)
    monkeypatch.setattr(
        release_admin,
        "bind_bootstrap_role",
        lambda actual, *, scope: "postgres" if actual is connection else None,
    )

    with _catalog_publication_transaction(scope=scope) as actual:
        assert actual is connection

    assert connection.statements == [
        (
            "DELETE FROM solvan.database_scope_bindings WHERE database_role=%s",
            ("postgres",),
        )
    ]


def test_catalog_publication_failure_relies_on_transaction_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _Connection()
    scope = Scope(
        "org_01M0GSK47F1GQM7ZH77QNKSQAQ",
        "prj_01M0GSK47F5VQ4D2W12Y959N8F",
        "env_01M0GSK47FHBCSJY9BT1VG7SZC",
    )
    monkeypatch.setattr(release_admin, "connect_database", lambda: connection)
    monkeypatch.setattr(release_admin, "bind_bootstrap_role", lambda *_args, **_kwargs: "postgres")

    with (
        pytest.raises(RuntimeError, match="publication failed"),
        _catalog_publication_transaction(scope=scope),
    ):
        raise RuntimeError("publication failed")

    assert connection.statements == []
