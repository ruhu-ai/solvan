from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from solvan.domain import Scope
from solvan.persistence.saas_scale import (
    SaaSScaleRepository,
    install_postgres_routing_session,
    reset_postgres_routing_session,
)
from solvan.persistence.saas_scale_cursors import SaaSScaleCursorRepository


class _Result:
    rowcount = 1

    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row


class _Connection:
    def __init__(self):
        self.calls = []

    def execute(self, statement, params):
        self.calls.append((statement, params))
        if "tenant_placements" in statement and statement.startswith("SELECT"):
            return _Result(
                ("org_1", 2, "cell_1", "ACTIVE", "OSS_SINGLE_TENANT", "europe-west1", "INTERNAL")
            )
        if "tenant_lifecycle_jobs" in statement and statement.startswith("SELECT"):
            return _Result(("MOVE",))
        if "recover_scope_event_cursor" in statement or "advance_scope_event_cursor" in statement:
            return _Result(("cur_reader",))
        return _Result()


def _scope() -> Scope:
    return Scope(
        "org_00000000000000000000000000",
        "prj_00000000000000000000000000",
        "env_00000000000000000000000000",
    )


def test_scale_repository_reads_identity_derived_placement() -> None:
    connection = _Connection()
    placement = SaaSScaleRepository(connection).current_placement(organization_id="org_1")  # type: ignore[arg-type]
    assert placement is not None
    assert placement.home_region == "europe-west1"


def test_scale_queue_refuses_non_positive_cost() -> None:
    repository = SaaSScaleRepository(_Connection())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        repository.enqueue(
            scope=_scope(),
            work_id="wrk_1",
            cell_id="cell_1",
            placement_epoch=1,
            work_kind="CONVERSATION_TURN",
            work_class="INTERACTIVE_ASK",
            resource_kind="MODEL_REQUEST",
            cost_units=0,
            tenant_sequence=1,
            available_at=datetime.now(UTC),
        )


def test_lifecycle_job_creation_binds_request_and_starts_pending() -> None:
    connection = _Connection()
    SaaSScaleRepository(connection).create_lifecycle_job(
        organization_id="org_00000000000000000000000000",
        job_id="job_move_1",
        job_kind="MOVE",
        expected_placement_epoch=7,
        source_cell_id="cell_eu_1",
        request_hash="sha256:" + "a" * 64,
    )
    statement, params = connection.calls[-1]
    assert "tenant_lifecycle_jobs" in statement
    assert "'PENDING'" in statement
    assert params["request_hash"] == "sha256:" + "a" * 64


def test_lifecycle_job_rejects_untyped_request_hash() -> None:
    with pytest.raises(ValueError, match="request hash"):
        SaaSScaleRepository(_Connection()).create_lifecycle_job(
            organization_id="org_00000000000000000000000000",
            job_id="job_move_1",
            job_kind="MOVE",
            expected_placement_epoch=7,
            source_cell_id="cell_eu_1",
            request_hash="not-a-digest",
        )


def test_move_cutover_requires_receipts_and_exact_epoch() -> None:
    connection = _Connection()
    repository = SaaSScaleRepository(connection)
    with pytest.raises(ValueError, match="move cutover"):
        repository.prepare_move(
            organization_id="org_00000000000000000000000000",
            job_id="job_move_1",
            expected_placement_epoch=7,
            destination_cell_id="cell_eu_2",
            proposed_placement_epoch=8,
            quiesce_receipt_hash="bad",
            source_high_water=4,
            export_manifest_hash="sha256:" + "b" * 64,
            destination_verification_hash="sha256:" + "c" * 64,
            isolation_verification_hash="sha256:" + "d" * 64,
            cutover_decision_ref="ref_cutover",
        )
    repository.prepare_move(
        organization_id="org_00000000000000000000000000",
        job_id="job_move_1",
        expected_placement_epoch=7,
        destination_cell_id="cell_eu_2",
        proposed_placement_epoch=8,
        quiesce_receipt_hash="sha256:" + "a" * 64,
        source_high_water=4,
        export_manifest_hash="sha256:" + "b" * 64,
        destination_verification_hash="sha256:" + "c" * 64,
        isolation_verification_hash="sha256:" + "d" * 64,
        cutover_decision_ref="ref_cutover",
    )
    assert "state='CUTOVER_READY'" in connection.calls[-1][0]


def test_move_commit_requires_the_same_decision_reference() -> None:
    connection = _Connection()
    repository = SaaSScaleRepository(connection)
    with pytest.raises(ValueError, match="decision reference"):
        repository.commit_move(
            organization_id="org_00000000000000000000000000",
            job_id="job_move_1",
            cutover_decision_ref="decision-not-ref",
            completion_proof_hash="sha256:" + "e" * 64,
        )
    repository.commit_move(
        organization_id="org_00000000000000000000000000",
        job_id="job_move_1",
        cutover_decision_ref="ref_cutover",
        completion_proof_hash="sha256:" + "e" * 64,
    )
    assert "state='CUTOVER_COMMITTED'" in connection.calls[-1][0]


def test_repository_rejects_move_completion_before_cutover() -> None:
    with pytest.raises(ValueError, match="committed cutover"):
        SaaSScaleRepository(_Connection()).transition_lifecycle(
            organization_id="org_00000000000000000000000000",
            job_id="job_move_1",
            expected_from="VERIFYING",
            to_state="COMPLETED",
            completion_proof_hash="sha256:" + "a" * 64,
        )


def test_repository_routes_cursor_recovery_and_advance_through_target_functions() -> None:
    connection = _Connection()
    repository = SaaSScaleCursorRepository(connection)
    digest = "sha256:" + "a" * 64
    assert (
        repository.recover(
            scope=_scope(),
            cursor_id="cur_reader",
            reader_key_hash=digest,
            cell_id="cell_eu_1",
            placement_epoch=3,
            policy_epoch=4,
            membership_epoch=5,
            scope_sequence=0,
            recovery_receipt_hash=digest,
        )
        == "cur_reader"
    )
    assert (
        repository.advance(
            scope=_scope(),
            cursor_id="cur_reader",
            expected_sequence=0,
            next_sequence=1,
        )
        == "cur_reader"
    )
    assert "recover_scope_event_cursor" in connection.calls[-2][0]
    assert "advance_scope_event_cursor" in connection.calls[-1][0]


def test_repository_refuses_untyped_cursor_operands() -> None:
    repository = SaaSScaleCursorRepository(_Connection())
    digest = "sha256:" + "a" * 64
    with pytest.raises(ValueError, match="reader key hash"):
        repository.recover(
            scope=_scope(),
            cursor_id="cur_reader",
            reader_key_hash="raw-principal",
            cell_id="cell_eu_1",
            placement_epoch=3,
            policy_epoch=4,
            membership_epoch=5,
            scope_sequence=0,
            recovery_receipt_hash=digest,
        )
    with pytest.raises(ValueError, match="cursor sequence"):
        repository.advance(
            scope=_scope(),
            cursor_id="cur_reader",
            expected_sequence=1,
            next_sequence=1,
        )


def test_grant_audit_persists_only_content_free_hashes_and_closed_outcomes() -> None:
    connection = _Connection()
    now = datetime.now(UTC)
    event = SaaSScaleRepository(connection).record_grant_audit(
        audit_id="audit_1",
        organization_id="org_00000000000000000000000000",
        grant_jti="opaque-jti",
        cell_id="cell_eu_1",
        placement_epoch=7,
        principal_hash="sha256:" + "a" * 64,
        request_hash="sha256:" + "b" * 64,
        audience="https://cell.example",
        outcome="DENIED",
        occurred_at=now,
        expires_at=now + timedelta(seconds=1),
        reason_code="STALE_EPOCH",
    )
    assert event.grant_jti_hash.startswith("sha256:")
    statement, params = connection.calls[-1]
    assert "routing_grant_audits" in statement
    assert params["grant_jti_hash"] == event.grant_jti_hash
    assert params["audience_hash"].startswith("sha256:")
    assert "opaque-jti" not in params.values()


def test_grant_audit_requires_reason_for_terminal_outcomes() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="terminal grant audit"):
        SaaSScaleRepository(_Connection()).record_grant_audit(
            audit_id="audit_1",
            organization_id=None,
            grant_jti="opaque-jti",
            cell_id=None,
            placement_epoch=None,
            principal_hash="sha256:" + "a" * 64,
            request_hash="sha256:" + "b" * 64,
            audience="audience",
            outcome="EXPIRED",
            occurred_at=now,
            expires_at=now + timedelta(seconds=1),
        )


def test_postgres_routing_session_binds_database_observed_identity_and_clears_context() -> None:
    class RoutingConnection:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def execute(self, statement: str, params: object = None) -> _Result:
            self.calls.append((statement, params))
            if "pg_backend_pid" in statement:
                return _Result((1234, "42"))
            return _Result()

    connection = RoutingConnection()
    context_id = install_postgres_routing_session(
        connection,  # type: ignore[arg-type]
        grant_jti="opaque-jti",
        organization_id="org_00000000000000000000000000",
        project_id="prj_00000000000000000000000000",
        environment_id="env_00000000000000000000000000",
        cell_id="cell_eu_1",
        placement_epoch=7,
        database_role="solvan_access_broker",
        principal_hash="sha256:" + "a" * 64,
        request_hash="sha256:" + "b" * 64,
        audience="https://cell.example",
        expires_at=datetime.now(UTC) + timedelta(seconds=30),
    )
    assert len(context_id) == 36
    insert_params = connection.calls[2][1]
    assert isinstance(insert_params, dict)
    assert insert_params["backend_pid"] == 1234
    assert insert_params["transaction_id"] == "42"
    assert insert_params["grant_jti_hash"].startswith("sha256:")
    assert "opaque-jti" not in insert_params.values()

    reset_postgres_routing_session(connection)  # type: ignore[arg-type]
    assert "invalidated_at" in connection.calls[-2][0]
    assert "set_config" in connection.calls[-1][0]
