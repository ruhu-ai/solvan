"""Target SaaS control-plane and tenant-work repository.

The repository is deliberately thin: identity-derived placement, RLS scope,
fairness, lifecycle transitions, and idempotency remain database predicates or
the typed application services in :mod:`solvan.application.saas_scale`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import uuid4

from psycopg import Connection

from solvan.domain import Scope
from solvan.persistence.saas_scale_capacity import SaaSScaleCapacityMixin


@dataclass(frozen=True, slots=True)
class PlacementRecord:
    organization_id: str
    placement_epoch: int
    cell_id: str
    lifecycle: str
    isolation_tier: str
    home_region: str
    classification_ceiling: str


@dataclass(frozen=True, slots=True)
class LifecycleJobRecord:
    """Content-free durable lifecycle projection from the target schema."""

    organization_id: str
    job_id: str
    job_kind: str
    expected_placement_epoch: int
    source_cell_id: str
    state: str
    destination_cell_id: str | None
    proposed_placement_epoch: int | None
    request_hash: str
    quiesce_receipt_hash: str | None
    source_high_water: int | None
    export_manifest_hash: str | None
    destination_verification_hash: str | None
    isolation_verification_hash: str | None
    cutover_decision_ref: str | None
    completion_proof_hash: str | None
    legal_hold_ref: str | None
    unsettled_mutation_count: int


@dataclass(frozen=True, slots=True)
class RoutingGrantAuditEvent:
    audit_id: str
    grant_jti_hash: str
    outcome: str
    reason_code: str | None
    occurred_at: datetime
    expires_at: datetime


def install_postgres_routing_session(
    connection: Connection[Any],
    *,
    grant_jti: str,
    organization_id: str,
    project_id: str,
    environment_id: str,
    cell_id: str,
    placement_epoch: int,
    database_role: str,
    principal_hash: str,
    request_hash: str,
    audience: str,
    expires_at: datetime,
) -> str:
    """Install one live grant binding in the caller's open transaction.

    The target broker role is the only role allowed to insert this row.  The
    backend PID and transaction ID are read from PostgreSQL itself, never from
    request data, and the context ID is transaction-local and immediately
    installed with ``SET LOCAL`` semantics.
    """

    if placement_epoch < 1 or expires_at.tzinfo is None:
        raise ValueError("routing session operands are invalid")
    context_id = uuid4()
    backend_row = connection.execute("SELECT pg_backend_pid(), pg_current_xact_id()").fetchone()
    if backend_row is None:
        raise RuntimeError("PostgreSQL did not return the live transaction identity")
    backend_pid, transaction_id = backend_row
    grant_jti_hash = "sha256:" + hashlib.sha256(grant_jti.encode("utf-8")).hexdigest()
    audience_hash = "sha256:" + hashlib.sha256(audience.encode("utf-8")).hexdigest()
    # Acceptance is recorded in the same transaction before the live session;
    # the target trigger refuses a session without this non-terminal receipt.
    connection.execute(
        """INSERT INTO solvan_scale.routing_grant_audits
             (audit_id,organization_id,grant_jti_hash,cell_id,placement_epoch,
              principal_hash,request_hash,audience_hash,outcome,occurred_at,expires_at)
           VALUES (%(audit_id)s,%(organization_id)s,%(grant_jti_hash)s,%(cell_id)s,
                   %(placement_epoch)s,%(principal_hash)s,%(request_hash)s,
                   %(audience_hash)s,'ACCEPTED',clock_timestamp(),%(expires_at)s)""",
        {
            "audit_id": f"audit_{uuid4().hex}",
            "organization_id": organization_id,
            "grant_jti_hash": grant_jti_hash,
            "cell_id": cell_id,
            "placement_epoch": placement_epoch,
            "principal_hash": principal_hash,
            "request_hash": request_hash,
            "audience_hash": audience_hash,
            "expires_at": expires_at,
        },
    )
    connection.execute(
        """INSERT INTO solvan_scale.routing_grant_sessions
             (context_id,grant_jti_hash,organization_id,project_id,environment_id,
              cell_id,placement_epoch,database_role,principal_hash,request_hash,
              audience_hash,backend_pid,transaction_id,expires_at)
           VALUES (%(context_id)s,%(grant_jti_hash)s,%(organization_id)s,%(project_id)s,
                   %(environment_id)s,%(cell_id)s,%(placement_epoch)s,%(database_role)s,
                   %(principal_hash)s,%(request_hash)s,%(audience_hash)s,%(backend_pid)s,
                   %(transaction_id)s,%(expires_at)s)""",
        {
            "context_id": context_id,
            "grant_jti_hash": grant_jti_hash,
            "organization_id": organization_id,
            "project_id": project_id,
            "environment_id": environment_id,
            "cell_id": cell_id,
            "placement_epoch": placement_epoch,
            "database_role": database_role,
            "principal_hash": principal_hash,
            "request_hash": request_hash,
            "audience_hash": audience_hash,
            "backend_pid": backend_pid,
            "transaction_id": transaction_id,
            "expires_at": expires_at,
        },
    )
    connection.execute(
        "SELECT set_config('solvan.routing_context_id', %(context_id)s, true)",
        {"context_id": str(context_id)},
    )
    return str(context_id)


def reset_postgres_routing_session(connection: Connection[Any]) -> None:
    """Invalidate the live row and clear the transaction-local context."""

    connection.execute(
        """UPDATE solvan_scale.routing_grant_sessions
              SET invalidated_at=COALESCE(invalidated_at,clock_timestamp())
            WHERE context_id::text = current_setting('solvan.routing_context_id', true)
              AND backend_pid=pg_backend_pid()
              AND transaction_id=pg_current_xact_id()
              AND invalidated_at IS NULL"""
    )
    connection.execute("SELECT set_config('solvan.routing_context_id', '', true)")


class SaaSScaleRepository(SaaSScaleCapacityMixin):
    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def record_grant_audit(
        self,
        *,
        audit_id: str,
        organization_id: str | None,
        grant_jti: str,
        cell_id: str | None,
        placement_epoch: int | None,
        principal_hash: str,
        request_hash: str,
        audience: str,
        outcome: str,
        occurred_at: datetime,
        expires_at: datetime,
        reason_code: str | None = None,
    ) -> RoutingGrantAuditEvent:
        """Append content-free grant history; never persist the JTI itself."""

        if not audit_id.startswith("audit_") or not grant_jti:
            raise ValueError("grant audit identity is invalid")
        if outcome not in {"ISSUED", "ACCEPTED", "DENIED", "EXPIRED", "REVOKED"}:
            raise ValueError("grant audit outcome is closed")
        if outcome in {"ISSUED", "ACCEPTED"} and reason_code is not None:
            raise ValueError("successful grant audit cannot carry a reason")
        if outcome in {"DENIED", "EXPIRED", "REVOKED"} and not reason_code:
            raise ValueError("terminal grant audit requires a reason")
        for value, name in (
            (principal_hash, "principal hash"),
            (request_hash, "request hash"),
        ):
            if not value.startswith("sha256:") or len(value) != 71:
                raise ValueError(f"{name} must be typed")
        if occurred_at.tzinfo is None or expires_at.tzinfo is None or expires_at <= occurred_at:
            raise ValueError("grant audit times are invalid")
        grant_hash = "sha256:" + hashlib.sha256(grant_jti.encode("utf-8")).hexdigest()
        audience_hash = "sha256:" + hashlib.sha256(audience.encode("utf-8")).hexdigest()
        self._connection.execute(
            """INSERT INTO solvan_scale.routing_grant_audits
                 (audit_id,organization_id,grant_jti_hash,cell_id,placement_epoch,
                  principal_hash,request_hash,audience_hash,outcome,reason_code,
                  occurred_at,expires_at)
               VALUES (%(audit_id)s,%(organization_id)s,%(grant_jti_hash)s,%(cell_id)s,
                       %(placement_epoch)s,%(principal_hash)s,%(request_hash)s,
                       %(audience_hash)s,%(outcome)s,%(reason_code)s,%(occurred_at)s,
                       %(expires_at)s)""",
            {
                "audit_id": audit_id,
                "organization_id": organization_id,
                "grant_jti_hash": grant_hash,
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "principal_hash": principal_hash,
                "request_hash": request_hash,
                "audience_hash": audience_hash,
                "outcome": outcome,
                "reason_code": reason_code,
                "occurred_at": occurred_at,
                "expires_at": expires_at,
            },
        )
        return RoutingGrantAuditEvent(
            audit_id, grant_hash, outcome, reason_code, occurred_at, expires_at
        )

    def invalidate_grant_session(self, *, context_id: str, invalidated_at: datetime) -> None:
        """Invalidate a live broker session without exposing its content."""

        if not context_id or invalidated_at.tzinfo is None:
            raise ValueError("live session invalidation is invalid")
        result = self._connection.execute(
            """UPDATE solvan_scale.routing_grant_sessions
                  SET invalidated_at=COALESCE(invalidated_at,%(invalidated_at)s)
                WHERE context_id=%(context_id)s AND invalidated_at IS NULL""",
            {"context_id": context_id, "invalidated_at": invalidated_at},
        )
        if getattr(result, "rowcount", 1) == 0:
            raise RuntimeError("routing grant session is absent or already invalidated")

    def current_placement(self, *, organization_id: str) -> PlacementRecord | None:
        row = self._connection.execute(
            """SELECT organization_id,placement_epoch,cell_id,lifecycle,isolation_tier,
                          home_region,classification_ceiling
                     FROM solvan_scale.tenant_placements
                    WHERE organization_id=%(organization_id)s AND is_current
                    FOR SHARE""",
            {"organization_id": organization_id},
        ).fetchone()
        if row is None:
            return None
        return PlacementRecord(
            organization_id=str(row[0]),
            placement_epoch=int(row[1]),
            cell_id=str(row[2]),
            lifecycle=str(row[3]),
            isolation_tier=str(row[4]),
            home_region=str(row[5]),
            classification_ceiling=str(row[6]),
        )

    def register_work(
        self,
        *,
        scope: Scope,
        work_kind: str,
        work_id: str,
        state: str = "PENDING",
    ) -> None:
        self._connection.execute(
            """INSERT INTO solvan_scale.tenant_work_registry
                 (organization_id,project_id,environment_id,work_kind,work_id,state)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                       %(work_kind)s,%(work_id)s,%(state)s)""",
            {**scope.canonical_dict(), "work_kind": work_kind, "work_id": work_id, "state": state},
        )

    def create_lifecycle_job(
        self,
        *,
        organization_id: str,
        job_id: str,
        job_kind: str,
        expected_placement_epoch: int,
        source_cell_id: str,
        request_hash: str,
    ) -> None:
        """Create one content-free lifecycle job with an immutable request hash."""

        if expected_placement_epoch < 1 or not request_hash.startswith("sha256:"):
            raise ValueError("lifecycle job identity and request hash are invalid")
        self._connection.execute(
            """INSERT INTO solvan_scale.tenant_lifecycle_jobs
                 (organization_id,job_id,job_kind,expected_placement_epoch,source_cell_id,
                  request_hash,state)
               VALUES (%(organization_id)s,%(job_id)s,%(job_kind)s,
                       %(expected_placement_epoch)s,%(source_cell_id)s,
                       %(request_hash)s,'PENDING')""",
            {
                "organization_id": organization_id,
                "job_id": job_id,
                "job_kind": job_kind,
                "expected_placement_epoch": expected_placement_epoch,
                "source_cell_id": source_cell_id,
                "request_hash": request_hash,
            },
        )

    def lifecycle_job(self, *, organization_id: str, job_id: str) -> LifecycleJobRecord | None:
        row = self._connection.execute(
            """SELECT organization_id,job_id,job_kind,expected_placement_epoch,source_cell_id,
                          state,destination_cell_id,proposed_placement_epoch,request_hash,
                          quiesce_receipt_hash,source_high_water,export_manifest_hash,
                          destination_verification_hash,isolation_verification_hash,
                          cutover_decision_ref,completion_proof_hash,legal_hold_ref,
                          unsettled_mutation_count
                     FROM solvan_scale.tenant_lifecycle_jobs
                    WHERE organization_id=%(organization_id)s AND job_id=%(job_id)s
                    FOR SHARE""",
            {"organization_id": organization_id, "job_id": job_id},
        ).fetchone()
        if row is None:
            return None
        return LifecycleJobRecord(
            organization_id=str(row[0]),
            job_id=str(row[1]),
            job_kind=str(row[2]),
            expected_placement_epoch=int(row[3]),
            source_cell_id=str(row[4]),
            state=str(row[5]),
            destination_cell_id=str(row[6]) if row[6] is not None else None,
            proposed_placement_epoch=int(row[7]) if row[7] is not None else None,
            request_hash=str(row[8]),
            quiesce_receipt_hash=str(row[9]) if row[9] is not None else None,
            source_high_water=int(row[10]) if row[10] is not None else None,
            export_manifest_hash=str(row[11]) if row[11] is not None else None,
            destination_verification_hash=str(row[12]) if row[12] is not None else None,
            isolation_verification_hash=str(row[13]) if row[13] is not None else None,
            cutover_decision_ref=str(row[14]) if row[14] is not None else None,
            completion_proof_hash=str(row[15]) if row[15] is not None else None,
            legal_hold_ref=str(row[16]) if row[16] is not None else None,
            unsettled_mutation_count=int(row[17]),
        )

    def enqueue(
        self,
        *,
        scope: Scope,
        work_id: str,
        cell_id: str,
        placement_epoch: int,
        work_kind: str,
        work_class: str,
        resource_kind: str,
        cost_units: int,
        tenant_sequence: int,
        available_at: datetime,
    ) -> None:
        if cost_units < 1 or tenant_sequence < 1:
            raise ValueError("queue cost and tenant sequence must be positive")
        self._connection.execute(
            """INSERT INTO solvan_scale.tenant_dispatch_queue
                 (organization_id,project_id,environment_id,work_id,cell_id,placement_epoch,
                  work_kind,work_class,resource_kind,cost_units,tenant_sequence,state,available_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(work_id)s,
                       %(cell_id)s,%(placement_epoch)s,%(work_kind)s,%(work_class)s,
                       %(resource_kind)s,%(cost_units)s,%(tenant_sequence)s,'QUEUED',
                       %(available_at)s)""",
            {
                **scope.canonical_dict(),
                "work_id": work_id,
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "work_kind": work_kind,
                "work_class": work_class,
                "resource_kind": resource_kind,
                "cost_units": cost_units,
                "tenant_sequence": tenant_sequence,
                "available_at": available_at,
            },
        )

    def transition_lifecycle(
        self,
        *,
        organization_id: str,
        job_id: str,
        expected_from: str,
        to_state: str,
        completion_proof_hash: str | None = None,
    ) -> None:
        if completion_proof_hash is not None and not completion_proof_hash.startswith("sha256:"):
            raise ValueError("lifecycle completion proof must be a typed hash")
        if to_state == "COMPLETED" and expected_from != "CUTOVER_COMMITTED":
            move_row = self._connection.execute(
                """SELECT job_kind FROM solvan_scale.tenant_lifecycle_jobs
                     WHERE organization_id=%(organization_id)s AND job_id=%(job_id)s
                       AND state=%(expected_from)s
                     FOR SHARE""",
                {
                    "organization_id": organization_id,
                    "job_id": job_id,
                    "expected_from": expected_from,
                },
            ).fetchone()
            if move_row is not None and str(move_row[0]) == "MOVE":
                raise ValueError("move completion requires the committed cutover")
        result = self._connection.execute(
            """UPDATE solvan_scale.tenant_lifecycle_jobs
                  SET state=%(to_state)s,
                      completion_proof_hash=COALESCE(%(completion_proof_hash)s,completion_proof_hash),
                      completed_at=CASE WHEN %(to_state)s IN ('COMPLETED','CUTOVER_COMMITTED')
                                        THEN COALESCE(completed_at,now())
                                        ELSE completed_at END
                WHERE organization_id=%(organization_id)s
                  AND job_id=%(job_id)s AND state=%(expected_from)s""",
            {
                "organization_id": organization_id,
                "job_id": job_id,
                "expected_from": expected_from,
                "to_state": to_state,
                "completion_proof_hash": completion_proof_hash,
            },
        )
        rowcount = getattr(result, "rowcount", 1)
        if rowcount == 0:
            raise RuntimeError("lifecycle transition lost its expected state fence")

    def prepare_move(
        self,
        *,
        organization_id: str,
        job_id: str,
        expected_placement_epoch: int,
        destination_cell_id: str,
        proposed_placement_epoch: int,
        quiesce_receipt_hash: str,
        source_high_water: int,
        export_manifest_hash: str,
        destination_verification_hash: str,
        isolation_verification_hash: str,
        cutover_decision_ref: str,
    ) -> None:
        """Persist a verified move cutover with an exact state/epoch fence."""

        hashes = (
            quiesce_receipt_hash,
            export_manifest_hash,
            destination_verification_hash,
            isolation_verification_hash,
        )
        if (
            expected_placement_epoch < 1
            or proposed_placement_epoch <= expected_placement_epoch
            or source_high_water < 0
            or not destination_cell_id
            or not cutover_decision_ref.startswith("ref_")
            or any(not value.startswith("sha256:") for value in hashes)
        ):
            raise ValueError("move cutover operands are invalid")
        result = self._connection.execute(
            """UPDATE solvan_scale.tenant_lifecycle_jobs
                  SET state='CUTOVER_READY',destination_cell_id=%(destination_cell_id)s,
                      proposed_placement_epoch=%(proposed_placement_epoch)s,
                      quiesce_receipt_hash=%(quiesce_receipt_hash)s,
                      source_high_water=%(source_high_water)s,
                      export_manifest_hash=%(export_manifest_hash)s,
                      destination_verification_hash=%(destination_verification_hash)s,
                      isolation_verification_hash=%(isolation_verification_hash)s,
                      cutover_decision_ref=%(cutover_decision_ref)s
                WHERE organization_id=%(organization_id)s AND job_id=%(job_id)s
                  AND expected_placement_epoch=%(expected_placement_epoch)s
                  AND state='VERIFYING'""",
            {
                "organization_id": organization_id,
                "job_id": job_id,
                "expected_placement_epoch": expected_placement_epoch,
                "destination_cell_id": destination_cell_id,
                "proposed_placement_epoch": proposed_placement_epoch,
                "quiesce_receipt_hash": quiesce_receipt_hash,
                "source_high_water": source_high_water,
                "export_manifest_hash": export_manifest_hash,
                "destination_verification_hash": destination_verification_hash,
                "isolation_verification_hash": isolation_verification_hash,
                "cutover_decision_ref": cutover_decision_ref,
            },
        )
        if getattr(result, "rowcount", 1) == 0:
            raise RuntimeError("move cutover lost its state or placement fence")

    def commit_move(
        self,
        *,
        organization_id: str,
        job_id: str,
        cutover_decision_ref: str,
        completion_proof_hash: str,
    ) -> None:
        """Commit exactly the previously prepared cutover decision."""

        if not cutover_decision_ref.startswith("ref_"):
            raise ValueError("cutover decision reference is invalid")
        if not completion_proof_hash.startswith("sha256:"):
            raise ValueError("cutover completion proof must be a typed hash")
        result = self._connection.execute(
            """UPDATE solvan_scale.tenant_lifecycle_jobs
                  SET state='CUTOVER_COMMITTED',completion_proof_hash=%(proof)s,
                      completed_at=now()
                WHERE organization_id=%(organization_id)s AND job_id=%(job_id)s
                  AND state='CUTOVER_READY'
                  AND cutover_decision_ref=%(decision_ref)s""",
            {
                "organization_id": organization_id,
                "job_id": job_id,
                "decision_ref": cutover_decision_ref,
                "proof": completion_proof_hash,
            },
        )
        if getattr(result, "rowcount", 1) == 0:
            raise RuntimeError("move cutover decision is stale or mismatched")

    def record_usage(
        self,
        *,
        scope: Scope,
        event_id: str,
        cell_id: str,
        placement_epoch: int,
        resource_kind: str,
        units: int,
        unit_scale: str,
        source_work_kind: str,
        source_work_id: str,
        event_hash: str,
        occurred_at: datetime,
        provider_key_hash: str | None = None,
    ) -> None:
        if units < 1:
            raise ValueError("usage units must be positive")
        self._connection.execute(
            """INSERT INTO solvan_scale.usage_events
                 (organization_id,event_id,project_id,environment_id,cell_id,placement_epoch,
                  resource_kind,units,unit_scale,source_work_kind,source_work_id,
                  provider_key_hash,occurred_at,event_hash)
               VALUES (%(organization_id)s,%(event_id)s,%(project_id)s,%(environment_id)s,
                       %(cell_id)s,%(placement_epoch)s,%(resource_kind)s,%(units)s,
                       %(unit_scale)s,%(source_work_kind)s,%(source_work_id)s,
                       %(provider_key_hash)s,%(occurred_at)s,%(event_hash)s)""",
            {
                **scope.canonical_dict(),
                "event_id": event_id,
                "cell_id": cell_id,
                "placement_epoch": placement_epoch,
                "resource_kind": resource_kind,
                "units": units,
                "unit_scale": unit_scale,
                "source_work_kind": source_work_kind,
                "source_work_id": source_work_id,
                "provider_key_hash": provider_key_hash,
                "occurred_at": occurred_at,
                "event_hash": event_hash,
            },
        )
