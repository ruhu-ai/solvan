"""Target persistence implementations of pre-mutation action gates."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from psycopg import Connection

from solvan.application.action_gates import GraphActionBinding
from solvan.application.actions import ExecutionAuthorization, StandingAuthority
from solvan.domain import ActionPolicyError, AuthorizedActionMaterial, Scope, new_identifier
from solvan.persistence.earned_autonomy import (
    EarnedAutonomyOperands,
    reserve_earned_action_in_transaction,
)
from solvan.persistence.production_graph import CurrentGraphProjection


class ProductionGraphActionGate:
    """Require the exact current, autonomy-eligible graph for standing actions."""

    def __init__(
        self,
        *,
        read_current: Callable[[Scope], CurrentGraphProjection | None],
        resolve_binding: Callable[[Scope, AuthorizedActionMaterial], GraphActionBinding],
    ) -> None:
        self._read_current = read_current
        self._resolve_binding = resolve_binding

    def check(self, *, scope: Scope, authority: ExecutionAuthorization) -> None:
        if not isinstance(authority, StandingAuthority):
            return
        try:
            binding = self._resolve_binding(scope, authority.material)
            current = self._read_current(scope)
        except ActionPolicyError:
            raise
        except Exception as error:
            raise ActionPolicyError("graph_precondition_unavailable") from error
        if current is None:
            raise ActionPolicyError("graph_current_snapshot_missing")
        if not current.autonomy_eligible or current.completeness != "COMPLETE":
            raise ActionPolicyError("graph_not_autonomy_eligible")
        if (current.cell_id, current.placement_epoch) != (
            binding.cell_id,
            binding.placement_epoch,
        ):
            raise ActionPolicyError("graph_placement_changed")
        if current.snapshot_id != binding.snapshot_id:
            raise ActionPolicyError("graph_snapshot_changed")


class PostgresGraphActionBindingResolver:
    """Resolve an action's graph binding from authoritative scoped records."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def __call__(self, scope: Scope, material: AuthorizedActionMaterial) -> GraphActionBinding:
        row = self._connection.execute(
            """SELECT COALESCE(i.production_graph_snapshot_id,
                                c.production_graph_snapshot_id),
                           b.cell_id,b.placement_epoch
                      FROM solvan_graph.graph_scope_bindings b
                 JOIN solvan.actions a
                   ON a.organization_id=%(organization_id)s
                  AND a.project_id=%(project_id)s
                  AND a.environment_id=%(environment_id)s
                  AND a.id=%(action_id)s
                 LEFT JOIN solvan.incidents i
                        ON i.organization_id=%(organization_id)s
                       AND i.project_id=%(project_id)s
                       AND i.environment_id=%(environment_id)s
                       AND i.id=a.incident_id
                 LEFT JOIN solvan.reliability_cases c
                        ON c.organization_id=%(organization_id)s
                       AND c.project_id=%(project_id)s
                       AND c.environment_id=%(environment_id)s
                       AND c.id=a.reliability_case_id
                     WHERE b.organization_id=%(organization_id)s
                       AND b.project_id=%(project_id)s
                       AND b.environment_id=%(environment_id)s
                       AND b.is_current AND b.lifecycle='ACTIVE'""",
            {**scope.canonical_dict(), "action_id": material.action_id},
        ).fetchone()
        if row is None or row[0] is None:
            raise ActionPolicyError("graph_action_binding_missing")
        return GraphActionBinding(
            snapshot_id=str(row[0]),
            cell_id=str(row[1]),
            placement_epoch=int(row[2]),
        )


class PostgresEarnedAutonomyActionGate:
    """Atomically derive and reserve every standing-autonomy operand."""

    def __init__(
        self,
        *,
        connect: Callable[[], Connection[Any]],
    ) -> None:
        self._connect = connect

    def check(self, *, scope: Scope, authority: ExecutionAuthorization) -> None:
        if not isinstance(authority, StandingAuthority):
            return
        try:
            with self._connect() as connection, connection.transaction():
                # This must be the first statement. Eligibility reads and the
                # reservation therefore share one serializable snapshot.
                connection.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                operands = self._load_operands(
                    connection=connection,
                    scope=scope,
                    authority=authority,
                )
                reserve_earned_action_in_transaction(connection, operands=operands)
        except ActionPolicyError:
            raise
        except Exception as error:
            raise ActionPolicyError("earned_autonomy_precondition_failed") from error

    def _load_operands(
        self,
        *,
        connection: Connection[Any],
        scope: Scope,
        authority: StandingAuthority,
    ) -> EarnedAutonomyOperands:
        material = authority.material
        if material.scope != scope:
            raise ActionPolicyError("earned_autonomy_scope_drift")

        existing = connection.execute(
            """SELECT cell_id,placement_epoch,reservation_id,action_class,target_key,
                      standing_preauthorization_id,standing_preauthorization_version,
                      competence_receipt_id,capacity_resource_kind,
                      capacity_binding_epoch,capacity_receipt_id,lease_token,expires_at
                 FROM solvan_quality.earned_action_reservations
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                  AND action_id=%(action_id)s""",
            {**scope.canonical_dict(), "action_id": material.action_id},
        ).fetchone()
        if existing is not None:
            expected = (
                material.action_type.value,
                material.target_key,
                authority.authority.preauthorization_id,
                authority.authority.version,
            )
            if tuple(existing[3:7]) != expected:
                raise ActionPolicyError("earned_autonomy_reservation_material_drift")
            return EarnedAutonomyOperands(
                material=material,
                standing_authority=authority.authority,
                cell_id=str(existing[0]),
                placement_epoch=int(existing[1]),
                reservation_id=str(existing[2]),
                competence_receipt_id=str(existing[7]),
                capacity_resource_kind=str(existing[8]),
                capacity_binding_epoch=int(existing[9]),
                capacity_receipt_id=str(existing[10]),
                lease_token=_require_uuid(existing[11]),
                expires_at=_require_datetime(existing[12]),
            )

        row = connection.execute(
            """SELECT binding.cell_id,binding.placement_epoch,
                      competence.receipt_id,capacity.binding_epoch,
                      capacity.receipt_id,
                      action.expires_at
                 FROM solvan.actions action
                 JOIN solvan_graph.graph_scope_bindings binding
                   ON binding.organization_id=action.organization_id
                  AND binding.project_id=action.project_id
                  AND binding.environment_id=action.environment_id
                  AND binding.is_current AND binding.lifecycle='ACTIVE'
                 LEFT JOIN solvan.incidents incident
                   ON incident.organization_id=action.organization_id
                  AND incident.project_id=action.project_id
                  AND incident.environment_id=action.environment_id
                  AND incident.id=action.incident_id
                 LEFT JOIN solvan.reliability_cases repair_case
                   ON repair_case.organization_id=action.organization_id
                  AND repair_case.project_id=action.project_id
                  AND repair_case.environment_id=action.environment_id
                  AND repair_case.id=action.reliability_case_id
                 JOIN LATERAL (
                   SELECT receipt.receipt_id
                     FROM solvan_quality.autonomy_competence_receipts receipt
                    WHERE receipt.organization_id=action.organization_id
                      AND receipt.project_id=action.project_id
                      AND receipt.environment_id=action.environment_id
                      AND receipt.cell_id=binding.cell_id
                      AND receipt.placement_epoch=binding.placement_epoch
                      AND receipt.action_class=action.action_type
                      AND receipt.graph_snapshot_id=coalesce(
                        incident.production_graph_snapshot_id,
                        repair_case.production_graph_snapshot_id)
                      AND receipt.eligible AND receipt.evidence_expires_at>clock_timestamp()
                    ORDER BY receipt.computed_at DESC,receipt.receipt_id DESC LIMIT 1
                 ) competence ON true
                 JOIN LATERAL (
                   SELECT capacity_binding.binding_epoch,
                          capacity_binding.receipt_id,capacity_binding.decision,
                          capacity_receipt.expires_at
                     FROM solvan_scale.cell_capacity_bindings capacity_binding
                     LEFT JOIN solvan_scale.cell_capacity_receipts capacity_receipt
                       ON capacity_receipt.cell_id=capacity_binding.cell_id
                      AND capacity_receipt.receipt_id=capacity_binding.receipt_id
                    WHERE capacity_binding.cell_id=binding.cell_id
                      AND capacity_binding.resource_kind='CONNECTOR_CALL'
                    ORDER BY capacity_binding.binding_epoch DESC LIMIT 1
                 ) capacity ON capacity.decision='QUALIFY'
                              AND capacity.receipt_id IS NOT NULL
                              AND capacity.expires_at>clock_timestamp()
                WHERE action.organization_id=%(organization_id)s
                  AND action.project_id=%(project_id)s
                  AND action.environment_id=%(environment_id)s
                  AND action.id=%(action_id)s
                  AND action.status='AUTHORIZED'
                  AND action.expires_at>clock_timestamp()""",
            {
                **scope.canonical_dict(),
                "action_id": material.action_id,
            },
        ).fetchone()
        if row is None:
            raise ActionPolicyError("earned_autonomy_operands_unavailable")
        return EarnedAutonomyOperands(
            material=material,
            standing_authority=authority.authority,
            cell_id=str(row[0]),
            placement_epoch=int(row[1]),
            reservation_id=new_identifier("ear"),
            competence_receipt_id=str(row[2]),
            capacity_resource_kind="CONNECTOR_CALL",
            capacity_binding_epoch=int(row[3]),
            capacity_receipt_id=str(row[4]),
            lease_token=uuid4(),
            expires_at=_require_datetime(row[5]),
        )


def _require_uuid(value: object) -> UUID:
    if not isinstance(value, UUID):
        raise ActionPolicyError("earned_autonomy_lease_token_invalid")
    return value


def _require_datetime(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ActionPolicyError("earned_autonomy_expiry_invalid")
    return value
