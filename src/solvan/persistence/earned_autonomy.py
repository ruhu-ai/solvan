"""Atomic target-only reservation seam for earned standing autonomy.

The target graph and outcome-quality schemas are not part of the competition
release DDL. This module is consequently not wired into ``ActionStore`` yet;
it is the sole intended application caller once those schemas are promoted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from psycopg import Connection

from solvan.domain import AuthorizedActionMaterial, StandingPreauthorization


@dataclass(frozen=True, slots=True)
class EarnedAutonomyOperands:
    """Immutable operands whose current validity is re-derived in Cloud SQL."""

    material: AuthorizedActionMaterial
    standing_authority: StandingPreauthorization
    cell_id: str
    placement_epoch: int
    reservation_id: str
    competence_receipt_id: str
    capacity_resource_kind: str
    capacity_binding_epoch: int
    capacity_receipt_id: str
    lease_token: UUID
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.placement_epoch < 1 or self.capacity_binding_epoch < 1:
            raise ValueError("earned-autonomy epochs must be positive")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("earned-autonomy reservation expiry must be timezone-aware")
        if self.standing_authority.action_type is not self.material.action_type:
            raise ValueError("standing authority does not cover the exact action class")


@dataclass(frozen=True, slots=True)
class EarnedAutonomyReservation:
    reservation_id: str
    action_id: str
    action_class: str
    target_key: str
    graph_snapshot_id: str
    competence_receipt_id: str
    falsification_sequence_high_water: int
    lease_token: UUID
    expires_at: datetime


def reserve_earned_action(
    connection: Connection[Any], *, operands: EarnedAutonomyOperands
) -> EarnedAutonomyReservation:
    """Atomically revalidate every earned-autonomy fence and reserve the target.

    The caller must invoke this as the first operation of a fresh transaction.
    ``SET TRANSACTION`` deliberately fails if an earlier read made the snapshot
    ambiguous. No Python-side eligibility boolean is accepted by this API.
    """

    connection.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
    return reserve_earned_action_in_transaction(connection, operands=operands)


def reserve_earned_action_in_transaction(
    connection: Connection[Any], *, operands: EarnedAutonomyOperands
) -> EarnedAutonomyReservation:
    """Reserve after the caller made SERIALIZABLE the transaction's first command."""

    scope = operands.material.scope
    connection.execute(
        """SELECT solvan_quality.quality_reserve_earned_action(
              %(organization_id)s,%(project_id)s,%(environment_id)s,%(cell_id)s,
              %(placement_epoch)s,%(reservation_id)s,%(action_id)s,%(action_class)s,
              %(target_key)s,%(preauthorization_id)s,%(preauthorization_version)s,
              %(competence_receipt_id)s,%(capacity_resource_kind)s,
              %(capacity_binding_epoch)s,%(capacity_receipt_id)s,%(lease_token)s,
              %(expires_at)s)""",
        {
            **scope.canonical_dict(),
            "cell_id": operands.cell_id,
            "placement_epoch": operands.placement_epoch,
            "reservation_id": operands.reservation_id,
            "action_id": operands.material.action_id,
            "action_class": operands.material.action_type.value,
            "target_key": operands.material.target_key,
            "preauthorization_id": operands.standing_authority.preauthorization_id,
            "preauthorization_version": operands.standing_authority.version,
            "competence_receipt_id": operands.competence_receipt_id,
            "capacity_resource_kind": operands.capacity_resource_kind,
            "capacity_binding_epoch": operands.capacity_binding_epoch,
            "capacity_receipt_id": operands.capacity_receipt_id,
            "lease_token": operands.lease_token,
            "expires_at": operands.expires_at,
        },
    )
    row = connection.execute(
        """SELECT reservation_id,action_id,action_class,target_key,graph_snapshot_id,
                  competence_receipt_id,falsification_sequence_high_water,lease_token,expires_at
             FROM solvan_quality.earned_action_reservations
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND cell_id=%(cell_id)s
              AND placement_epoch=%(placement_epoch)s AND reservation_id=%(reservation_id)s""",
        {
            **scope.canonical_dict(),
            "cell_id": operands.cell_id,
            "placement_epoch": operands.placement_epoch,
            "reservation_id": operands.reservation_id,
        },
    ).fetchone()
    if row is None:
        raise RuntimeError("earned-autonomy function returned without an exact reservation")
    return EarnedAutonomyReservation(
        reservation_id=str(row[0]),
        action_id=str(row[1]),
        action_class=str(row[2]),
        target_key=str(row[3]),
        graph_snapshot_id=str(row[4]),
        competence_receipt_id=str(row[5]),
        falsification_sequence_high_water=int(row[6]),
        lease_token=row[7],
        expires_at=row[8],
    )
