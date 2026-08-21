"""Transactional tenant-quota and qualified cell-capacity reservations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import ROUND_FLOOR, Decimal
from typing import Any
from uuid import uuid4

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.domain import Scope, new_identifier


class CapacityReservationError(RuntimeError):
    def __init__(self, reason_code: str, *, retry_at: datetime | None = None) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.retry_at = retry_at


@dataclass(frozen=True, slots=True)
class CapacityReservationRecord:
    reservation_id: str
    reservation_token: str
    request_hash: str
    resource_kind: str
    units: int
    expires_at: datetime
    created: bool


class SaaSScaleCapacityMixin:
    _connection: Connection[Any]

    def reserve_capacity(
        self,
        *,
        scope: Scope,
        work_kind: str,
        work_id: str,
        cell_id: str,
        placement_epoch: int,
        resource_kind: str,
        units: int,
        idempotency_key: str,
        request_hash: str,
        ttl_seconds: int = 300,
        capacity_class: str = "ORDINARY",
    ) -> CapacityReservationRecord:
        """Reserve tenant quota and qualified cell capacity under one lock set."""

        if units < 1 or placement_epoch < 1 or not 1 <= ttl_seconds <= 3600:
            raise ValueError("capacity reservation bounds are invalid")
        if capacity_class not in {"ORDINARY", "CONTROL"}:
            raise ValueError("capacity class is closed")
        if not 1 <= len(idempotency_key) <= 128:
            raise ValueError("capacity idempotency key is invalid")
        if not request_hash.startswith("sha256:") or len(request_hash) != 71:
            raise ValueError("capacity request hash must be typed")
        values = {
            **scope.canonical_dict(),
            "work_kind": work_kind,
            "work_id": work_id,
            "cell_id": cell_id,
            "placement_epoch": placement_epoch,
            "resource_kind": resource_kind,
            "units": units,
            "idempotency_key": idempotency_key,
            "request_hash": request_hash,
            "capacity_class": capacity_class,
        }
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT reservation_id,reservation_token,request_hash,resource_kind,
                          units,expires_at
                     FROM solvan_scale.tenant_capacity_reservations
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND resource_kind=%(resource_kind)s
                      AND idempotency_key=%(idempotency_key)s FOR SHARE""",
                values,
            )
            prior = cursor.fetchone()
            if prior is not None:
                if prior["request_hash"] != request_hash:
                    raise CapacityReservationError("QUOTA_IDEMPOTENCY_CONFLICT")
                return _capacity_record(prior, created=False)

            cursor.execute("SELECT clock_timestamp() AS now")
            clock_row = cursor.fetchone()
            if clock_row is None:
                raise CapacityReservationError("DATABASE_CLOCK_UNAVAILABLE")
            database_now = clock_row["now"]
            cursor.execute(
                """SELECT placement.cell_id,placement.placement_epoch
                     FROM solvan_scale.tenant_placements placement
                    WHERE placement.organization_id=%(organization_id)s
                      AND placement.is_current AND placement.lifecycle='ACTIVE'
                      AND placement.cell_id=%(cell_id)s
                      AND placement.placement_epoch=%(placement_epoch)s FOR SHARE""",
                values,
            )
            if cursor.fetchone() is None:
                raise CapacityReservationError("PLACEMENT_STALE")

            cursor.execute(
                """SELECT binding.policy_version,policy.effective_at,policy.expires_at,
                          limit_row.window_seconds,limit_row.sustained_limit,
                          limit_row.burst_limit,limit_row.maximum_concurrent,
                          limit_row.exhaustion_behavior,counter.token_nanounits,
                          counter.refill_remainder,counter.active_reservations,
                          counter.refill_at,counter.counter_epoch
                     FROM solvan_scale.tenant_quota_policy_bindings binding
                     JOIN solvan_scale.tenant_quota_policy_revisions policy
                       ON (policy.organization_id,policy.version)=
                          (binding.organization_id,binding.policy_version)
                     JOIN solvan_scale.tenant_quota_limits limit_row
                       ON (limit_row.organization_id,limit_row.policy_version,
                           limit_row.resource_kind)=
                          (binding.organization_id,binding.policy_version,%(resource_kind)s)
                     JOIN solvan_scale.tenant_quota_counters counter
                       ON (counter.organization_id,counter.policy_version,
                           counter.resource_kind)=
                          (limit_row.organization_id,limit_row.policy_version,
                           limit_row.resource_kind)
                    WHERE binding.organization_id=%(organization_id)s
                      AND binding.binding_epoch=(
                        SELECT max(latest.binding_epoch)
                          FROM solvan_scale.tenant_quota_policy_bindings latest
                         WHERE latest.organization_id=binding.organization_id)
                      AND binding.decision='ACTIVATE'
                    FOR UPDATE OF counter""",
                values,
            )
            quota = cursor.fetchone()
            if (
                quota is None
                or quota["effective_at"] > database_now
                or (quota["expires_at"] is not None and quota["expires_at"] <= database_now)
            ):
                raise CapacityReservationError("QUOTA_POLICY_UNAVAILABLE")

            cursor.execute(
                """SELECT binding.binding_epoch,binding.receipt_id,
                          receipt.observed_limit,receipt.reserved_headroom,receipt.expires_at
                     FROM solvan_scale.cell_capacity_bindings binding
                     JOIN solvan_scale.cell_capacity_receipts receipt
                       ON (receipt.cell_id,receipt.receipt_id,receipt.resource_kind)=
                          (binding.cell_id,binding.receipt_id,binding.resource_kind)
                    WHERE binding.cell_id=%(cell_id)s
                      AND binding.resource_kind=%(resource_kind)s
                      AND binding.binding_epoch=(
                        SELECT max(latest.binding_epoch)
                          FROM solvan_scale.cell_capacity_bindings latest
                         WHERE latest.cell_id=binding.cell_id
                           AND latest.resource_kind=binding.resource_kind)
                      AND binding.decision='QUALIFY'
                    FOR UPDATE OF binding""",
                values,
            )
            capacity = cursor.fetchone()
            if capacity is None or capacity["expires_at"] <= database_now:
                raise CapacityReservationError("CELL_CAPACITY_UNQUALIFIED")

            available_tokens, remainder = _refill_tokens(quota, now=database_now)
            requested_nanounits = units * 1_000_000_000
            cursor.execute(
                """SELECT COALESCE(sum(units),0) AS reserved
                     FROM solvan_scale.tenant_capacity_reservations
                    WHERE cell_id=%(cell_id)s AND resource_kind=%(resource_kind)s
                      AND status IN ('HELD','STARTED') AND expires_at>%(database_now)s""",
                {**values, "database_now": database_now},
            )
            reserved_row = cursor.fetchone()
            if reserved_row is None:
                raise CapacityReservationError("CELL_CAPACITY_UNAVAILABLE")
            reserved_cell_units = int(reserved_row["reserved"])
            cell_ceiling = int(capacity["observed_limit"]) - int(capacity["reserved_headroom"])
            exhausted = (
                available_tokens < requested_nanounits
                or int(quota["active_reservations"]) >= int(quota["maximum_concurrent"])
                or reserved_cell_units + units > cell_ceiling
            )
            if exhausted:
                retry = database_now + timedelta(seconds=max(1, int(quota["window_seconds"])))
                if quota["exhaustion_behavior"] == "WAIT":
                    raise CapacityReservationError("CENTRAL_CAPACITY_WAIT", retry_at=retry)
                raise CapacityReservationError("TRIAGE_CAPACITY_EXHAUSTED")

            reservation_id = new_identifier("res")
            reservation_token = uuid4()
            expires_at = database_now + timedelta(seconds=ttl_seconds)
            cursor.execute(
                """INSERT INTO solvan_scale.tenant_capacity_reservations
                    (organization_id,project_id,environment_id,reservation_id,cell_id,
                     placement_epoch,policy_version,resource_kind,capacity_binding_epoch,
                     capacity_receipt_id,units,work_kind,work_id,idempotency_key,request_hash,
                     reservation_token,capacity_class,status,acquired_at,expires_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                     %(reservation_id)s,%(cell_id)s,%(placement_epoch)s,%(policy_version)s,
                     %(resource_kind)s,%(binding_epoch)s,%(receipt_id)s,%(units)s,
                     %(work_kind)s,%(work_id)s,%(idempotency_key)s,%(request_hash)s,
                     %(reservation_token)s,%(capacity_class)s,'HELD',%(database_now)s,
                     %(expires_at)s)""",
                {
                    **values,
                    "reservation_id": reservation_id,
                    "policy_version": quota["policy_version"],
                    "binding_epoch": capacity["binding_epoch"],
                    "receipt_id": capacity["receipt_id"],
                    "reservation_token": reservation_token,
                    "database_now": database_now,
                    "expires_at": expires_at,
                },
            )
            cursor.execute(
                """UPDATE solvan_scale.tenant_quota_counters
                      SET token_nanounits=%(tokens)s,refill_remainder=%(remainder)s,
                          active_reservations=active_reservations+1,
                          refill_at=%(database_now)s,counter_epoch=counter_epoch+1
                    WHERE organization_id=%(organization_id)s
                      AND policy_version=%(policy_version)s
                      AND resource_kind=%(resource_kind)s
                      AND counter_epoch=%(counter_epoch)s""",
                {
                    **values,
                    "policy_version": quota["policy_version"],
                    "counter_epoch": quota["counter_epoch"],
                    "tokens": available_tokens - requested_nanounits,
                    "remainder": remainder,
                    "database_now": database_now,
                },
            )
            if cursor.rowcount != 1:
                raise CapacityReservationError("QUOTA_COUNTER_STALE")
        return CapacityReservationRecord(
            reservation_id,
            str(reservation_token),
            request_hash,
            resource_kind,
            units,
            expires_at,
            True,
        )


def _refill_tokens(row: dict[str, Any], *, now: datetime) -> tuple[int, int]:
    elapsed_ns = max(0, int((now - row["refill_at"]).total_seconds() * 1_000_000_000))
    numerator = Decimal(elapsed_ns) * Decimal(int(row["sustained_limit"])) + Decimal(
        int(row["refill_remainder"])
    )
    denominator = Decimal(int(row["window_seconds"]))
    refill = int((numerator / denominator).to_integral_value(rounding=ROUND_FLOOR))
    remainder = int(numerator % denominator)
    ceiling = int(row["burst_limit"]) * 1_000_000_000
    return min(ceiling, int(row["token_nanounits"]) + refill), remainder


def _capacity_record(row: dict[str, Any], *, created: bool) -> CapacityReservationRecord:
    return CapacityReservationRecord(
        str(row["reservation_id"]),
        str(row["reservation_token"]),
        str(row["request_hash"]),
        str(row["resource_kind"]),
        int(row["units"]),
        row["expires_at"],
        created,
    )
