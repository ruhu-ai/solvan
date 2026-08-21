"""Provider-independent runtime controls for the SaaS target profiles.

These controls are intentionally small and typed.  Cloud SQL procedures and
the Cell Data Access Broker remain the authority in a deployed shared cell;
this module is the deterministic admission/scheduling seam used by the OSS
profile, local integration tests, and the eventual broker adapter.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections import defaultdict
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import RLock
from typing import Any, Protocol


class ScaleRuntimeError(RuntimeError):
    pass


# Re-export the scheduler types from the application boundary while keeping
# the broker/quota module below the architecture size ceiling.
from solvan.application.saas_scale_scheduling import (  # noqa: E402,F401
    DeficitRoundRobinScheduler,
    SchedulerItem,
)


class DeploymentProfile(StrEnum):
    OSS_SINGLE_TENANT = "OSS_SINGLE_TENANT"
    SHARED_CELL = "SHARED_CELL"
    DEDICATED_CELL = "DEDICATED_CELL"


from solvan.application.saas_scale_profiles import (  # noqa: E402,F401
    PROFILE_CONTROL_POSTURES,
    ControlPosture,
    validate_control_posture,
)


@dataclass(frozen=True, slots=True)
class Placement:
    organization_id: str
    cell_id: str
    placement_epoch: int
    region: str
    profile: DeploymentProfile
    lifecycle: str = "ACTIVE"

    def __post_init__(self) -> None:
        if not self.organization_id or not self.cell_id or self.placement_epoch < 1:
            raise ValueError("placement identity and epoch are required")
        if not self.region:
            raise ValueError("placement region is required")
        if self.lifecycle != "ACTIVE":
            raise ValueError("ordinary runtime placement must be ACTIVE")


class PlacementProvider(Protocol):
    def resolve(
        self, *, verified_organization_id: str, requested_organization_id: str | None = None
    ) -> Placement: ...


class OssSingleTenantPlacementProvider:
    """Startup-bound placement with no request-controlled tenant selector."""

    def __init__(self, *, placement: Placement, configured_organizations: tuple[str, ...]) -> None:
        if placement.profile is not DeploymentProfile.OSS_SINGLE_TENANT:
            raise ValueError("OSS provider requires OSS_SINGLE_TENANT placement")
        if (
            len(configured_organizations) != 1
            or configured_organizations[0] != placement.organization_id
        ):
            raise ValueError("OSS_SINGLE_TENANT must bind exactly one organization")
        self._placement = placement

    def resolve(
        self, *, verified_organization_id: str, requested_organization_id: str | None = None
    ) -> Placement:
        if requested_organization_id is not None:
            raise ScaleRuntimeError("request cannot select organization placement")
        if verified_organization_id != self._placement.organization_id:
            raise ScaleRuntimeError("verified identity is not bound to this OSS installation")
        return self._placement


@dataclass(frozen=True, slots=True)
class CellRoutingGrant:
    organization_id: str
    project_id: str
    environment_id: str
    cell_id: str
    placement_epoch: int
    region: str
    principal_hash: str
    request_hash: str
    audience: str
    issued_at: datetime
    expires_at: datetime
    jti: str
    signature: str

    def unsigned(self) -> dict[str, Any]:
        return {
            "organization_id": self.organization_id,
            "project_id": self.project_id,
            "environment_id": self.environment_id,
            "cell_id": self.cell_id,
            "placement_epoch": self.placement_epoch,
            "region": self.region,
            "principal_hash": self.principal_hash,
            "request_hash": self.request_hash,
            "audience": self.audience,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "jti": self.jti,
        }


class RoutingGrantIssuer:
    def __init__(self, *, signing_key: bytes, max_ttl_seconds: int = 60) -> None:
        if not signing_key or not 1 <= max_ttl_seconds <= 60:
            raise ValueError("routing grant signing key and <=60s TTL are required")
        self._key = signing_key
        self._max_ttl = max_ttl_seconds

    def issue(
        self,
        *,
        placement: Placement,
        project_id: str,
        environment_id: str,
        principal: str,
        request: Mapping[str, Any],
        audience: str,
        now: datetime | None = None,
    ) -> CellRoutingGrant:
        issued = now or datetime.now(UTC)
        if issued.tzinfo is None or issued.utcoffset() is None:
            raise ValueError("grant time must be timezone-aware")
        request_json = json.dumps(dict(request), sort_keys=True, separators=(",", ":"), default=str)
        unsigned = CellRoutingGrant(
            organization_id=placement.organization_id,
            project_id=_required_scope_part(project_id, "project_id"),
            environment_id=_required_scope_part(environment_id, "environment_id"),
            cell_id=placement.cell_id,
            placement_epoch=placement.placement_epoch,
            region=placement.region,
            principal_hash=_sha(principal),
            request_hash=_sha(request_json),
            audience=audience,
            issued_at=issued,
            expires_at=issued + timedelta(seconds=self._max_ttl),
            jti=secrets.token_hex(16),
            signature="",
        )
        return CellRoutingGrant(
            organization_id=unsigned.organization_id,
            project_id=unsigned.project_id,
            environment_id=unsigned.environment_id,
            cell_id=unsigned.cell_id,
            placement_epoch=unsigned.placement_epoch,
            region=unsigned.region,
            principal_hash=unsigned.principal_hash,
            request_hash=unsigned.request_hash,
            audience=unsigned.audience,
            issued_at=unsigned.issued_at,
            expires_at=unsigned.expires_at,
            jti=unsigned.jti,
            signature=self._sign(unsigned),
        )

    def verify(
        self,
        grant: CellRoutingGrant,
        *,
        verified_principal: str,
        request: Mapping[str, Any],
        expected_placement: Placement,
        expected_project_id: str,
        expected_environment_id: str,
        audience: str,
        now: datetime | None = None,
        revoked_jtis: Collection[str] = frozenset(),
    ) -> None:
        current = now or datetime.now(UTC)
        if grant.jti in revoked_jtis:
            raise ScaleRuntimeError("routing grant is revoked")
        if not hmac.compare_digest(grant.signature.encode(), self._sign(grant).encode()):
            raise ScaleRuntimeError("routing grant signature is invalid")
        if grant.audience != audience or grant.expires_at <= current or grant.issued_at > current:
            raise ScaleRuntimeError("routing grant audience or expiry is invalid")
        if grant.expires_at - grant.issued_at > timedelta(seconds=self._max_ttl):
            raise ScaleRuntimeError("routing grant TTL exceeds policy")
        if grant.unsigned()["organization_id"] != expected_placement.organization_id:
            raise ScaleRuntimeError("routing grant organization mismatch")
        if (grant.project_id, grant.environment_id) != (
            _required_scope_part(expected_project_id, "project_id"),
            _required_scope_part(expected_environment_id, "environment_id"),
        ):
            raise ScaleRuntimeError("routing grant scope mismatch")
        if (grant.cell_id, grant.placement_epoch, grant.region) != (
            expected_placement.cell_id,
            expected_placement.placement_epoch,
            expected_placement.region,
        ):
            raise ScaleRuntimeError("routing grant placement is stale")
        request_json = json.dumps(dict(request), sort_keys=True, separators=(",", ":"), default=str)
        if grant.principal_hash != _sha(verified_principal) or grant.request_hash != _sha(
            request_json
        ):
            raise ScaleRuntimeError("routing grant principal or request binding mismatch")

    def _sign(self, grant: CellRoutingGrant) -> str:
        body = json.dumps(grant.unsigned(), sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._key, body, hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class QuotaReservation:
    reservation_id: str
    organization_id: str
    resource: str
    units: int
    expires_at: datetime
    request_hash: str | None = None


@dataclass(frozen=True, slots=True)
class CapacityReceipt:
    """One immutable, expiring input to the deployment capacity equation."""

    receipt_id: str
    profile_hash: str
    value: int
    observed_at: datetime
    expires_at: datetime
    denominator: int = 1

    def __post_init__(self) -> None:
        if not self.receipt_id.startswith("ref_"):
            raise ValueError("capacity receipt id must be a typed reference")
        if not self.profile_hash.startswith("sha256:") or len(self.profile_hash) != 71:
            raise ValueError("capacity profile hash must be typed")
        if self.value < 0 or self.denominator <= 0 or self.expires_at <= self.observed_at:
            raise ValueError("capacity receipt value or lifetime is invalid")
        if self.observed_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("capacity receipt times must be timezone-aware")


@dataclass(frozen=True, slots=True)
class ServicePoolBudget:
    """Bounded Cloud Run instance/pool operands from one cell manifest."""

    service_key: str
    max_instances: int
    per_instance_pool_max: int

    def __post_init__(self) -> None:
        if not self.service_key or self.max_instances < 0 or self.per_instance_pool_max < 0:
            raise ValueError("service pool budget is invalid")


class CapacityEnvelopeEvaluator:
    """Fail-closed evaluator for the qualified SQL connection envelope."""

    def evaluate(
        self,
        *,
        profile_hash: str,
        services: Collection[ServicePoolBudget],
        overshoot: CapacityReceipt,
        job_connection_budget: CapacityReceipt,
        migration_connection_budget: CapacityReceipt,
        operator_emergency_reserve: CapacityReceipt,
        qualified_sql_limit: CapacityReceipt,
        now: datetime,
    ) -> int:
        if now.tzinfo is None or not profile_hash.startswith("sha256:"):
            raise ScaleRuntimeError("capacity profile is absent or invalid")
        if not services:
            raise ScaleRuntimeError("capacity service pool profile is absent")
        if any(not isinstance(item, ServicePoolBudget) for item in services):
            raise ScaleRuntimeError("capacity operands must be typed application records")
        receipts = (
            overshoot,
            job_connection_budget,
            migration_connection_budget,
            operator_emergency_reserve,
            qualified_sql_limit,
        )
        for receipt in receipts:
            if not isinstance(receipt, CapacityReceipt):
                raise ScaleRuntimeError("capacity operands must be typed application records")
            if receipt.profile_hash != profile_hash or receipt.expires_at <= now:
                raise ScaleRuntimeError("capacity receipt is missing, stale, or mismatched")
        if overshoot.value < overshoot.denominator:
            raise ScaleRuntimeError("overshoot receipt must be at least one")
        if any(receipt.denominator != 1 for receipt in receipts[1:]):
            raise ScaleRuntimeError("capacity budget receipts must be integer units")
        numerator = sum(item.max_instances * item.per_instance_pool_max for item in services)
        service_demand = (
            numerator * overshoot.value + overshoot.denominator - 1
        ) // overshoot.denominator
        demand = (
            service_demand
            + job_connection_budget.value
            + migration_connection_budget.value
            + operator_emergency_reserve.value
        )
        if demand > qualified_sql_limit.value:
            raise ScaleRuntimeError("qualified SQL capacity envelope is exceeded")
        return demand


class QuotaLedger:
    """Idempotent in-memory model of the SQL reservation/settlement contract."""

    def __init__(self, *, limits: Mapping[tuple[str, str], int]) -> None:
        self._limits = dict(limits)
        self._used: defaultdict[tuple[str, str], int] = defaultdict(int)
        self._reservations: dict[str, QuotaReservation] = {}
        self._settled: dict[str, int] = {}
        self._lock = RLock()

    def reserve(
        self,
        *,
        reservation_id: str,
        organization_id: str,
        resource: str,
        units: int,
        expires_at: datetime,
        request_hash: str | None = None,
        now: datetime | None = None,
    ) -> QuotaReservation:
        current = now or datetime.now(UTC)
        if (
            units <= 0
            or expires_at.tzinfo is None
            or current.tzinfo is None
            or expires_at <= current
        ):
            raise ValueError("quota reservation operands are invalid")
        with self._lock:
            existing = self._reservations.get(reservation_id)
            if existing is not None:
                if existing != QuotaReservation(
                    reservation_id, organization_id, resource, units, expires_at, request_hash
                ):
                    raise ScaleRuntimeError("reservation id was reused with different operands")
                return existing
            key = (organization_id, resource)
            limit = self._limits.get(key)
            if limit is None or self._used[key] + units > limit:
                raise ScaleRuntimeError("tenant quota exhausted")
            result = QuotaReservation(
                reservation_id, organization_id, resource, units, expires_at, request_hash
            )
            self._reservations[reservation_id] = result
            self._used[key] += units
            return result

    def settle(
        self, reservation_id: str, *, actual_units: int, now: datetime | None = None
    ) -> None:
        # The clock defaults exactly as `reserve` does. Checking expiry only
        # when the caller happened to pass a time made the control optional:
        # every ordinary `settle(id, actual_units=n)` skipped it, so a
        # reservation already released by `release_expired` could still be
        # settled and drive the tenant's usage below what it holds.
        current = now or datetime.now(UTC)
        with self._lock:
            reservation = self._reservations.get(reservation_id)
            if reservation is None:
                raise ScaleRuntimeError("unknown quota reservation")
            settled_units = self._settled.get(reservation_id)
            if settled_units is not None:
                if settled_units != actual_units:
                    raise ScaleRuntimeError("quota settlement was replayed with different usage")
                return
            if current >= reservation.expires_at:
                raise ScaleRuntimeError("quota reservation expired before settlement")
            if actual_units < 0 or actual_units > reservation.units:
                raise ValueError("settled units must be within the reserved bound")
            key = (reservation.organization_id, reservation.resource)
            self._used[key] += actual_units - reservation.units
            if self._used[key] < 0:
                raise ScaleRuntimeError("quota settlement would underflow")
            self._settled[reservation_id] = actual_units

    def release_expired(self, *, now: datetime | None = None) -> tuple[str, ...]:
        """Release only reservations whose expiry is authoritative and reached."""

        current = now or datetime.now(UTC)
        with self._lock:
            released: list[str] = []
            for reservation_id, reservation in tuple(self._reservations.items()):
                if reservation_id in self._settled or reservation.expires_at > current:
                    continue
                key = (reservation.organization_id, reservation.resource)
                self._used[key] -= reservation.units
                if self._used[key] < 0:
                    raise ScaleRuntimeError("quota expiry would underflow")
                self._settled[reservation_id] = 0
                released.append(reservation_id)
            return tuple(released)


class CellDataAccessBroker:
    """Shared-cell SQL entry boundary; request data never selects a tenant."""

    def __init__(
        self,
        *,
        placement_provider: PlacementProvider,
        grant_issuer: RoutingGrantIssuer,
        audience: str,
        database_role: str,
        session_installer: Callable[..., None] | None = None,
        session_resetter: Callable[[Any], None] | None = None,
    ) -> None:
        if not audience or not database_role:
            raise ValueError("broker audience and database role are required")
        self._placements = placement_provider
        self._grants = grant_issuer
        self._audience = audience
        self._database_role = database_role
        self._session_installer = session_installer
        self._session_resetter = session_resetter

    def open_scope(
        self,
        connection: Any,
        *,
        grant: CellRoutingGrant,
        verified_principal: str,
        request: Mapping[str, Any],
        verified_organization_id: str,
        verified_project_id: str,
        verified_environment_id: str,
        now: datetime | None = None,
    ) -> TenantConnectionContext:
        """Open one transaction-local tenant scope from verified identity.

        The three ``verified_*`` scope parts come from the caller's verified
        cryptographic claims, never from the request body, a header, or the
        grant being checked. They used to be taken from the grant's own fields,
        which turned `verify`'s scope comparison into `grant == grant`: a grant
        minted for another project inside the same cell verified perfectly and
        then installed that other project's scope on the connection.
        """

        placement = self._placements.resolve(verified_organization_id=verified_organization_id)
        self._grants.verify(
            grant,
            verified_principal=verified_principal,
            request=request,
            expected_placement=placement,
            expected_project_id=verified_project_id,
            expected_environment_id=verified_environment_id,
            audience=self._audience,
            now=now,
        )
        if placement.profile is not DeploymentProfile.SHARED_CELL:
            raise ScaleRuntimeError("shared-cell broker cannot open a non-shared placement")
        if grant.organization_id != verified_organization_id:
            raise ScaleRuntimeError("routing grant organization does not match verified identity")

        def install(opened: Any) -> None:
            installer = getattr(opened, "install_routing_session", None)
            operands: dict[str, Any] = {
                "grant_jti": grant.jti,
                "organization_id": grant.organization_id,
                "project_id": grant.project_id,
                "environment_id": grant.environment_id,
                "cell_id": placement.cell_id,
                "placement_epoch": placement.placement_epoch,
                "database_role": self._database_role,
                "principal_hash": grant.principal_hash,
                "request_hash": grant.request_hash,
                "audience": grant.audience,
                "expires_at": grant.expires_at,
            }
            if callable(installer):
                installer(**operands)
                return
            if self._session_installer is None:
                raise ScaleRuntimeError("shared-cell broker has no session installer")
            self._session_installer(opened, **operands)

        def reset(opened: Any) -> None:
            resetter = getattr(opened, "reset_routing_session", None)
            if callable(resetter):
                resetter()
                return
            if self._session_resetter is None:
                raise ScaleRuntimeError("shared-cell broker has no session resetter")
            self._session_resetter(opened)

        return TenantConnectionContext(
            connection,
            organization_id=grant.organization_id,
            project_id=grant.project_id,
            environment_id=grant.environment_id,
            install=install,
            reset=reset,
        )


class TenantConnectionContext:
    """Transaction-local scope context; reset always runs on exit."""

    def __init__(
        self,
        connection: Any,
        *,
        organization_id: str,
        project_id: str,
        environment_id: str,
        install: Callable[[Any], None],
        reset: Callable[[Any], None],
    ) -> None:
        self.connection = connection
        self.scope = (organization_id, project_id, environment_id)
        self._install = install
        self._reset = reset

    def __enter__(self) -> Any:
        try:
            # Installation must happen after the caller has entered its
            # transaction.  A session binding created outside that transaction
            # could otherwise be reused by a later pooled connection.
            self._install(self.connection)
            set_local_scope = getattr(self.connection, "set_local_scope", None)
            if callable(set_local_scope):
                set_local_scope(*self.scope)
            return self.connection
        except BaseException:
            self._reset(self.connection)
            raise

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        try:
            if exc_type is not None:
                rollback = getattr(self.connection, "rollback", None)
                if callable(rollback):
                    rollback()
        finally:
            # Reset is unconditional: a successful transaction can still have
            # session-local state, and an exception must never return a dirty
            # connection to the shared pool.
            self._reset(self.connection)


def _sha(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _required_scope_part(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        raise ValueError(f"{name} is required and bounded")
    return value
