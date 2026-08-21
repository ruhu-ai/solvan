from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from solvan.application.saas_scale import (
    PROFILE_CONTROL_POSTURES,
    CapacityEnvelopeEvaluator,
    CapacityReceipt,
    CellDataAccessBroker,
    ControlPosture,
    DeficitRoundRobinScheduler,
    DeploymentProfile,
    OssSingleTenantPlacementProvider,
    Placement,
    QuotaLedger,
    RoutingGrantIssuer,
    ScaleRuntimeError,
    SchedulerItem,
    ServicePoolBudget,
    validate_control_posture,
)
from solvan.application.saas_scale_runtime import LifecycleController

PLACEMENT = Placement(
    organization_id="org-a",
    cell_id="cell-eu-1",
    placement_epoch=7,
    region="europe-west1",
    profile=DeploymentProfile.OSS_SINGLE_TENANT,
)
NOW = datetime(2026, 8, 12, 12, tzinfo=UTC)


def _capacity_receipt(
    ref: str, profile_hash: str, value: int, denominator: int = 1
) -> CapacityReceipt:
    return CapacityReceipt(
        ref,
        profile_hash,
        value,
        NOW,
        NOW + timedelta(minutes=5),
        denominator,
    )


def test_oss_placement_is_startup_bound_and_request_cannot_spoof_tenant() -> None:
    provider = OssSingleTenantPlacementProvider(
        placement=PLACEMENT,
        configured_organizations=("org-a",),
    )
    assert provider.resolve(verified_organization_id="org-a") == PLACEMENT
    with pytest.raises(ScaleRuntimeError):
        provider.resolve(verified_organization_id="org-a", requested_organization_id="org-b")
    with pytest.raises(ScaleRuntimeError):
        provider.resolve(verified_organization_id="org-b")


def test_routing_grant_binds_principal_request_audience_and_epoch() -> None:
    issuer = RoutingGrantIssuer(signing_key=b"test-key")
    request = {"operation": "conversation.turn", "idempotency_key": "abc"}
    grant = issuer.issue(
        placement=PLACEMENT,
        project_id="prj-a",
        environment_id="env-a",
        principal="principal-a",
        request=request,
        audience="cell-api",
        now=NOW,
    )
    issuer.verify(
        grant,
        verified_principal="principal-a",
        request=request,
        expected_placement=PLACEMENT,
        expected_project_id="prj-a",
        expected_environment_id="env-a",
        audience="cell-api",
        now=NOW + timedelta(seconds=30),
    )
    with pytest.raises(ScaleRuntimeError, match="request binding"):
        issuer.verify(
            grant,
            verified_principal="principal-a",
            request={"operation": "other"},
            expected_placement=PLACEMENT,
            expected_project_id="prj-a",
            expected_environment_id="env-a",
            audience="cell-api",
            now=NOW,
        )
    with pytest.raises(ScaleRuntimeError, match="stale"):
        issuer.verify(
            grant,
            verified_principal="principal-a",
            request=request,
            expected_placement=Placement(
                organization_id="org-a",
                cell_id="cell-eu-1",
                placement_epoch=8,
                region="europe-west1",
                profile=DeploymentProfile.OSS_SINGLE_TENANT,
            ),
            expected_project_id="prj-a",
            expected_environment_id="env-a",
            audience="cell-api",
            now=NOW,
        )


def test_quota_reservation_is_idempotent_and_settlement_exact() -> None:
    ledger = QuotaLedger(limits={("org-a", "MODEL_INPUT_TOKEN"): 10})
    expiry = NOW + timedelta(minutes=1)
    first = ledger.reserve(
        reservation_id="res-1",
        organization_id="org-a",
        resource="MODEL_INPUT_TOKEN",
        units=4,
        expires_at=expiry,
        now=NOW,
    )
    assert (
        ledger.reserve(
            reservation_id="res-1",
            organization_id="org-a",
            resource="MODEL_INPUT_TOKEN",
            units=4,
            expires_at=expiry,
            now=NOW,
        )
        == first
    )
    with pytest.raises(ScaleRuntimeError):
        ledger.reserve(
            reservation_id="res-2",
            organization_id="org-a",
            resource="MODEL_INPUT_TOKEN",
            units=7,
            expires_at=expiry,
            now=NOW,
        )
    ledger.settle("res-1", actual_units=2, now=NOW)
    ledger.settle("res-1", actual_units=2, now=NOW)
    with pytest.raises(ScaleRuntimeError, match="different usage"):
        ledger.settle("res-1", actual_units=1, now=NOW)


def test_quota_reservation_race_never_oversubscribes_the_tenant_limit() -> None:
    ledger = QuotaLedger(limits={("org-a", "MODEL_REQUEST"): 4})
    expiry = NOW + timedelta(minutes=1)

    def reserve(index: int) -> bool:
        try:
            ledger.reserve(
                reservation_id=f"race-{index}",
                organization_id="org-a",
                resource="MODEL_REQUEST",
                units=1,
                expires_at=expiry,
                now=NOW,
            )
        except ScaleRuntimeError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = tuple(executor.map(reserve, range(32)))
    assert sum(results) == 4


def test_quota_settlement_cannot_exceed_the_reserved_bound() -> None:
    ledger = QuotaLedger(limits={("org-a", "MODEL_INPUT_TOKEN"): 10})
    with pytest.raises(ValueError, match="reserved bound"):
        ledger.settle(
            ledger.reserve(
                reservation_id="res-bound",
                organization_id="org-a",
                resource="MODEL_INPUT_TOKEN",
                units=2,
                expires_at=NOW + timedelta(minutes=1),
                now=NOW,
            ).reservation_id,
            actual_units=3,
            now=NOW,
        )


def test_scheduler_selects_tenant_before_fifo_work_and_does_not_use_control_reserve() -> None:
    scheduler = DeficitRoundRobinScheduler(
        assured_share={"org-a": 1, "org-b": 1}, control_reserve=2
    )
    scheduler.enqueue(SchedulerItem("org-a", "a1"))
    scheduler.enqueue(SchedulerItem("org-b", "b1"))
    assert scheduler.pop(control=True) is None
    seen = {scheduler.pop().payload, scheduler.pop().payload}  # type: ignore[union-attr]
    assert seen == {"a1", "b1"}


def test_scheduler_control_lane_is_structurally_separate() -> None:
    scheduler = DeficitRoundRobinScheduler(
        assured_share={"org-a": 1}, control_reserve=1, base_quantum=2
    )
    scheduler.enqueue(SchedulerItem("org-a", "ordinary", work_class="INTERACTIVE_ASK"), now=NOW)
    scheduler.enqueue(SchedulerItem("org-a", "reconcile", work_class="RECONCILIATION"), now=NOW)
    # An ordinary pop cannot consume the control lane, and a control pop
    # cannot return ordinary user work.
    ordinary_first = scheduler.pop(now=NOW)
    assert ordinary_first is not None and ordinary_first.payload == "ordinary"
    control = scheduler.pop(control=True, now=NOW)
    assert control is not None and control.payload == "reconcile"
    assert scheduler.pop(now=NOW) is None


def test_scheduler_drops_empty_lane_credit_and_ages_within_tenant() -> None:
    scheduler = DeficitRoundRobinScheduler(
        assured_share={"org-a": 1, "org-b": 1},
        base_quantum=1,
        max_deficit=2,
        maximum_wait_seconds=10,
    )
    # Give org-a several empty rounds; it must not bank enough credit to
    # consume all of org-b's work later.
    for _ in range(4):
        assert scheduler.pop(now=NOW) is None
    scheduler.enqueue(
        SchedulerItem("org-a", "background", cost=2, work_class="BACKGROUND"),
        now=NOW,
    )
    scheduler.enqueue(
        SchedulerItem("org-b", "severe", cost=1, work_class="OPEN_SEVERE"),
        now=NOW,
    )
    first = scheduler.pop(now=NOW)
    assert first is not None and first.payload == "severe"
    # Aged work is selected before a newer lower-priority item in the same
    # tenant, without changing tenant selection order.
    scheduler.enqueue(
        SchedulerItem("org-a", "new-ask", work_class="INTERACTIVE_ASK"),
        now=NOW + timedelta(seconds=11),
    )
    aged = scheduler.pop(now=NOW + timedelta(seconds=11))
    assert aged is not None and aged.payload == "background"


def test_scheduler_rejects_unknown_classes_and_unscoped_tenants() -> None:
    with pytest.raises(ValueError, match="unknown workload class"):
        SchedulerItem("org-a", "bad", work_class="UNKNOWN")
    scheduler = DeficitRoundRobinScheduler(assured_share={"org-a": 1})
    with pytest.raises(ScaleRuntimeError, match="not admitted"):
        scheduler.enqueue(SchedulerItem("org-b", "foreign"), now=NOW)


def test_scheduler_rejects_naive_clock_and_skips_work_above_current_credit() -> None:
    scheduler = DeficitRoundRobinScheduler(assured_share={"org-a": 1}, base_quantum=1)
    with pytest.raises(ValueError, match="timezone-aware"):
        scheduler.enqueue(SchedulerItem("org-a", "work"), now=datetime(2026, 8, 12, 12))
    scheduler.enqueue(SchedulerItem("org-a", "expensive", cost=3), now=NOW)
    with pytest.raises(ValueError, match="timezone-aware"):
        scheduler.pop(now=datetime(2026, 8, 12, 12))
    assert scheduler.pop(now=NOW) is None


def test_quota_expiry_releases_only_expired_reservations() -> None:
    ledger = QuotaLedger(limits={("org-a", "MODEL_REQUEST"): 5})
    ledger.reserve(
        reservation_id="res-expired",
        organization_id="org-a",
        resource="MODEL_REQUEST",
        units=3,
        expires_at=NOW + timedelta(seconds=10),
        now=NOW,
    )
    ledger.reserve(
        reservation_id="res-live",
        organization_id="org-a",
        resource="MODEL_REQUEST",
        units=2,
        expires_at=NOW + timedelta(seconds=30),
        now=NOW,
    )
    assert ledger.release_expired(now=NOW + timedelta(seconds=11)) == ("res-expired",)
    with pytest.raises(ScaleRuntimeError, match="expired"):
        ledger.settle("res-live", actual_units=1, now=NOW + timedelta(seconds=31))


def test_settlement_checks_expiry_on_the_default_clock() -> None:
    """The expiry check used to run only when the caller passed a time.

    Every ordinary `settle(id, actual_units=n)` therefore skipped it, so a
    reservation the expiry sweep had already released could still be settled
    and push the tenant's recorded usage below what it actually holds.
    """

    ledger = QuotaLedger(limits={("org-a", "MODEL_REQUEST"): 5})
    ledger.reserve(
        reservation_id="res-stale",
        organization_id="org-a",
        resource="MODEL_REQUEST",
        units=2,
        expires_at=NOW + timedelta(seconds=30),
        now=NOW,
    )
    with pytest.raises(ScaleRuntimeError, match="expired"):
        ledger.settle("res-stale", actual_units=1)
    # A live reservation still settles on the default clock.
    live = QuotaLedger(limits={("org-a", "MODEL_REQUEST"): 5})
    now = datetime.now(UTC)
    live.reserve(
        reservation_id="res-live",
        organization_id="org-a",
        resource="MODEL_REQUEST",
        units=2,
        expires_at=now + timedelta(minutes=5),
        now=now,
    )
    live.settle("res-live", actual_units=1)


def test_control_polling_does_not_erase_the_ordinary_lanes_credit() -> None:
    """The two lanes kept one deficit counter, so they cleared each other.

    A worker polling the (usually empty) control lane between ordinary polls
    reset the tenant's ordinary deficit to zero every time, and work costing
    more than one quantum could never accumulate enough credit to run — which
    is precisely the starvation deficit round robin exists to prevent.
    """

    scheduler = DeficitRoundRobinScheduler(assured_share={"org-a": 1}, base_quantum=1)
    scheduler.enqueue(SchedulerItem("org-a", "expensive", cost=3), now=NOW)
    for _ in range(2):
        assert scheduler.pop(now=NOW) is None
        assert scheduler.pop(control=True, now=NOW) is None
    item = scheduler.pop(now=NOW)
    assert item is not None and item.payload == "expensive"


def test_shared_cell_broker_refuses_a_grant_minted_for_another_project() -> None:
    """The scope comparison used to be `grant == grant`.

    `open_scope` passed the grant's own project and environment as the values
    to check the grant against, so a validly signed grant for another project
    in the same cell verified and then installed that project's scope on the
    connection.
    """

    placement = Placement(
        organization_id="org-a",
        cell_id="cell-eu-1",
        placement_epoch=7,
        region="europe-west1",
        profile=DeploymentProfile.SHARED_CELL,
    )
    provider = type(
        "Provider",
        (),
        {
            "resolve": lambda self,
            *,
            verified_organization_id,
            requested_organization_id=None: placement
        },
    )()
    issuer = RoutingGrantIssuer(signing_key=b"test-key")
    request = {"operation": "conversation.turn", "idempotency_key": "broker-5"}
    other_project = issuer.issue(
        placement=placement,
        project_id="prj-b",
        environment_id="env-a",
        principal="principal-a",
        request=request,
        audience="cell-api",
        now=NOW,
    )
    with pytest.raises(ScaleRuntimeError, match="scope mismatch"):
        CellDataAccessBroker(
            placement_provider=provider,
            grant_issuer=issuer,
            audience="cell-api",
            database_role="solvan_access_broker",
        ).open_scope(
            object(),
            grant=other_project,
            verified_principal="principal-a",
            request=request,
            verified_organization_id="org-a",
            verified_project_id="prj-a",
            verified_environment_id="env-a",
            now=NOW,
        )


def test_shared_cell_broker_verifies_grant_before_installing_scope() -> None:
    placement = Placement(
        organization_id="org-a",
        cell_id="cell-eu-1",
        placement_epoch=7,
        region="europe-west1",
        profile=DeploymentProfile.SHARED_CELL,
    )
    provider = type(
        "Provider",
        (),
        {
            "resolve": lambda self,
            *,
            verified_organization_id,
            requested_organization_id=None: placement
        },
    )()
    issuer = RoutingGrantIssuer(signing_key=b"test-key")
    request = {"operation": "conversation.turn", "idempotency_key": "broker-1"}
    grant = issuer.issue(
        placement=placement,
        project_id="prj-a",
        environment_id="env-a",
        principal="principal-a",
        request=request,
        audience="cell-api",
        now=NOW,
    )

    class Connection:
        def __init__(self) -> None:
            self.installed = False
            self.reset = False

        def install_routing_session(self, **_: object) -> None:
            self.installed = True

        def set_local_scope(self, *_: object) -> None:
            pass

        def reset_routing_session(self) -> None:
            self.reset = True

    connection = Connection()
    context = CellDataAccessBroker(
        placement_provider=provider,
        grant_issuer=issuer,
        audience="cell-api",
        database_role="solvan_access_broker",
    ).open_scope(
        connection,
        grant=grant,
        verified_principal="principal-a",
        request=request,
        verified_organization_id="org-a",
        verified_project_id="prj-a",
        verified_environment_id="env-a",
        now=NOW,
    )
    with context:
        assert connection.installed
    assert connection.reset


def test_shared_cell_broker_derives_scope_from_signed_grant() -> None:
    placement = Placement(
        organization_id="org-a",
        cell_id="cell-eu-1",
        placement_epoch=7,
        region="europe-west1",
        profile=DeploymentProfile.SHARED_CELL,
    )
    provider = type(
        "Provider",
        (),
        {
            "resolve": lambda self,
            *,
            verified_organization_id,
            requested_organization_id=None: placement
        },
    )()
    issuer = RoutingGrantIssuer(signing_key=b"test-key")
    request = {"operation": "conversation.turn", "idempotency_key": "broker-2"}
    grant = issuer.issue(
        placement=placement,
        project_id="prj-a",
        environment_id="env-a",
        principal="principal-a",
        request=request,
        audience="cell-api",
        now=NOW,
    )

    class Connection:
        def install_routing_session(self, **_: object) -> None:
            pass

        def set_local_scope(self, *scope: object) -> None:
            self.scope = scope

        def reset_routing_session(self) -> None:
            pass

    connection = Connection()
    context = CellDataAccessBroker(
        placement_provider=provider,
        grant_issuer=issuer,
        audience="cell-api",
        database_role="solvan_access_broker",
    ).open_scope(
        connection,
        grant=grant,
        verified_principal="principal-a",
        request=request,
        verified_organization_id="org-a",
        verified_project_id="prj-a",
        verified_environment_id="env-a",
        now=NOW,
    )
    with context:
        assert connection.scope == ("org-a", "prj-a", "env-a")

    with pytest.raises(ScaleRuntimeError, match="organization"):
        CellDataAccessBroker(
            placement_provider=provider,
            grant_issuer=issuer,
            audience="cell-api",
            database_role="solvan_access_broker",
        ).open_scope(
            object(),
            grant=grant,
            verified_principal="principal-a",
            request=request,
            verified_organization_id="org-attacker",
            verified_project_id="prj-a",
            verified_environment_id="env-a",
            now=NOW,
        )


def test_shared_cell_scope_rolls_back_and_resets_on_exception() -> None:
    placement = Placement(
        organization_id="org-a",
        cell_id="cell-eu-1",
        placement_epoch=7,
        region="europe-west1",
        profile=DeploymentProfile.SHARED_CELL,
    )
    provider = type(
        "Provider",
        (),
        {
            "resolve": lambda self,
            *,
            verified_organization_id,
            requested_organization_id=None: placement
        },
    )()
    issuer = RoutingGrantIssuer(signing_key=b"test-key")
    request = {"operation": "conversation.turn", "idempotency_key": "broker-3"}
    grant = issuer.issue(
        placement=placement,
        project_id="prj-a",
        environment_id="env-a",
        principal="principal-a",
        request=request,
        audience="cell-api",
        now=NOW,
    )

    class Connection:
        rolled_back = False
        reset = False

        def install_routing_session(self, **_: object) -> None:
            pass

        def set_local_scope(self, *_: object) -> None:
            pass

        def rollback(self) -> None:
            self.rolled_back = True

        def reset_routing_session(self) -> None:
            self.reset = True

    connection = Connection()
    context = CellDataAccessBroker(
        placement_provider=provider,
        grant_issuer=issuer,
        audience="cell-api",
        database_role="solvan_access_broker",
    ).open_scope(
        connection,
        grant=grant,
        verified_principal="principal-a",
        request=request,
        verified_organization_id="org-a",
        verified_project_id="prj-a",
        verified_environment_id="env-a",
        now=NOW,
    )
    with pytest.raises(RuntimeError, match="boom"), context:
        raise RuntimeError("boom")
    assert connection.rolled_back
    assert connection.reset


def test_shared_cell_scope_resets_when_installation_fails() -> None:
    placement = Placement(
        organization_id="org-a",
        cell_id="cell-eu-1",
        placement_epoch=7,
        region="europe-west1",
        profile=DeploymentProfile.SHARED_CELL,
    )
    provider = type(
        "Provider",
        (),
        {
            "resolve": lambda self,
            *,
            verified_organization_id,
            requested_organization_id=None: placement
        },
    )()
    issuer = RoutingGrantIssuer(signing_key=b"test-key")
    request = {"operation": "conversation.turn", "idempotency_key": "broker-4"}
    grant = issuer.issue(
        placement=placement,
        project_id="prj-a",
        environment_id="env-a",
        principal="principal-a",
        request=request,
        audience="cell-api",
        now=NOW,
    )

    class Connection:
        reset = False

        def install_routing_session(self, **_: object) -> None:
            raise RuntimeError("install failed")

        def reset_routing_session(self) -> None:
            self.reset = True

    connection = Connection()
    context = CellDataAccessBroker(
        placement_provider=provider,
        grant_issuer=issuer,
        audience="cell-api",
        database_role="solvan_access_broker",
    ).open_scope(
        connection,
        grant=grant,
        verified_principal="principal-a",
        request=request,
        verified_organization_id="org-a",
        verified_project_id="prj-a",
        verified_environment_id="env-a",
        now=NOW,
    )
    with pytest.raises(RuntimeError, match="install failed"), context:
        pass
    assert connection.reset


def test_capacity_envelope_requires_fresh_bound_receipts_and_reserves_headroom() -> None:
    profile_hash = "sha256:" + "a" * 64
    evaluator = CapacityEnvelopeEvaluator()
    demand = evaluator.evaluate(
        profile_hash=profile_hash,
        services=(
            ServicePoolBudget("api", max_instances=2, per_instance_pool_max=2),
            ServicePoolBudget("worker", max_instances=1, per_instance_pool_max=1),
        ),
        overshoot=_capacity_receipt("ref_overshoot", profile_hash, 3, 2),
        job_connection_budget=_capacity_receipt("ref_jobs", profile_hash, 1),
        migration_connection_budget=_capacity_receipt("ref_migrations", profile_hash, 1),
        operator_emergency_reserve=_capacity_receipt("ref_reserve", profile_hash, 2),
        qualified_sql_limit=_capacity_receipt("ref_sql", profile_hash, 12),
        now=NOW,
    )
    assert demand == 12
    with pytest.raises(ScaleRuntimeError, match="stale"):
        expiry = NOW + timedelta(minutes=5)
        evaluator.evaluate(
            profile_hash=profile_hash,
            services=(ServicePoolBudget("api", 3, 4),),
            overshoot=_capacity_receipt("ref_overshoot", profile_hash, 3, 2),
            job_connection_budget=_capacity_receipt("ref_jobs", profile_hash, 1),
            migration_connection_budget=_capacity_receipt("ref_migrations", profile_hash, 1),
            operator_emergency_reserve=_capacity_receipt("ref_reserve", profile_hash, 2),
            qualified_sql_limit=_capacity_receipt("ref_sql", profile_hash, 20),
            now=expiry,
        )


def test_capacity_envelope_refuses_saturation_over_the_qualified_limit() -> None:
    profile_hash = "sha256:" + "c" * 64
    evaluator = CapacityEnvelopeEvaluator()
    with pytest.raises(ScaleRuntimeError, match="exceeded"):
        evaluator.evaluate(
            profile_hash=profile_hash,
            services=(ServicePoolBudget("api", max_instances=4, per_instance_pool_max=4),),
            overshoot=_capacity_receipt("ref_overshoot", profile_hash, 1),
            job_connection_budget=_capacity_receipt("ref_jobs", profile_hash, 1),
            migration_connection_budget=_capacity_receipt("ref_migrations", profile_hash, 1),
            operator_emergency_reserve=_capacity_receipt("ref_reserve", profile_hash, 1),
            qualified_sql_limit=_capacity_receipt("ref_sql", profile_hash, 8),
            now=NOW,
        )


def test_every_deployment_profile_retains_the_same_defense_in_depth_controls() -> None:
    postures = tuple(validate_control_posture(profile) for profile in DeploymentProfile)
    assert len(postures) == 3
    assert all(posture == postures[0] for posture in postures)
    assert all(
        all(
            (
                posture.scope_binding,
                posture.rls,
                posture.identity,
                posture.audit,
                posture.quota,
                posture.defense_in_depth,
            )
        )
        for posture in postures
    )
    with pytest.raises(ValueError, match="every deployment profile"):
        ControlPosture(True, True, True, True, True, False)
    assert set(PROFILE_CONTROL_POSTURES) == set(DeploymentProfile)


def test_model_or_request_shaped_values_cannot_become_scale_authority() -> None:
    evaluator = CapacityEnvelopeEvaluator()
    profile_hash = "sha256:" + "b" * 64
    with pytest.raises(ScaleRuntimeError, match="typed application records"):
        evaluator.evaluate(
            profile_hash=profile_hash,
            services=({"service_key": "api"},),  # type: ignore[arg-type]
            overshoot={"value": 1},  # type: ignore[arg-type]
            job_connection_budget={"value": 0},  # type: ignore[arg-type]
            migration_connection_budget={"value": 0},  # type: ignore[arg-type]
            operator_emergency_reserve={"value": 0},  # type: ignore[arg-type]
            qualified_sql_limit={"value": 1},  # type: ignore[arg-type]
            now=NOW,
        )
    with pytest.raises(ScaleRuntimeError, match="typed application records"):
        LifecycleController().transition(  # type: ignore[arg-type]
            {"state": "VERIFYING"},
            expected_from="VERIFYING",
            to_state="BLOCKED",
        )
