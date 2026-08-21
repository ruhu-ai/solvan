"""Transactional shared-capacity reservation integration checks."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

from solvan.domain import Scope, new_identifier
from solvan.persistence.saas_scale import SaaSScaleRepository
from solvan.persistence.saas_scale_capacity import CapacityReservationError

DATABASE_URL = os.environ.get("SOLVAN_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(DATABASE_URL is None, reason="requires contract PostgreSQL")
SCOPE = Scope(
    # Contract SQL and integration suites share one clean database in
    # scripts/check-contracts. Keep this suite on its own valid tenant so its
    # rollback-isolated fixture cannot collide with target-schema seed data.
    "org_0000000000000000000000000K",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)


@pytest.fixture
def connection():
    assert DATABASE_URL is not None
    now = datetime.now(UTC)
    with psycopg.connect(DATABASE_URL) as database, database.transaction(force_rollback=True):
        database.execute(
            "INSERT INTO solvan.organizations VALUES (%s,'Capacity',now())",
            (SCOPE.organization_id,),
        )
        database.execute(
            "INSERT INTO solvan.projects VALUES (%s,%s,'Capacity','capacity-gcp',now())",
            (SCOPE.organization_id, SCOPE.project_id),
        )
        database.execute(
            """INSERT INTO solvan.environments
                 (organization_id,project_id,id,display_name,region,classification)
               VALUES (%s,%s,%s,'Capacity','europe-west1','INTERNAL')""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        database.execute(
            """INSERT INTO solvan_scale.cell_eligibility_profiles
                 (eligibility_profile_hash,allowed_classifications,
                  allowed_residency_regions,allowed_provider_launch_stages,
                  encryption_profile_hash,support_access_allowed,
                  allowed_recovery_regions,approved_ref)
               VALUES (%s,ARRAY['INTERNAL'],ARRAY['europe-west1'],ARRAY['GA'],%s,
                       false,ARRAY['europe-west1'],'ref_capacity')""",
            ("sha256:" + "1" * 64, "sha256:" + "2" * 64),
        )
        database.execute(
            """INSERT INTO solvan_scale.cells
                 (cell_id,deployment_profile,region,project_ref,lifecycle,max_organizations,
                  capacity_profile_hash,data_policy_hash,eligibility_profile_hash,
                  deployment_manifest_hash)
               VALUES ('cell_capacity','OSS_SINGLE_TENANT','europe-west1','capacity-gcp',
                       'READY',1,%s,%s,%s,%s)""",
            (
                "sha256:" + "3" * 64,
                "sha256:" + "4" * 64,
                "sha256:" + "1" * 64,
                "sha256:" + "5" * 64,
            ),
        )
        database.execute(
            """INSERT INTO solvan_scale.tenant_eligibility_requirements
                 (organization_id,requirement_hash,allowed_classifications,
                  allowed_residency_regions,allowed_provider_launch_stages,
                  encryption_profile_hash,support_access_allowed,
                  allowed_recovery_regions,approved_ref)
               VALUES (%s,%s,ARRAY['INTERNAL'],ARRAY['europe-west1'],ARRAY['GA'],%s,
                       false,ARRAY['europe-west1'],'ref_capacity_tenant')""",
            (SCOPE.organization_id, "sha256:" + "6" * 64, "sha256:" + "2" * 64),
        )
        database.execute(
            """INSERT INTO solvan_scale.tenant_placements
                 (organization_id,placement_epoch,cell_id,lifecycle,is_current,
                  isolation_tier,home_region,classification_ceiling,
                  eligibility_requirement_hash,policy_hash,encryption_profile_hash,
                  activated_at)
               VALUES (%s,1,'cell_capacity','ACTIVE',true,'OSS_SINGLE_TENANT',
                       'europe-west1','INTERNAL',%s,%s,%s,now())""",
            (
                SCOPE.organization_id,
                "sha256:" + "6" * 64,
                "sha256:" + "7" * 64,
                "sha256:" + "2" * 64,
            ),
        )
        database.execute(
            """INSERT INTO solvan_scale.tenant_quota_policy_revisions
                 (organization_id,version,policy_hash,effective_at,approval_ref)
               VALUES (%s,1,%s,%s,'ref_capacity_policy')""",
            (SCOPE.organization_id, "sha256:" + "8" * 64, now - timedelta(minutes=1)),
        )
        database.execute(
            """INSERT INTO solvan_scale.tenant_quota_policy_bindings
                 (organization_id,binding_epoch,decision,policy_version,decision_ref)
               VALUES (%s,1,'ACTIVATE',1,'ref_capacity_binding')""",
            (SCOPE.organization_id,),
        )
        database.execute(
            """INSERT INTO solvan_scale.tenant_quota_limits
                 (organization_id,policy_version,resource_kind,window_seconds,
                  sustained_limit,burst_limit,maximum_concurrent,exhaustion_behavior)
               VALUES (%s,1,'MODEL_REQUEST',60,10,10,2,'WAIT')""",
            (SCOPE.organization_id,),
        )
        database.execute(
            """INSERT INTO solvan_scale.tenant_quota_counters
                 (organization_id,policy_version,resource_kind,token_nanounits,
                  refill_at,counter_epoch)
               VALUES (%s,1,'MODEL_REQUEST',10000000000,%s,1)""",
            (SCOPE.organization_id, now),
        )
        database.execute(
            """INSERT INTO solvan_scale.cell_capacity_receipts
                 (cell_id,receipt_id,resource_kind,project_ref,region,observed_limit,
                  reserved_headroom,deployment_manifest_hash,source_ref,source_hash,
                  provider_model_resource,provider_endpoint_ref,provider_profile_hash,
                  observed_at,expires_at)
               VALUES ('cell_capacity','cap_model','MODEL_REQUEST','capacity-gcp',
                       'europe-west1',10,1,%s,'ref_capacity_source',%s,
                       'publishers/google/models/gemini-3.1-pro','eu.rep',%s,%s,%s)""",
            (
                "sha256:" + "5" * 64,
                "sha256:" + "9" * 64,
                "sha256:" + "a" * 64,
                now,
                now + timedelta(hours=1),
            ),
        )
        database.execute(
            """INSERT INTO solvan_scale.cell_capacity_bindings
                 (cell_id,resource_kind,binding_epoch,decision,receipt_id,project_ref,
                  region,deployment_manifest_hash,provider_model_resource,
                  provider_endpoint_ref,provider_profile_hash,decision_ref)
               VALUES ('cell_capacity','MODEL_REQUEST',1,'QUALIFY','cap_model',
                       'capacity-gcp','europe-west1',%s,
                       'publishers/google/models/gemini-3.1-pro','eu.rep',%s,
                       'ref_capacity_qualified')""",
            ("sha256:" + "5" * 64, "sha256:" + "a" * 64),
        )
        yield database


def test_reservation_is_atomic_idempotent_and_hash_bound(connection) -> None:
    repository = SaaSScaleRepository(connection)
    work_id = new_identifier("wrk")
    repository.register_work(scope=SCOPE, work_kind="AGENT_RUN", work_id=work_id)
    request_hash = "sha256:" + "b" * 64
    first = repository.reserve_capacity(
        scope=SCOPE,
        work_kind="AGENT_RUN",
        work_id=work_id,
        cell_id="cell_capacity",
        placement_epoch=1,
        resource_kind="MODEL_REQUEST",
        units=1,
        idempotency_key="alert-triage:test",
        request_hash=request_hash,
    )
    replay = repository.reserve_capacity(
        scope=SCOPE,
        work_kind="AGENT_RUN",
        work_id=work_id,
        cell_id="cell_capacity",
        placement_epoch=1,
        resource_kind="MODEL_REQUEST",
        units=1,
        idempotency_key="alert-triage:test",
        request_hash=request_hash,
    )
    assert first.created is True
    assert replay.created is False
    assert replay.reservation_id == first.reservation_id
    assert connection.execute(
        "SELECT count(*) FROM solvan_scale.tenant_capacity_reservations"
    ).fetchone() == (1,)
    with pytest.raises(CapacityReservationError, match="QUOTA_IDEMPOTENCY_CONFLICT"):
        repository.reserve_capacity(
            scope=SCOPE,
            work_kind="AGENT_RUN",
            work_id=work_id,
            cell_id="cell_capacity",
            placement_epoch=1,
            resource_kind="MODEL_REQUEST",
            units=1,
            idempotency_key="alert-triage:test",
            request_hash="sha256:" + "c" * 64,
        )


def test_capacity_exhaustion_returns_closed_wait_outcome(connection) -> None:
    connection.execute(
        """UPDATE solvan_scale.tenant_quota_counters
              SET token_nanounits=0,active_reservations=2,refill_at=clock_timestamp()
            WHERE organization_id=%s AND resource_kind='MODEL_REQUEST'""",
        (SCOPE.organization_id,),
    )
    work_id = new_identifier("wrk")
    repository = SaaSScaleRepository(connection)
    repository.register_work(scope=SCOPE, work_kind="AGENT_RUN", work_id=work_id)
    with pytest.raises(CapacityReservationError) as raised:
        repository.reserve_capacity(
            scope=SCOPE,
            work_kind="AGENT_RUN",
            work_id=work_id,
            cell_id="cell_capacity",
            placement_epoch=1,
            resource_kind="MODEL_REQUEST",
            units=1,
            idempotency_key="alert-triage:wait",
            request_hash="sha256:" + "d" * 64,
        )
    assert raised.value.reason_code == "CENTRAL_CAPACITY_WAIT"
    assert raised.value.retry_at is not None
