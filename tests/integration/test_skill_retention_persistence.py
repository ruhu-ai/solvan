"""Skill retention claim and settlement contracts against real PostgreSQL 16."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

from solvan.application.skills_retention import execute_due_deletions
from solvan.domain import Scope
from solvan.persistence.skills_retention_store import PostgresSkillRetentionRepository

DATABASE_URL = os.environ.get("SOLVAN_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(DATABASE_URL is None, reason="requires contract PostgreSQL")
SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
REGION = "europe-west1"
OBJECT_ID = "obj_retention_1"
OBJECT_URI = "gs://skills-test/retention/source.bin"
GENERATION = "7"


@pytest.fixture
def connection():
    assert DATABASE_URL is not None
    with (
        psycopg.connect(DATABASE_URL) as database,
        database.transaction(force_rollback=True),
    ):
        database.execute(
            """INSERT INTO solvan.organizations(id,display_name)
               VALUES (%s,'Test') ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id,),
        )
        database.execute(
            """INSERT INTO solvan.projects
                 (organization_id,id,display_name,gcp_project_id)
               VALUES (%s,%s,'Test','solvan-test') ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id),
        )
        database.execute(
            """INSERT INTO solvan.environments
                 (organization_id,project_id,id,display_name,region,classification)
               VALUES (%s,%s,%s,'Test','europe-west1','INTERNAL')
               ON CONFLICT DO NOTHING""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        yield database


class _MemoryObjectDeleter:
    """Mirror of GcsEvidenceDeleter semantics: 404 is idempotent success."""

    def __init__(self, objects: dict[str, str]) -> None:
        self.objects = objects
        self.calls: list[tuple[str, str | None]] = []

    def delete(self, *, uri: str, expected_generation: str | None = None) -> str:
        self.calls.append((uri, expected_generation))
        generation = self.objects.get(uri)
        if generation is None:
            return f"{uri}#deleted-status=404"
        if expected_generation is not None and generation != expected_generation:
            raise RuntimeError("object generation does not match the durable ledger")
        del self.objects[uri]
        return f"{uri}#deleted-status=204"


def _register(connection, *, retention_until: datetime) -> None:
    connection.execute(
        """INSERT INTO solvan_operability.skill_retention_controls
             (organization_id,project_id,environment_id,object_kind,object_id,
              storage_region,retention_until,legal_hold_ref,object_uri,
              object_generation,deletion_state)
           VALUES (%s,%s,%s,'SOURCE_PACKAGE',%s,%s,%s,NULL,%s,%s,'RETAINED')""",
        (
            SCOPE.organization_id,
            SCOPE.project_id,
            SCOPE.environment_id,
            OBJECT_ID,
            REGION,
            retention_until,
            OBJECT_URI,
            GENERATION,
        ),
    )


def _control_row(connection) -> tuple:
    return connection.execute(
        """SELECT deletion_state, legal_hold_ref, deletion_job_ref,
                  deletion_claimed_at IS NOT NULL, deleted_at IS NOT NULL
             FROM solvan_operability.skill_retention_controls
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND object_kind='SOURCE_PACKAGE' AND object_id=%s""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, OBJECT_ID),
    ).fetchone()


def _receipts(connection) -> list[tuple]:
    return connection.execute(
        """SELECT object_uri, expected_generation, provider_receipt_ref
             FROM solvan_operability.skill_deletion_receipts
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND object_kind='SOURCE_PACKAGE' AND object_id=%s""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, OBJECT_ID),
    ).fetchall()


def _rewind_claim(connection, minutes: int) -> None:
    connection.execute(
        """UPDATE solvan_operability.skill_retention_controls
              SET deletion_claimed_at = deletion_claimed_at - make_interval(mins => %s)
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND object_kind='SOURCE_PACKAGE' AND object_id=%s""",
        (minutes, SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, OBJECT_ID),
    )


def test_claim_then_settle_commits_receipt_and_deleted_state(connection) -> None:
    now = datetime.now(UTC)
    _register(connection, retention_until=now - timedelta(days=1))
    deleter = _MemoryObjectDeleter({OBJECT_URI: GENERATION})
    deleted = execute_due_deletions(
        repository=PostgresSkillRetentionRepository(connection),
        deleter=deleter,
        scope=SCOPE,
        region=REGION,
        now=now,
    )
    assert deleted == 1
    assert deleter.objects == {}
    state, hold, job_ref, claimed, settled = _control_row(connection)
    assert state == "DELETED"
    assert hold is None
    assert job_ref is not None
    assert claimed is True
    assert settled is True
    assert _receipts(connection) == [(OBJECT_URI, GENERATION, f"{OBJECT_URI}#deleted-status=204")]


def test_hold_attached_after_claim_refuses_deletion_and_keeps_object(connection) -> None:
    now = datetime.now(UTC)
    _register(connection, retention_until=now - timedelta(days=1))
    repository = PostgresSkillRetentionRepository(connection)
    (candidate,) = repository.claim_due(scope=SCOPE, region=REGION, now=now, limit=5)
    connection.execute(
        """UPDATE solvan_operability.skill_retention_controls
              SET legal_hold_ref='hold_1'
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND object_kind='SOURCE_PACKAGE' AND object_id=%s""",
        (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id, OBJECT_ID),
    )
    deleter = _MemoryObjectDeleter({OBJECT_URI: GENERATION})
    outcome = repository.settle(
        scope=SCOPE,
        candidate=candidate,
        deleter=deleter,
        requested_region=REGION,
        now=now,
    )
    assert outcome == "LEGAL_HOLD_ACTIVE"
    assert deleter.calls == []
    assert OBJECT_URI in deleter.objects
    assert _control_row(connection) == ("RETAINED", "hold_1", None, False, False)
    assert _receipts(connection) == []
    assert (
        repository.claim_due(scope=SCOPE, region=REGION, now=now + timedelta(hours=1), limit=5)
        == ()
    )


def test_region_mismatch_at_settlement_refuses_and_releases_the_claim(connection) -> None:
    now = datetime.now(UTC)
    _register(connection, retention_until=now - timedelta(days=1))
    repository = PostgresSkillRetentionRepository(connection)
    (candidate,) = repository.claim_due(scope=SCOPE, region=REGION, now=now, limit=5)
    deleter = _MemoryObjectDeleter({OBJECT_URI: GENERATION})
    outcome = repository.settle(
        scope=SCOPE,
        candidate=candidate,
        deleter=deleter,
        requested_region="us-central1",
        now=now,
    )
    assert outcome == "REGION_DENIED"
    assert deleter.calls == []
    assert OBJECT_URI in deleter.objects
    assert _control_row(connection) == ("RETAINED", None, None, False, False)
    assert _receipts(connection) == []


def test_interrupted_run_with_object_already_deleted_settles_on_rerun(connection) -> None:
    now = datetime.now(UTC)
    _register(connection, retention_until=now - timedelta(days=1))
    repository = PostgresSkillRetentionRepository(connection)
    (candidate,) = repository.claim_due(scope=SCOPE, region=REGION, now=now, limit=5)
    deleter = _MemoryObjectDeleter({OBJECT_URI: GENERATION})
    deleter.delete(uri=candidate.object_uri, expected_generation=candidate.object_generation)
    _rewind_claim(connection, 16)
    deleted = execute_due_deletions(
        repository=repository,
        deleter=deleter,
        scope=SCOPE,
        region=REGION,
        now=now,
    )
    assert deleted == 1
    state, _hold, _job_ref, claimed, settled = _control_row(connection)
    assert state == "DELETED"
    assert claimed is True
    assert settled is True
    assert _receipts(connection) == [(OBJECT_URI, GENERATION, f"{OBJECT_URI}#deleted-status=404")]


def test_stale_claim_is_superseded_and_the_replacement_settles_once(connection) -> None:
    now = datetime.now(UTC)
    _register(connection, retention_until=now - timedelta(days=1))
    repository = PostgresSkillRetentionRepository(connection)
    (stale,) = repository.claim_due(scope=SCOPE, region=REGION, now=now, limit=5)
    assert repository.claim_due(scope=SCOPE, region=REGION, now=now, limit=5) == ()
    _rewind_claim(connection, 16)
    (replacement,) = repository.claim_due(scope=SCOPE, region=REGION, now=now, limit=5)
    assert replacement.deletion_job_ref != stale.deletion_job_ref
    deleter = _MemoryObjectDeleter({OBJECT_URI: GENERATION})
    assert (
        repository.settle(
            scope=SCOPE,
            candidate=stale,
            deleter=deleter,
            requested_region=REGION,
            now=now,
        )
        == "CLAIM_SUPERSEDED"
    )
    assert deleter.calls == []
    assert OBJECT_URI in deleter.objects
    assert (
        repository.settle(
            scope=SCOPE,
            candidate=replacement,
            deleter=deleter,
            requested_region=REGION,
            now=now,
        )
        == "DELETED"
    )
    assert (
        repository.settle(
            scope=SCOPE,
            candidate=replacement,
            deleter=deleter,
            requested_region=REGION,
            now=now,
        )
        == "ALREADY_DELETED"
    )
    assert len(deleter.calls) == 1
    assert len(_receipts(connection)) == 1
