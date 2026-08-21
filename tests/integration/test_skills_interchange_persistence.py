"""Agent Skills interchange idempotency and durability against real PostgreSQL 16."""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from threading import Event
from zipfile import ZipFile

import psycopg
import pytest

from solvan.application.operational_guidance import GuidanceLifecycle
from solvan.application.skills_governance import (
    ExportReceipt,
    RepositoryObservation,
    SkillCompileCommand,
    compile_import,
)
from solvan.application.skills_interchange import inspect_skill_archive
from solvan.application.skills_interchange_service import SkillImportAttempt, SkillImportCommand
from solvan.application.skills_security import SecurityScanReceipt
from solvan.domain import Scope
from solvan.persistence.skills_interchange_store import (
    PostgresRefreshLedger,
    PostgresSkillImportRepository,
)

DATABASE_URL = os.environ.get("SOLVAN_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(DATABASE_URL is None, reason="requires contract PostgreSQL")
SCOPE = Scope(
    "org_00000000000000000000007542",
    "prj_00000000000000000000007542",
    "env_00000000000000000000007542",
)
_SCOPE_KEY = (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id)


class _RefusingObjectWriter:
    def put_bytes(self, *, object_name: str, content: bytes, content_type: str) -> object:
        raise AssertionError("these contracts must not write objects")


def _hash(seed: str) -> str:
    return f"sha256:{hashlib.sha256(seed.encode()).hexdigest()}"


def _seed_definition(db: psycopg.Connection, *, key: str) -> None:
    db.execute(
        """INSERT INTO solvan_operability.guidance_definitions
             (organization_id,project_id,environment_id,guidance_key,display_name,
              owner_department)
           VALUES (%s,%s,%s,%s,%s,'Payments SRE') ON CONFLICT DO NOTHING""",
        (*_SCOPE_KEY, key, key),
    )


def _seed_revision(db: psycopg.Connection, *, key: str, content_hash: str) -> None:
    _seed_definition(db, key=key)
    db.execute(
        """INSERT INTO solvan_operability.guidance_revisions
             (organization_id,project_id,environment_id,guidance_key,version,description,
              discoverable_departments_json,guidance_kind,applicable_service_kinds_json,
              applicable_incident_classes_json,symptom_tags_json,purpose,classification,
              eligible_regions_json,content_ref,content_hash,revision_hash,source_kind,
              source_ref,source_license,author_principal,lifecycle)
           VALUES (%s,%s,%s,%s,'1','Interchange contract fixture',
                   '["Payments"]'::jsonb,'SKILL','[]'::jsonb,'[]'::jsonb,'[]'::jsonb,
                   'INCIDENT_INVESTIGATION','INTERNAL','["europe-west1"]'::jsonb,
                   'gs://skills-test/interchange-fixture.json',%s,%s,'IMPORTED',%s,
                   'Apache-2.0','user:author@example.com','DRAFT')
           ON CONFLICT DO NOTHING""",
        (*_SCOPE_KEY, key, content_hash, _hash(f"revision-{key}"), f"skill-import:sia-{key}"),
    )


def _seed_retention_policy(db: psycopg.Connection) -> None:
    db.execute(
        """INSERT INTO solvan_operability.skill_retention_policies
             (organization_id,project_id,environment_id,policy_id,storage_region,retention_days)
           VALUES (%s,%s,%s,'default','europe-west1',30) ON CONFLICT DO NOTHING""",
        _SCOPE_KEY,
    )


def _approved_revision(key: str):
    output = BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr(
            "demo/SKILL.md",
            "---\nname: demo\ndescription: inspect\nlicense: Apache-2.0\n---\nRead only.\n",
        )
    inspection = inspect_skill_archive(output.getvalue())
    command = SkillCompileCommand(
        guidance_key=key,
        version="1",
        display_name="Interchange contract fixture",
        description="Interchange contract fixture",
        owner_department="Payments SRE",
        discoverable_departments=("Payments",),
        applicable_service_kinds=("payments",),
        applicable_incident_classes=("availability",),
        symptom_tags=("errors",),
        purpose="INCIDENT_INVESTIGATION",
        classification="INTERNAL",
        eligible_regions=("europe-west1",),
        allowed_agent_keys=("evidence-agent",),
        required_profile_revisions=("evidence@1",),
        normalized_license_identifier="Apache-2.0",
        author_principal="user:author@example.com",
    )
    revision = compile_import(command=command, attempt_id=f"sia-{key}", inspection=inspection)
    return revision.model_copy(update={"lifecycle": GuidanceLifecycle.APPROVED})


def _receipts(
    bundle_hash: str, *, secret_verdict: str = "ALLOWED"
) -> tuple[SecurityScanReceipt, ...]:
    return (
        SecurityScanReceipt(
            "SECRET_SCANNER",
            "deterministic-1",
            secret_verdict,
            ("SECRET_OR_CREDENTIAL",) if secret_verdict == "DENIED" else (),
            bundle_hash,
        ),
        SecurityScanReceipt("PII_SCANNER", "deterministic-1", "ALLOWED", (), bundle_hash),
        SecurityScanReceipt("MODEL_ARMOR", "fixture-1", "ALLOWED", (), bundle_hash),
        SecurityScanReceipt("TENANT_LICENSE_POLICY", "test/1", "ALLOWED", (), bundle_hash),
    )


@pytest.fixture
def connection():
    assert DATABASE_URL is not None
    with (
        psycopg.connect(DATABASE_URL) as database,
        database.transaction(force_rollback=True),
    ):
        yield database


def _persist_export(
    repository: PostgresSkillImportRepository,
    *,
    revision,
    idempotency_key: str,
    request_hash: str,
    receipt: ExportReceipt,
    scanner_receipts: tuple[SecurityScanReceipt, ...],
) -> ExportReceipt:
    return repository.persist_export(
        scope=SCOPE,
        revision=revision,
        idempotency_key=idempotency_key,
        request_hash=request_hash,
        destination_id="local-e2e",
        exporter_principal="user:exporter@example.com",
        authorization_ref="authz:interchange-contract",
        receipt=receipt,
        stale_acknowledged=False,
        destination_receipt_ref="gs://skills-test/exports/interchange-contract.zip",
        destination_receipt_generation="1",
        destination_kind="GCS",
        destination_binding_ref="gs://skills-e2e/exports",
        scanner_receipts=scanner_receipts,
        storage_region="europe-west1",
    )


def _prepare_export(
    repository: PostgresSkillImportRepository,
    *,
    key: str,
    idempotency_key: str,
    request_hash: str,
) -> str:
    return repository.prepare_export(
        scope=SCOPE,
        idempotency_key=idempotency_key,
        request_hash=request_hash,
        guidance_key=key,
        guidance_version="1",
        destination_id="local-e2e",
        purpose="GUIDANCE_DISTRIBUTION",
        exporter_principal="user:exporter@example.com",
        authorization_ref="authz:interchange-contract",
    )


def test_export_replay_is_keyed_to_request_hash_not_client_key(connection) -> None:
    """Resubmitting identical material under a fresh key returns the stored receipt."""

    key = "payments.export-replay"
    revision = _approved_revision(key)
    _seed_revision(connection, key=key, content_hash=revision.content_hash)
    _seed_retention_policy(connection)
    repository = PostgresSkillImportRepository(connection, object_writer=_RefusingObjectWriter())
    request_hash = _hash("export-replay-material")
    export_id = _prepare_export(
        repository, key=key, idempotency_key="export-key-00001", request_hash=request_hash
    )
    assert (
        _prepare_export(
            repository, key=key, idempotency_key="export-key-00002", request_hash=request_hash
        )
        == export_id
    )
    receipt = ExportReceipt(
        export_id=export_id,
        guidance_key=key,
        version="1",
        bundle_hash=_hash("export-replay-bundle"),
        content_hash=revision.content_hash,
        lifecycle="APPROVED",
        destination_id="local-e2e",
    )
    stored = _persist_export(
        repository,
        revision=revision,
        idempotency_key="export-key-00001",
        request_hash=request_hash,
        receipt=receipt,
        scanner_receipts=_receipts(receipt.bundle_hash),
    )
    assert stored.export_id == export_id

    replay = repository.find_export_by_idempotency(
        scope=SCOPE, idempotency_key="export-key-00003", request_hash=request_hash
    )
    assert replay is not None
    assert replay[0].export_id == export_id
    assert replay[0].bundle_hash == receipt.bundle_hash

    assert (
        _prepare_export(
            repository, key=key, idempotency_key="export-key-00004", request_hash=request_hash
        )
        == export_id
    )
    with pytest.raises(ValueError, match="IDEMPOTENCY_CONFLICT"):
        _prepare_export(
            repository,
            key=key,
            idempotency_key="export-key-00001",
            request_hash=_hash("export-replay-other-material"),
        )

    forged = ExportReceipt(
        export_id=export_id,
        guidance_key=key,
        version="1",
        bundle_hash=_hash("export-replay-forged-bundle"),
        content_hash=revision.content_hash,
        lifecycle="APPROVED",
        destination_id="local-e2e",
    )
    replayed = _persist_export(
        repository,
        revision=revision,
        idempotency_key="export-key-00005",
        request_hash=request_hash,
        receipt=forged,
        scanner_receipts=_receipts(forged.bundle_hash),
    )
    assert replayed.bundle_hash == receipt.bundle_hash
    assert replayed.export_id == export_id


def test_persist_export_refuses_non_allowed_or_incomplete_scan_receipts(connection) -> None:
    key = "payments.export-denied"
    revision = _approved_revision(key)
    _seed_revision(connection, key=key, content_hash=revision.content_hash)
    _seed_retention_policy(connection)
    repository = PostgresSkillImportRepository(connection, object_writer=_RefusingObjectWriter())
    request_hash = _hash("export-denied-material")
    export_id = _prepare_export(
        repository, key=key, idempotency_key="export-key-00006", request_hash=request_hash
    )
    receipt = ExportReceipt(
        export_id=export_id,
        guidance_key=key,
        version="1",
        bundle_hash=_hash("export-denied-bundle"),
        content_hash=revision.content_hash,
        lifecycle="APPROVED",
        destination_id="local-e2e",
    )
    with pytest.raises(ValueError, match="EXPORT_SCAN_REFUSED"):
        _persist_export(
            repository,
            revision=revision,
            idempotency_key="export-key-00006",
            request_hash=request_hash,
            receipt=receipt,
            scanner_receipts=_receipts(receipt.bundle_hash, secret_verdict="DENIED"),
        )
    with pytest.raises(ValueError, match="EXPORT_SCAN_RECEIPTS_INCOMPLETE"):
        _persist_export(
            repository,
            revision=revision,
            idempotency_key="export-key-00006",
            request_hash=request_hash,
            receipt=receipt,
            scanner_receipts=_receipts(receipt.bundle_hash)[:2],
        )
    rows = connection.execute(
        """SELECT 1 FROM solvan_operability.skill_export_receipts
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND export_request_hash=%s""",
        (*_SCOPE_KEY, request_hash),
    ).fetchall()
    assert rows == []
    decision = connection.execute(
        """SELECT decision FROM solvan_operability.skill_export_attempts
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s AND id=%s""",
        (*_SCOPE_KEY, export_id),
    ).fetchone()
    assert decision == ("PREPARED",)


def test_refresh_refusals_write_durable_refused_attempts(connection) -> None:
    key = "payments.refresh-refusal"
    _seed_definition(connection, key=key)
    repository = PostgresSkillImportRepository(connection, object_writer=_RefusingObjectWriter())
    request_hash = _hash("refresh-refusal-material")
    refused = repository.persist_refresh_attempt(
        scope=SCOPE,
        idempotency_key="refresh-key-00001",
        request_hash=request_hash,
        guidance_key=key,
        expected_head_epoch=1,
        principal="user:author@example.com",
        authorization_ref="authz:interchange-contract",
        decision="REFUSED",
        reason_code="REFRESH_LEASE_HELD",
    )
    assert refused.decision == "REFUSED"
    assert refused.reason_code == "REFRESH_LEASE_HELD"
    replay = repository.find_refresh_attempt(
        scope=SCOPE, idempotency_key="refresh-key-00001", request_hash=request_hash
    )
    assert replay is not None
    assert replay.decision == "REFUSED"
    with pytest.raises(ValueError, match="IDEMPOTENCY_CONFLICT"):
        repository.find_refresh_attempt(
            scope=SCOPE,
            idempotency_key="refresh-key-00001",
            request_hash=_hash("refresh-refusal-other-material"),
        )


def test_upstream_change_notice_records_the_observed_ref(connection) -> None:
    key = "payments.refresh-notice"
    _seed_definition(connection, key=key)
    ledger = PostgresRefreshLedger(connection, scope=SCOPE)
    observation = RepositoryObservation(commit_sha="a" * 40, subtree_hash="sha256:" + "1" * 64)
    ledger.record(key, upstream_ref="refs/heads/main", observation=observation, outcome="CHANGED")
    ledger.record(key, upstream_ref="refs/heads/main", observation=observation, outcome="CHANGED")
    rows = connection.execute(
        """SELECT upstream_ref,observed_commit_sha,observed_tree_hash
             FROM solvan_operability.skill_upstream_change_notices
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND guidance_key=%s""",
        (*_SCOPE_KEY, key),
    ).fetchall()
    assert rows == [("refs/heads/main", "a" * 40, "sha256:" + "1" * 64)]


def test_concurrent_import_key_reuse_is_a_closed_conflict() -> None:
    """A raced idempotency-key reuse maps to IDEMPOTENCY_CONFLICT, not a raw 500."""

    assert DATABASE_URL is not None
    marker = secrets.token_hex(8)
    idempotency_key = f"import-race-{marker}"
    hash_a = _hash(f"import-race-a-{marker}")
    hash_b = _hash(f"import-race-b-{marker}")

    def command(command_id: str) -> SkillImportCommand:
        return SkillImportCommand(
            command_id=command_id,
            scope=SCOPE,
            purpose="GUIDANCE_IMPORT",
            classification="INTERNAL",
            region="europe-west1",
            source_kind="ARCHIVE",
            source_ref=f"upload://{command_id}-{marker}",
            principal="user:author@example.com",
            authorization_ref="authz:interchange-contract",
            idempotency_key=idempotency_key,
        )

    def outcome(request_hash: str) -> SkillImportAttempt:
        return SkillImportAttempt(
            attempt_id="pending",
            import_request_hash=request_hash,
            decision="REJECTED",
            reason_codes=("ARCHIVE_TYPE_UNSUPPORTED",),
            inspection=None,
        )

    with (
        psycopg.connect(DATABASE_URL) as writer_a,
        psycopg.connect(DATABASE_URL) as writer_b,
    ):
        repo_a = PostgresSkillImportRepository(writer_a, object_writer=_RefusingObjectWriter())
        repo_b = PostgresSkillImportRepository(writer_b, object_writer=_RefusingObjectWriter())
        inserted = Event()
        release = Event()

        def first_writer() -> None:
            with writer_a.transaction():
                repo_a.persist_attempt(
                    scope=SCOPE,
                    request=command("cmd-race-a"),
                    request_hash=hash_a,
                    outcome=outcome(hash_a),
                    archive=b"not-an-archive",
                )
                inserted.set()
                assert release.wait(timeout=10)

        def second_writer() -> SkillImportAttempt:
            return repo_b.persist_attempt(
                scope=SCOPE,
                request=command("cmd-race-b"),
                request_hash=hash_b,
                outcome=outcome(hash_b),
                archive=b"not-an-archive",
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            future_a = pool.submit(first_writer)
            assert inserted.wait(timeout=10)
            future_b = pool.submit(second_writer)
            time.sleep(0.5)
            release.set()
            future_a.result(timeout=10)
            with pytest.raises(ValueError, match="IDEMPOTENCY_CONFLICT"):
                future_b.result(timeout=10)

    with psycopg.connect(DATABASE_URL) as check:
        rows = check.execute(
            """SELECT import_request_hash
                 FROM solvan_operability.skill_import_attempts
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND idempotency_key=%s""",
            (*_SCOPE_KEY, idempotency_key),
        ).fetchall()
    assert rows == [(hash_a,)]


def test_refresh_failure_accounting_survives_a_failed_request() -> None:
    """The failure record commits before the request errors, so limits can trip."""

    assert DATABASE_URL is not None
    marker = secrets.token_hex(8)
    key = f"payments.refresh-durability-{marker}"
    with psycopg.connect(DATABASE_URL) as seeder:
        _seed_definition(seeder, key=key)

    request = psycopg.connect(DATABASE_URL)
    try:
        request.autocommit = True
        ledger = PostgresRefreshLedger(request, scope=SCOPE)
        lease = ledger.acquire(key)
        ledger.record_failure(key)
        ledger.release(key, token=lease.token)
    finally:
        # The route's connector error aborts the request here; nothing after
        # this point may be required for the failure to remain durable.
        request.close()

    with psycopg.connect(DATABASE_URL) as observer:
        observer.autocommit = True
        row = observer.execute(
            """SELECT failure_count,last_outcome
                 FROM solvan_operability.skill_refresh_ledgers
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND guidance_key=%s""",
            (*_SCOPE_KEY, key),
        ).fetchone()
        assert row == (1, "FAILED")
        durable = PostgresRefreshLedger(observer, scope=SCOPE)
        with pytest.raises(ValueError, match="REFRESH_CADENCE_LIMIT"):
            durable.acquire(key)
        observer.execute(
            """UPDATE solvan_operability.skill_refresh_ledgers
                  SET last_checked_at=now() - interval '2 hours', failure_count=3
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND guidance_key=%s""",
            (*_SCOPE_KEY, key),
        )
        with pytest.raises(ValueError, match="REFRESH_RETRY_LIMIT"):
            durable.acquire(key)
