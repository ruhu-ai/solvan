"""Built-in product guidance lifecycle against PostgreSQL 16 (spec 18 §11)."""

from __future__ import annotations

import os
from pathlib import Path

import psycopg
import pytest

import tools.load_first_party_skill_packs as loader
from solvan.application.default_tool_catalog import catalog_profile, catalog_tools
from solvan.application.operational_guidance import GuidanceError
from solvan.application.skills_interchange import inspect_skill_archive
from solvan.domain import Scope
from solvan.persistence.operational_guidance_store import PostgresOperationalGuidanceStore
from solvan.persistence.tool_catalog_store import PostgresToolCatalogStore
from tools.load_first_party_skill_packs import (
    APPROVER_PRINCIPAL,
    ROOT,
    PackLoaderError,
    _ensure_release_role_bindings,
    _publish,
    load,
    provenance_attestation_hash,
    revision_for,
)

DATABASE_URL = os.environ.get("SOLVAN_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(DATABASE_URL is None, reason="requires contract PostgreSQL")
SCOPE = Scope(
    "org_00000000000000000000000009",
    "prj_00000000000000000000000009",
    "env_00000000000000000000000009",
)
COMMIT = "feedfacefeedfacefeedfacefeedfacefeedface"
NEXT_COMMIT = "beefcafebeefcafebeefcafebeefcafebeefcafe"
TENANT_ADMIN = "user:tenant-admin@example.com"
LOADER_PRINCIPAL = "service:first-party-pack-loader"


@pytest.fixture
def connection():
    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as database, database.transaction(force_rollback=True):
        database.execute(
            "INSERT INTO solvan.organizations VALUES (%s,'Builtin test',now())",
            (SCOPE.organization_id,),
        )
        database.execute(
            """INSERT INTO solvan.projects
                 (organization_id,id,display_name,gcp_project_id)
               VALUES (%s,%s,'Builtin test','builtin-test')""",
            (SCOPE.organization_id, SCOPE.project_id),
        )
        database.execute(
            """INSERT INTO solvan.environments
                 (organization_id,project_id,id,display_name,region,classification)
               VALUES (%s,%s,%s,'Builtin test','europe-west1','INTERNAL')""",
            (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id),
        )
        database.execute(
            """INSERT INTO solvan_operability.catalog_principals
                 (principal_key,display_name,registry_kind,execution_role,
                  model_backed,manifest_hash)
               VALUES ('evidence-agent','Evidence Agent','AGENT','SPECIALIST',
                       true,%s) ON CONFLICT DO NOTHING""",
            ("sha256:" + "3" * 64,),
        )
        database.execute(
            """INSERT INTO solvan_operability.tool_profile_revisions
                 (schema_version,canonicalization_version,profile_key,version,purpose,
                  allowed_agent_key,maximum_total_calls,maximum_parallel_calls,
                  maximum_read_window_ms,maximum_aggregate_evidence_bytes,
                  data_classification_ceiling,runtime_region,lifecycle,
                  profile_material_hash,approval_ref,evaluation_ref)
               VALUES (2,1,'evidence.gcp-core.v1','1','INCIDENT_INVESTIGATION',
                       'evidence-agent',8,2,60000,1000000,'INTERNAL','europe-west1',
                       'APPROVED',%s,'approval://seed','evaluation://seed')
               ON CONFLICT DO NOTHING""",
            ("sha256:" + "4" * 64,),
        )
        yield database


def _published_revision(connection):
    pack = ROOT / "guidance" / "reliability" / "triage-connection-exhaustion"
    revision = revision_for(
        pack,
        commit=COMMIT,
        agent_keys=("evidence-agent",),
        profile_revisions=("evidence.gcp-core.v1@1",),
    )
    _ensure_release_role_bindings(connection, scope=SCOPE, departments=(revision.owner_department,))
    connection.execute(
        """INSERT INTO solvan_operability.operability_role_bindings
             (organization_id,project_id,environment_id,principal,role,department,granted_by)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                   %(principal)s,'OPERABILITY_ADMIN',%(department)s,'user:seed')""",
        {
            **SCOPE.canonical_dict(),
            "principal": TENANT_ADMIN,
            "department": revision.owner_department,
        },
    )
    store = PostgresOperationalGuidanceStore(connection)
    _publish(
        store,
        connection=connection,
        scope=SCOPE,
        pack=pack,
        revision=revision,
        commit=COMMIT,
        provenance_hash=provenance_attestation_hash(pack),
    )
    row = connection.execute(
        """SELECT lifecycle, revision_hash FROM solvan_operability.guidance_revisions
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s
              AND guidance_key=%(key)s AND version='1'""",
        {**SCOPE.canonical_dict(), "key": revision.guidance_key},
    ).fetchone()
    return store, revision, row


def test_release_publication_walks_the_ordinary_lifecycle_to_approved(connection) -> None:
    _, revision, row = _published_revision(connection)
    assert row is not None
    assert row[0] == "APPROVED"


def test_publication_binds_the_provenance_attestation_into_evaluation_evidence(
    connection,
) -> None:
    _, revision, _ = _published_revision(connection)
    pack = ROOT / "guidance" / "reliability" / "triage-connection-exhaustion"
    row = connection.execute(
        """SELECT model_config_pins_json, receipt_ref
             FROM solvan_operability.guidance_evaluations
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND guidance_key=%(key)s""",
        {**SCOPE.canonical_dict(), "key": revision.guidance_key},
    ).fetchone()
    assert row is not None
    assert row[0]["provenance_attestation"] == provenance_attestation_hash(pack)
    assert row[1] == f"release-gate://{COMMIT}"


def test_tenant_admin_cannot_deprecate_builtin_guidance(connection) -> None:
    store, revision, row = _published_revision(connection)
    with pytest.raises(GuidanceError, match="application release"):
        store.deprecate(
            scope=SCOPE,
            guidance_key=revision.guidance_key,
            version="1",
            principal=TENANT_ADMIN,
            expected_digest=str(row[1]),
            decision_request_id="tenant-deprecate-attempt",
        )


def test_release_principal_supersedes_builtin_guidance(connection) -> None:
    store, revision, row = _published_revision(connection)
    commit = store.deprecate(
        scope=SCOPE,
        guidance_key=revision.guidance_key,
        version="1",
        principal=APPROVER_PRINCIPAL,
        expected_digest=str(row[1]),
        decision_request_id="release-deprecate",
    )
    assert commit.lifecycle == "DEPRECATED"


def _enable_code_repair_family(connection) -> None:
    """Register what a SKILL-kind built-in pack binds: Agent, Tools, and profile."""

    connection.execute(
        """INSERT INTO solvan_operability.catalog_principals
             (principal_key,display_name,registry_kind,execution_role,
              model_backed,manifest_hash)
           VALUES ('workspace-agent','Workspace Agent','AGENT','SPECIALIST',true,%s)
           ON CONFLICT DO NOTHING""",
        ("sha256:" + "5" * 64,),
    )
    catalog = PostgresToolCatalogStore(connection)
    for revision in catalog_tools(
        network_policy_hash="sha256:" + "7" * 64,
        approval_ref="approval://seed",
        evaluation_ref="evaluation://seed",
    ):
        if revision.tool_key.startswith("workspace.code-repair."):
            catalog.publish_tool(revision)
    catalog.publish_profile(
        scope=SCOPE,
        profile=catalog_profile(
            agent_key="workspace-agent",
            approval_ref="approval://seed",
            evaluation_ref="evaluation://seed",
            classification_ceiling="INTERNAL",
        ),
    )


def _write_skill_pack(root: Path, *, body: str) -> Path:
    """Write a pack the loader publishes under the SKILL kind (spec 18 §7, §11)."""

    pack = root / "guidance" / "reliability" / "code-repair"
    pack.mkdir(parents=True, exist_ok=True)
    (pack / "SKILL.md").write_text(
        "---\nname: code-repair\n"
        "description: Investigate a frozen snapshot and propose a bounded candidate.\n"
        "license: Apache-2.0\nmetadata:\n  solvan-owner: reliability\n"
        "  solvan-provenance: first-party\n---\n" + body,
        encoding="utf-8",
    )
    (pack / "PROVENANCE.yaml").write_text(
        "schema_version: 1\npack: reliability.code-repair\nsource_kind: FIRST_PARTY\n"
        "license: Apache-2.0\n",
        encoding="utf-8",
    )
    return pack


def _import_rows(connection) -> tuple[int, int, int]:
    counts = connection.execute(
        """SELECT (SELECT count(*) FROM solvan_operability.skill_import_attempts
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s),
                  (SELECT count(*) FROM solvan_operability.skill_imports
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s),
                  (SELECT count(*) FROM solvan_operability.guidance_skill_bindings
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s)""",
        SCOPE.canonical_dict(),
    ).fetchone()
    assert counts is not None
    return int(counts[0]), int(counts[1]), int(counts[2])


def test_a_skill_pack_publishes_from_a_real_first_party_import(
    connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_code_repair_family(connection)
    pack = _write_skill_pack(tmp_path, body="# Repair the cited mechanism\n")
    monkeypatch.setattr(loader, "ROOT", tmp_path)
    assert load(connection, scope=SCOPE, commit=COMMIT) == ["reliability.code-repair@1"]
    assert _import_rows(connection) == (1, 1, 1)
    row = connection.execute(
        """SELECT a.source_kind,a.decision,a.scanner_receipts_json,a.importer_principal,
                  i.upstream_commit_sha,i.license_state,i.normalized_license_identifier,
                  i.source_bundle_hash,b.source_classification,b.reviewable_digest,
                  b.contains_third_party_material,r.revision_hash
             FROM solvan_operability.skill_import_attempts a
             JOIN solvan_operability.skill_imports i ON
               (i.organization_id,i.project_id,i.environment_id,i.attempt_id)=
               (a.organization_id,a.project_id,a.environment_id,a.id)
             JOIN solvan_operability.guidance_skill_bindings b ON
               (b.organization_id,b.project_id,b.environment_id,b.import_attempt_id)=
               (a.organization_id,a.project_id,a.environment_id,a.id)
             JOIN solvan_operability.guidance_revisions r ON
               (r.organization_id,r.project_id,r.environment_id,r.guidance_key,r.version)=
               (b.organization_id,b.project_id,b.environment_id,b.guidance_key,
                b.guidance_version)
            WHERE a.organization_id=%(organization_id)s AND a.project_id=%(project_id)s
              AND a.environment_id=%(environment_id)s""",
        SCOPE.canonical_dict(),
    ).fetchone()
    assert row is not None
    assert row[0] == "FIRST_PARTY"
    assert row[1] == "QUARANTINED"
    # No quarantine scanner ran in this job, so none is claimed.
    assert row[2] == []
    assert row[3] == loader.AUTHOR_PRINCIPAL
    assert row[4] == COMMIT
    assert (row[5], row[6]) == ("PRESENT", "Apache-2.0")
    # The digest is the interchange canonicalizer's, over the packaged pack bytes.
    expected = inspect_skill_archive(loader._package_bytes(pack)).source_bundle_hash
    assert row[7] == expected
    assert row[8] == "SOLVAN_AUTHORED"
    assert row[10] is False
    # The binding cites the exact reviewable material the approver approved.
    assert row[9] == row[11]


def test_rerunning_a_skill_pack_at_the_same_commit_duplicates_no_import(
    connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_code_repair_family(connection)
    _write_skill_pack(tmp_path, body="# Repair the cited mechanism\n")
    monkeypatch.setattr(loader, "ROOT", tmp_path)
    assert load(connection, scope=SCOPE, commit=COMMIT) == ["reliability.code-repair@1"]
    before = _import_rows(connection)
    assert load(connection, scope=SCOPE, commit=COMMIT) == []
    assert _import_rows(connection) == before == (1, 1, 1)


def test_a_changed_skill_pack_imports_again_and_keeps_the_prior_import(
    connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_code_repair_family(connection)
    _write_skill_pack(tmp_path, body="# Repair the cited mechanism\n")
    monkeypatch.setattr(loader, "ROOT", tmp_path)
    assert load(connection, scope=SCOPE, commit=COMMIT) == ["reliability.code-repair@1"]
    _write_skill_pack(tmp_path, body="# Repair the cited mechanism, minimally\n")
    assert load(connection, scope=SCOPE, commit=NEXT_COMMIT) == ["reliability.code-repair@2"]
    assert _import_rows(connection) == (2, 2, 2)
    versions = connection.execute(
        """SELECT guidance_version FROM solvan_operability.guidance_skill_bindings
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s ORDER BY guidance_version""",
        SCOPE.canonical_dict(),
    ).fetchall()
    assert [str(row[0]) for row in versions] == ["1", "2"]
    assert _lineage(connection, "reliability.code-repair") == {"1": "DEPRECATED", "2": "APPROVED"}


def test_a_disabled_license_policy_refuses_rather_than_being_re_enabled(
    connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_code_repair_family(connection)
    _write_skill_pack(tmp_path, body="# Repair the cited mechanism\n")
    monkeypatch.setattr(loader, "ROOT", tmp_path)
    connection.execute(
        """INSERT INTO solvan_operability.skill_license_policies
             (organization_id,project_id,environment_id,normalized_identifier,
              policy_version,import_allowed,redistribution_allowed,enabled,
              reviewed_by_principal)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,'Apache-2.0',
                   'tenant/1',false,false,false,'user:governance@example.com')""",
        SCOPE.canonical_dict(),
    )
    with pytest.raises(PackLoaderError, match="import-allowed policy"):
        load(connection, scope=SCOPE, commit=COMMIT)
    row = connection.execute(
        """SELECT enabled,import_allowed FROM solvan_operability.skill_license_policies
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND normalized_identifier='Apache-2.0'""",
        SCOPE.canonical_dict(),
    ).fetchone()
    assert row == (False, False)
    assert _import_rows(connection) == (0, 0, 0)


def _write_temporary_pack(root: Path, *, body: str) -> Path:
    pack = root / "guidance" / "reliability" / "triage-sample"
    pack.mkdir(parents=True, exist_ok=True)
    (pack / "SKILL.md").write_text(
        "---\nname: triage-sample\ndescription: A bounded diagnostic checklist.\n---\n" + body,
        encoding="utf-8",
    )
    (pack / "PROVENANCE.yaml").write_text(
        "schema_version: 1\npack: reliability.triage-sample\nsource_kind: FIRST_PARTY\n"
        "license: Apache-2.0\n",
        encoding="utf-8",
    )
    return pack


def _lineage(connection, key: str) -> dict[str, str]:
    rows = connection.execute(
        """SELECT version, lifecycle FROM solvan_operability.guidance_revisions
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND guidance_key=%(key)s""",
        {**SCOPE.canonical_dict(), "key": key},
    ).fetchall()
    return {str(row[0]): str(row[1]) for row in rows}


def _head(connection, key: str) -> str | None:
    row = connection.execute(
        """SELECT approved_version FROM solvan_operability.guidance_current_heads
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND guidance_key=%(key)s""",
        {**SCOPE.canonical_dict(), "key": key},
    ).fetchone()
    return None if row is None else row[0]


def test_load_converges_and_rerun_at_same_commit_is_a_noop(
    connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_temporary_pack(tmp_path, body="# Read the checklist\n")
    monkeypatch.setattr(loader, "ROOT", tmp_path)
    published = load(connection, scope=SCOPE, commit=COMMIT)
    assert published == ["reliability.triage-sample@1"]
    assert _head(connection, "reliability.triage-sample") == "1"
    assert load(connection, scope=SCOPE, commit=COMMIT) == []
    assert _lineage(connection, "reliability.triage-sample") == {"1": "APPROVED"}


def test_changed_pack_at_a_new_commit_supersedes_and_preserves_history(
    connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_temporary_pack(tmp_path, body="# Read the checklist\n")
    monkeypatch.setattr(loader, "ROOT", tmp_path)
    assert load(connection, scope=SCOPE, commit=COMMIT) == ["reliability.triage-sample@1"]
    _write_temporary_pack(tmp_path, body="# Read the revised checklist\n")
    assert load(connection, scope=SCOPE, commit=NEXT_COMMIT) == ["reliability.triage-sample@2"]
    key = "reliability.triage-sample"
    assert _lineage(connection, key) == {"1": "DEPRECATED", "2": "APPROVED"}
    assert _head(connection, key) == "2"
    successor = connection.execute(
        """SELECT supersedes_version FROM solvan_operability.guidance_revisions
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND guidance_key=%(key)s
              AND version='2'""",
        {**SCOPE.canonical_dict(), "key": key},
    ).fetchone()
    assert successor == ("1",)
    for table in ("guidance_approvals", "guidance_evaluations", "guidance_ingestion_receipts"):
        count = connection.execute(
            f"""SELECT count(*) FROM solvan_operability.{table}
                 WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                   AND environment_id=%(environment_id)s AND guidance_key=%(key)s
                   AND guidance_version='1'""",
            {**SCOPE.canonical_dict(), "key": key},
        ).fetchone()
        assert count == (1,), f"{table} history for the superseded revision was not preserved"


def test_stale_bootstrap_draft_is_converged_past_without_deletion(
    connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack = _write_temporary_pack(tmp_path, body="# Read the checklist\n")
    monkeypatch.setattr(loader, "ROOT", tmp_path)
    key = "reliability.triage-sample"
    stale = revision_for(
        pack,
        commit=COMMIT,
        agent_keys=("evidence-agent",),
        profile_revisions=("evidence.gcp-core.v1@1",),
    ).model_copy(update={"author_principal": LOADER_PRINCIPAL})
    connection.execute(
        """INSERT INTO solvan_operability.operability_role_bindings
             (organization_id,project_id,environment_id,principal,role,department,granted_by)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                   %(principal)s,'GUIDANCE_AUTHOR','reliability','local-development-bootstrap')""",
        {**SCOPE.canonical_dict(), "principal": LOADER_PRINCIPAL},
    )
    store = PostgresOperationalGuidanceStore(connection)
    store.create_draft(scope=SCOPE, revision=stale, decision_request_id=f"first-party-pack:{key}")
    assert _lineage(connection, key) == {"1": "DRAFT"}
    published = load(connection, scope=SCOPE, commit=NEXT_COMMIT)
    assert published == [f"{key}@2"]
    assert _lineage(connection, key) == {"1": "DRAFT", "2": "APPROVED"}
    assert _head(connection, key) == "2"
    stale_row = connection.execute(
        """SELECT author_principal, supersedes_version
             FROM solvan_operability.guidance_revisions
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND guidance_key=%(key)s
              AND version='1'""",
        {**SCOPE.canonical_dict(), "key": key},
    ).fetchone()
    assert stale_row == (LOADER_PRINCIPAL, None)
    assert load(connection, scope=SCOPE, commit=NEXT_COMMIT) == []
