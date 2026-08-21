"""Agent Skills selection contracts against real PostgreSQL 16."""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest

from solvan.application.skills_selection import (
    PostgresSkillSelector,
    SkillSelectionCandidate,
    parse_skill_selector,
)
from solvan.domain import Scope, new_identifier

DATABASE_URL = os.environ.get("SOLVAN_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(DATABASE_URL is None, reason="requires contract PostgreSQL")
SCOPE = Scope(
    "org_00000000000000000000007541",
    "prj_00000000000000000000007541",
    "env_00000000000000000000007541",
)
_SCOPE_KEY = (SCOPE.organization_id, SCOPE.project_id, SCOPE.environment_id)
CONTENT_HASH = f"sha256:{'6' * 64}"
REVIEWABLE_DIGEST = f"sha256:{'e' * 64}"
HASH_CONFLICT_A = f"sha256:{'1' * 64}"
HASH_CONFLICT_B = f"sha256:{'2' * 64}"
HASH_PAYMENTS_TRIAGE = f"sha256:{'3' * 64}"
HASH_PLATFORM_TRIAGE = f"sha256:{'4' * 64}"
HASH_LEGACY_TRIAGE = f"sha256:{'5' * 64}"


def _approve_skill(
    db,
    *,
    key: str,
    ordinal: int,
    revision_hash: str,
    departments: str,
    approved_minutes_ago: int,
) -> None:
    evaluation_id = f"gev_{ordinal:026d}"
    approval_id = f"gap_{ordinal:026d}"
    db.execute(
        """INSERT INTO solvan_operability.guidance_definitions
             (organization_id,project_id,environment_id,guidance_key,display_name,
              owner_department)
           VALUES (%s,%s,%s,%s,%s,'Payments SRE') ON CONFLICT DO NOTHING""",
        (*_SCOPE_KEY, key, key),
    )
    db.execute(
        """INSERT INTO solvan_operability.guidance_revisions
             (organization_id,project_id,environment_id,guidance_key,version,description,
              discoverable_departments_json,guidance_kind,applicable_service_kinds_json,
              applicable_incident_classes_json,symptom_tags_json,purpose,classification,
              eligible_regions_json,content_ref,content_hash,revision_hash,source_kind,
              source_ref,author_principal,lifecycle)
           VALUES (%s,%s,%s,%s,'1','Selection contract fixture',%s::jsonb,'SKILL',
                   '[]'::jsonb,'[]'::jsonb,'[]'::jsonb,'INCIDENT_INVESTIGATION','INTERNAL',
                   '["europe-west1"]'::jsonb,'gs://skills-test/selection-fixture.json',%s,%s,
                   'SOLVAN_AUTHORED',%s,'user:author@example.com','DRAFT')
           ON CONFLICT DO NOTHING""",
        (
            *_SCOPE_KEY,
            key,
            departments,
            CONTENT_HASH,
            revision_hash,
            f"solvan://skills-selection-fixture/{key}",
        ),
    )
    db.execute(
        """INSERT INTO solvan_operability.guidance_evaluations
             (organization_id,project_id,environment_id,id,guidance_key,guidance_version,
              revision_digest,suite_version,decision,passed_cases,failed_cases,receipt_ref,
              receipt_hash,evaluator_principal,reason_codes_json,receipt_generation,
              corpus_digest,case_set_digest,scorer_name,scorer_version,
              model_config_pins_json,repetitions,pass_thresholds_json)
           VALUES (%s,%s,%s,%s,%s,'1',%s,'skills-selection-fixture-v1','PASS',1,0,
                   'gs://skills-test/selection-evaluation.json',%s,
                   'user:evaluator@example.com','["ADVERSARIAL_SUITE_PASSED"]'::jsonb,'1',
                   %s,%s,'deterministic-guidance-scorer','1','{}'::jsonb,1,
                   '{"pass_rate": 1.0}'::jsonb)
           ON CONFLICT DO NOTHING""",
        (
            *_SCOPE_KEY,
            evaluation_id,
            key,
            revision_hash,
            CONTENT_HASH,
            CONTENT_HASH,
            CONTENT_HASH,
        ),
    )
    db.execute(
        """INSERT INTO solvan_operability.guidance_approvals
             (organization_id,project_id,environment_id,id,guidance_key,guidance_version,
              revision_digest,evaluation_ref,approver_principal,decision,reason,
              decision_request_id)
           VALUES (%s,%s,%s,%s,%s,'1',%s,%s,'user:approver@example.com','APPROVE',
                   'Selection contract fixture approval.',%s)
           ON CONFLICT DO NOTHING""",
        (
            *_SCOPE_KEY,
            approval_id,
            key,
            revision_hash,
            evaluation_id,
            f"skill-selection-fixture-{key}",
        ),
    )
    db.execute(
        """UPDATE solvan_operability.guidance_revisions
              SET lifecycle='APPROVED',evaluation_ref=%s,approval_ref=%s,
                  approved_digest=revision_hash,
                  approved_by_principal='user:approver@example.com',
                  approved_at=now() - make_interval(mins => %s)
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND guidance_key=%s AND version='1'""",
        (evaluation_id, approval_id, approved_minutes_ago, *_SCOPE_KEY, key),
    )
    db.execute(
        """INSERT INTO solvan_operability.guidance_current_heads
             (organization_id,project_id,environment_id,guidance_key,approved_version)
           VALUES (%s,%s,%s,%s,'1') ON CONFLICT DO NOTHING""",
        (*_SCOPE_KEY, key),
    )


def _seed(db) -> None:
    db.execute(
        """INSERT INTO solvan.organizations(id,display_name)
           VALUES (%s,'Skill selection') ON CONFLICT DO NOTHING""",
        (SCOPE.organization_id,),
    )
    db.execute(
        """INSERT INTO solvan.projects (organization_id,id,display_name,gcp_project_id)
           VALUES (%s,%s,'Skill selection','solvan-skill-selection')
           ON CONFLICT DO NOTHING""",
        (SCOPE.organization_id, SCOPE.project_id),
    )
    db.execute(
        """INSERT INTO solvan.environments
             (organization_id,project_id,id,display_name,region,classification)
           VALUES (%s,%s,%s,'Skill selection','europe-west1','INTERNAL')
           ON CONFLICT DO NOTHING""",
        _SCOPE_KEY,
    )
    db.execute(
        """INSERT INTO solvan_operability.skill_owner_department_slugs
             (organization_id,project_id,environment_id,owner_slug,owner_department,
              owner_principal)
           VALUES (%s,%s,%s,'payments','Payments SRE','user:owner@example.com'),
                  (%s,%s,%s,'platform','Platform SRE','user:owner@example.com')
           ON CONFLICT DO NOTHING""",
        _SCOPE_KEY * 2,
    )
    _approve_skill(
        db,
        key="payments.conflict-a",
        ordinal=1,
        revision_hash=HASH_CONFLICT_A,
        departments='["Payments"]',
        approved_minutes_ago=50,
    )
    _approve_skill(
        db,
        key="payments.conflict-b",
        ordinal=2,
        revision_hash=HASH_CONFLICT_B,
        departments='["Payments"]',
        approved_minutes_ago=40,
    )
    _approve_skill(
        db,
        key="payments.triage-latency",
        ordinal=3,
        revision_hash=HASH_PAYMENTS_TRIAGE,
        departments='["Payments","Payments Ops"]',
        approved_minutes_ago=30,
    )
    _approve_skill(
        db,
        key="platform.triage-latency",
        ordinal=4,
        revision_hash=HASH_PLATFORM_TRIAGE,
        departments='["Platform"]',
        approved_minutes_ago=20,
    )
    _approve_skill(
        db,
        key="payments.triage-latency.legacy",
        ordinal=5,
        revision_hash=HASH_LEGACY_TRIAGE,
        departments='["Payments"]',
        approved_minutes_ago=10,
    )
    db.execute(
        """INSERT INTO solvan_operability.guidance_incompatibilities
             (organization_id,project_id,environment_id,declaring_guidance_key,
              declaring_version,incompatible_guidance_key,reason_code,reviewable_digest)
           VALUES (%s,%s,%s,'payments.conflict-b','1','payments.conflict-a',
                   'AUTHOR_DECLARED_INCOMPATIBLE',%s)
           ON CONFLICT DO NOTHING""",
        (*_SCOPE_KEY, REVIEWABLE_DIGEST),
    )
    db.execute(
        """INSERT INTO solvan_operability.skill_reader_grants
             (organization_id,project_id,environment_id,principal,owner_department,
              purpose,region,classification_ceiling,granted_by_principal)
           VALUES (%s,%s,%s,'user:multi@example.com','Payments',
                   'INCIDENT_INVESTIGATION','europe-west1','INTERNAL',
                   'user:approver@example.com'),
                  (%s,%s,%s,'user:multi@example.com','Platform',
                   'INCIDENT_INVESTIGATION','europe-west1','INTERNAL',
                   'user:approver@example.com'),
                  (%s,%s,%s,'user:single@example.com','Payments',
                   'INCIDENT_INVESTIGATION','europe-west1','INTERNAL',
                   'user:approver@example.com'),
                  (%s,%s,%s,'user:single@example.com','Payments Ops',
                   'INCIDENT_INVESTIGATION','europe-west1','INTERNAL',
                   'user:approver@example.com')
           ON CONFLICT DO NOTHING""",
        _SCOPE_KEY * 4,
    )


@pytest.fixture
def connection():
    assert DATABASE_URL is not None
    with (
        psycopg.connect(DATABASE_URL) as database,
        database.transaction(force_rollback=True),
    ):
        _seed(database)
        yield database


def test_grant_scope_wide_ambiguity_refuses_and_one_lineage_resolves(connection) -> None:
    selector = PostgresSkillSelector(connection)
    with pytest.raises(ValueError) as excinfo:
        selector.resolve_for_principal(
            scope=SCOPE,
            principal="user:multi@example.com",
            command="/triage-latency",
            runtime_region="europe-west1",
        )
    message = str(excinfo.value)
    assert message.startswith("GUIDANCE_SELECTOR_AMBIGUOUS:")
    assert "/payments/triage-latency" in message
    assert "/platform/triage-latency" in message

    _, single = selector.resolve_for_principal(
        scope=SCOPE,
        principal="user:single@example.com",
        command="/triage-latency",
        runtime_region="europe-west1",
    )
    assert single.guidance_key == "payments.triage-latency"
    assert single.revision_hash == HASH_PAYMENTS_TRIAGE

    _, qualified = selector.resolve_for_principal(
        scope=SCOPE,
        principal="user:multi@example.com",
        command="/payments/triage-latency",
        runtime_region="europe-west1",
    )
    assert qualified.guidance_key == "payments.triage-latency"
    assert qualified.revision_hash == HASH_PAYMENTS_TRIAGE


def test_invocation_replay_keeps_analytics_and_original_refusal_details(connection) -> None:
    selector = PostgresSkillSelector(connection)
    thread_id = "thr_skill_replay"
    parsed_a, candidate_a = selector.resolve_for_principal(
        scope=SCOPE,
        principal="user:multi@example.com",
        command="/payments/conflict-a",
        runtime_region="europe-west1",
    )
    first = selector.record_invocation(
        scope=SCOPE,
        thread_id=thread_id,
        answer_message_id="msg_skill_replay_a",
        anchor_kind="RECORD",
        anchor_record_type="incident",
        anchor_record_id="inc_skill_replay",
        parsed=parsed_a,
        candidate=candidate_a,
        principal="user:multi@example.com",
        membership_epoch=1,
        policy_epoch=1,
    )
    assert first.status == "PENDING_COORDINATOR"
    replay = selector.record_invocation(
        scope=SCOPE,
        thread_id=thread_id,
        answer_message_id="msg_skill_replay_a",
        anchor_kind="RECORD",
        anchor_record_type="incident",
        anchor_record_id="inc_skill_replay",
        parsed=parsed_a,
        candidate=candidate_a,
        principal="user:multi@example.com",
        membership_epoch=1,
        policy_epoch=1,
    )
    assert replay.request_id == first.request_id
    assert (replay.status, replay.conflict_reason) == ("PENDING_COORDINATOR", None)
    assert connection.execute(
        """SELECT outcome_code,selection_count
             FROM solvan_operability.guidance_selection_analytics
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND guidance_key='payments.conflict-a' AND guidance_version='1'
            ORDER BY outcome_code""",
        _SCOPE_KEY,
    ).fetchall() == [("CANDIDATE_RECORDED", 1)]

    parsed_b, candidate_b = selector.resolve_for_principal(
        scope=SCOPE,
        principal="user:multi@example.com",
        command="/payments/conflict-b",
        runtime_region="europe-west1",
    )
    refused = selector.record_invocation(
        scope=SCOPE,
        thread_id=thread_id,
        answer_message_id="msg_skill_replay_b",
        anchor_kind="RECORD",
        anchor_record_type="incident",
        anchor_record_id="inc_skill_replay",
        parsed=parsed_b,
        candidate=candidate_b,
        principal="user:multi@example.com",
        membership_epoch=1,
        policy_epoch=1,
    )
    assert (refused.status, refused.conflict_reason) == (
        "REFUSED",
        "AUTHOR_DECLARED_INCOMPATIBLE",
    )
    connection.execute(
        """UPDATE solvan_operability.guidance_invocation_requests
              SET request_status='EXPIRED'
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s AND id=%s""",
        (*_SCOPE_KEY, first.request_id),
    )
    replayed_refusal = selector.record_invocation(
        scope=SCOPE,
        thread_id=thread_id,
        answer_message_id="msg_skill_replay_b",
        anchor_kind="RECORD",
        anchor_record_type="incident",
        anchor_record_id="inc_skill_replay",
        parsed=parsed_b,
        candidate=candidate_b,
        principal="user:multi@example.com",
        membership_epoch=1,
        policy_epoch=1,
    )
    assert replayed_refusal.request_id == refused.request_id
    assert (replayed_refusal.status, replayed_refusal.conflict_reason) == (
        "REFUSED",
        "AUTHOR_DECLARED_INCOMPATIBLE",
    )
    assert connection.execute(
        """SELECT outcome_code,selection_count
             FROM solvan_operability.guidance_selection_analytics
            WHERE organization_id=%s AND project_id=%s AND environment_id=%s
              AND guidance_key='payments.conflict-b' AND guidance_version='1'
            ORDER BY outcome_code""",
        _SCOPE_KEY,
    ).fetchall() == [("CONFLICT_REFUSED", 1)]


def test_incompatible_co_selection_is_serialized_across_two_database_transactions() -> None:
    """Concurrent incompatible invocations in one thread leave one pending."""

    assert DATABASE_URL is not None
    with psycopg.connect(DATABASE_URL) as setup:
        _seed(setup)
        setup.commit()

    thread_id = new_identifier("thr")
    barrier = threading.Barrier(2)
    candidates = {
        "conflict-a": SkillSelectionCandidate(
            guidance_key="payments.conflict-a",
            version="1",
            revision_hash=HASH_CONFLICT_A,
            owner_slug="payments",
        ),
        "conflict-b": SkillSelectionCandidate(
            guidance_key="payments.conflict-b",
            version="1",
            revision_hash=HASH_CONFLICT_B,
            owner_slug="payments",
        ),
    }

    def invoke(skill_name: str) -> tuple[str, str, str | None]:
        assert DATABASE_URL is not None
        with psycopg.connect(DATABASE_URL) as worker:
            selector = PostgresSkillSelector(worker)
            barrier.wait(timeout=5)
            result = selector.record_invocation(
                scope=SCOPE,
                thread_id=thread_id,
                answer_message_id=new_identifier("msg"),
                anchor_kind="RECORD",
                anchor_record_type="incident",
                anchor_record_id="inc_skill_race",
                parsed=parse_skill_selector(f"/payments/{skill_name}"),
                candidate=candidates[skill_name],
                principal="user:multi@example.com",
                membership_epoch=1,
                policy_epoch=1,
            )
            worker.commit()
            return skill_name, result.status, result.conflict_reason

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(invoke, ("conflict-a", "conflict-b")))

    assert {status for _name, status, _reason in results} == {
        "PENDING_COORDINATOR",
        "REFUSED",
    }
    refused = next(item for item in results if item[1] == "REFUSED")
    assert refused[2] == "AUTHOR_DECLARED_INCOMPATIBLE"
    with psycopg.connect(DATABASE_URL) as inspection:
        assert inspection.execute(
            """SELECT count(*)
                 FROM solvan_operability.guidance_invocation_requests
                WHERE organization_id=%s AND project_id=%s AND environment_id=%s
                  AND thread_id=%s AND request_status='PENDING_COORDINATOR'""",
            (*_SCOPE_KEY, thread_id),
        ).fetchone() == (1,)
        assert inspection.execute(
            """SELECT c.reason_code
                 FROM solvan_operability.guidance_invocation_conflicts c
                 JOIN solvan_operability.guidance_invocation_requests i ON
                   (i.organization_id,i.project_id,i.environment_id,i.id)=
                   (c.organization_id,c.project_id,c.environment_id,
                    c.invocation_request_id)
                WHERE i.organization_id=%s AND i.project_id=%s AND i.environment_id=%s
                  AND i.thread_id=%s""",
            (*_SCOPE_KEY, thread_id),
        ).fetchall() == [("AUTHOR_DECLARED_INCOMPATIBLE",)]
