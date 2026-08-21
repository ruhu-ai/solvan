from __future__ import annotations

from contextlib import nullcontext
from typing import Any

import pytest

from solvan.application.skills_selection import (
    PostgresSkillSelector,
    SkillInvocationRequest,
    SkillSelectionCandidate,
    parse_skill_selector,
)
from solvan.domain import Scope, new_identifier


@pytest.mark.parametrize(
    ("text", "owner", "skill", "note"),
    [
        ("/triage-latency", None, "triage-latency", ""),
        (
            "/reliability/triage-latency check spikes",
            "reliability",
            "triage-latency",
            "check spikes",
        ),
    ],
)
def test_skill_selector_parses_qualified_and_bare_forms(
    text: str, owner: str | None, skill: str, note: str
) -> None:
    parsed = parse_skill_selector(text)
    assert parsed.owner_slug == owner
    assert parsed.skill_name == skill
    assert parsed.note == note


@pytest.mark.parametrize("text", ["triage-latency", "/bad//selector", "/owner/skill/"])
def test_skill_selector_rejects_untrusted_or_malformed_forms(text: str) -> None:
    with pytest.raises(ValueError, match="GUIDANCE_SELECTOR_INVALID"):
        parse_skill_selector(text)


class _Cursor:
    def __init__(self, rows: list[tuple[object, ...]]) -> None:
        self.rows = rows

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, *_args: object) -> None:
        return None

    def fetchall(self) -> list[tuple[object, ...]]:
        return self.rows


class _Connection:
    def __init__(self, rows: list[tuple[object, ...]]) -> None:
        self.rows = rows

    def cursor(self) -> _Cursor:
        return _Cursor(self.rows)


class _ScriptedCursor:
    def __init__(self, connection: _ScriptedConnection) -> None:
        self.connection = connection
        self.result: object = None

    def __enter__(self) -> _ScriptedCursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, parameters: object) -> None:
        self.connection.executions.append((statement, parameters))
        self.result = self.connection.results.pop(0)

    def fetchall(self) -> list[tuple[object, ...]]:
        assert isinstance(self.result, list)
        return self.result

    def fetchone(self) -> tuple[object, ...] | None:
        assert self.result is None or isinstance(self.result, tuple)
        return self.result


class _ScriptedConnection:
    def __init__(self, results: list[object]) -> None:
        self.results = results
        self.executions: list[tuple[str, object]] = []

    def cursor(self) -> _ScriptedCursor:
        return _ScriptedCursor(self)

    def transaction(self) -> Any:
        return nullcontext()


SCOPE = Scope(
    organization_id=new_identifier("org"),
    project_id=new_identifier("prj"),
    environment_id=new_identifier("env"),
)
ROW = (
    "reliability.triage-latency",
    "1",
    "sha256:" + "a" * 64,
    "INTERNAL",
    "reliability",
    ["SRE"],
)
LEGACY_ROW = (
    "reliability.triage-latency.legacy",
    "3",
    "sha256:" + "b" * 64,
    "INTERNAL",
    "reliability",
    ["SRE"],
)
CANDIDATE = SkillSelectionCandidate(
    guidance_key="reliability.triage-latency",
    version="1",
    revision_hash="sha256:" + "a" * 64,
    owner_slug="reliability",
)


def test_selector_resolves_current_eligible_head() -> None:
    parsed, candidate = PostgresSkillSelector(_Connection([ROW])).resolve(
        scope=SCOPE,
        command="/reliability/triage-latency check latency",
        runtime_region="europe-west1",
        purpose="incident-investigation",
        classification_ceiling="INTERNAL",
        discoverable_departments=("SRE",),
    )
    assert parsed.note == "check latency"
    assert candidate.guidance_key == "reliability.triage-latency"


def test_selector_refuses_ambiguous_and_ineligible_results() -> None:
    with pytest.raises(ValueError, match="GUIDANCE_SELECTOR_AMBIGUOUS"):
        PostgresSkillSelector(
            _Connection(
                [ROW, ("platform.triage-latency", "2", ROW[2], "INTERNAL", "platform", ["SRE"])]
            )
        ).resolve(
            scope=SCOPE,
            command="/triage-latency",
            runtime_region="europe-west1",
            purpose="incident-investigation",
            classification_ceiling="INTERNAL",
            discoverable_departments=("SRE",),
        )
    with pytest.raises(ValueError, match="GUIDANCE_NOT_ELIGIBLE"):
        PostgresSkillSelector(_Connection([])).resolve(
            scope=SCOPE,
            command="/triage-latency",
            runtime_region="europe-west1",
            purpose="incident-investigation",
            classification_ceiling="INTERNAL",
            discoverable_departments=("SRE",),
        )


def test_qualified_selector_never_matches_non_canonical_legacy_key() -> None:
    _, candidate = PostgresSkillSelector(_Connection([LEGACY_ROW, ROW])).resolve(
        scope=SCOPE,
        command="/reliability/triage-latency",
        runtime_region="europe-west1",
        purpose="incident-investigation",
        classification_ceiling="INTERNAL",
        discoverable_departments=("SRE",),
    )
    assert candidate.guidance_key == "reliability.triage-latency"
    assert candidate.revision_hash == ROW[2]
    with pytest.raises(ValueError, match="GUIDANCE_NOT_ELIGIBLE"):
        PostgresSkillSelector(_Connection([LEGACY_ROW])).resolve(
            scope=SCOPE,
            command="/reliability/triage-latency",
            runtime_region="europe-west1",
            purpose="incident-investigation",
            classification_ceiling="INTERNAL",
            discoverable_departments=("SRE",),
        )


def test_selector_refuses_unknown_classification_ceiling() -> None:
    with pytest.raises(ValueError, match="CLASSIFICATION_INVALID"):
        PostgresSkillSelector(_Connection([ROW])).resolve(
            scope=SCOPE,
            command="/triage-latency",
            runtime_region="europe-west1",
            purpose="incident-investigation",
            classification_ceiling="SECRET",
            discoverable_departments=("SRE",),
        )


def test_selector_resolves_from_explicit_reader_grant() -> None:
    connection = _ScriptedConnection(
        [
            [("SRE", "incident-investigation", "INTERNAL")],
            [ROW],
        ]
    )
    parsed, candidate = PostgresSkillSelector(connection).resolve_for_principal(
        scope=SCOPE,
        principal="operator@example.com",
        command="/reliability/triage-latency investigate",
        runtime_region="europe-west1",
    )
    assert parsed.note == "investigate"
    assert candidate.guidance_key == "reliability.triage-latency"
    grant_parameters = connection.executions[0][1]
    assert isinstance(grant_parameters, dict)
    assert grant_parameters["principal"] == "operator@example.com"


def test_selector_denies_omitted_reader_grant() -> None:
    connection = _ScriptedConnection([[]])
    with pytest.raises(ValueError, match="GUIDANCE_READER_GRANT_REQUIRED"):
        PostgresSkillSelector(connection).resolve_for_principal(
            scope=SCOPE,
            principal="operator@example.com",
            command="/triage-latency",
            runtime_region="europe-west1",
        )


def test_two_grants_matching_two_lineages_refuse_with_both_qualified_selectors() -> None:
    platform_row = (
        "platform.triage-latency",
        "2",
        "sha256:" + "c" * 64,
        "INTERNAL",
        "platform",
        ["Platform"],
    )
    connection = _ScriptedConnection(
        [
            [
                ("Platform", "incident-investigation", "INTERNAL"),
                ("SRE", "incident-investigation", "INTERNAL"),
            ],
            [platform_row],
            [ROW],
        ]
    )
    with pytest.raises(ValueError, match="GUIDANCE_SELECTOR_AMBIGUOUS") as excinfo:
        PostgresSkillSelector(connection).resolve_for_principal(
            scope=SCOPE,
            principal="operator@example.com",
            command="/triage-latency",
            runtime_region="europe-west1",
        )
    assert "/platform/triage-latency" in str(excinfo.value)
    assert "/reliability/triage-latency" in str(excinfo.value)


def test_two_grants_matching_one_lineage_resolve_without_ambiguity() -> None:
    payments_visible_row = (
        "reliability.triage-latency",
        "1",
        ROW[2],
        "INTERNAL",
        "reliability",
        ["Payments"],
    )
    connection = _ScriptedConnection(
        [
            [
                ("Payments", "incident-investigation", "INTERNAL"),
                ("SRE", "incident-investigation", "INTERNAL"),
            ],
            [payments_visible_row],
            [ROW],
        ]
    )
    _, candidate = PostgresSkillSelector(connection).resolve_for_principal(
        scope=SCOPE,
        principal="operator@example.com",
        command="/triage-latency",
        runtime_region="europe-west1",
    )
    assert candidate.guidance_key == "reliability.triage-latency"
    assert candidate.version == "1"


def test_autocomplete_returns_only_grant_eligible_approved_heads() -> None:
    row = (
        "reliability.triage-latency",
        "1",
        "reliability",
        "Triage latency",
        "Investigate latency safely",
        "incident-investigation",
        "INTERNAL",
        ["SRE"],
    )
    connection = _ScriptedConnection([[("SRE", "incident-investigation", "INTERNAL")], [row]])
    items = PostgresSkillSelector(connection).autocomplete_for_principal(
        scope=SCOPE,
        principal="operator@example.com",
        runtime_region="europe-west1",
        query="latency",
    )
    assert [item.selector for item in items] == ["/reliability/triage-latency"]
    assert items[0].description == "Investigate latency safely"


def test_autocomplete_denies_without_grant_and_rejects_unbounded_limit() -> None:
    selector = PostgresSkillSelector(_ScriptedConnection([[]]))
    assert (
        selector.autocomplete_for_principal(
            scope=SCOPE,
            principal="operator@example.com",
            runtime_region="europe-west1",
            query="",
        )
        == ()
    )
    with pytest.raises(ValueError, match="GUIDANCE_AUTOCOMPLETE_LIMIT_INVALID"):
        selector.autocomplete_for_principal(
            scope=SCOPE,
            principal="operator@example.com",
            runtime_region="europe-west1",
            query="",
            limit=51,
        )


def test_record_invocation_persists_inert_note_and_content_free_analytics() -> None:
    connection = _ScriptedConnection(
        [
            None,
            None,
            ("gir_new",),
            None,
            None,
        ]
    )
    result = PostgresSkillSelector(connection).record_invocation(
        scope=SCOPE,
        thread_id="thr_demo",
        answer_message_id="msg_demo",
        anchor_kind="INCIDENT",
        anchor_record_type="incident",
        anchor_record_id="inc_demo",
        parsed=parse_skill_selector("/reliability/triage-latency check saturation"),
        candidate=CANDIDATE,
        principal="operator@example.com",
        membership_epoch=3,
        policy_epoch=7,
    )
    assert result.request_id.startswith("gir_")
    assert result.status == "PENDING_COORDINATOR"
    statements = [statement for statement, _ in connection.executions]
    assert "pg_advisory_xact_lock" in statements[0]
    assert any("guidance_operator_notes" in statement for statement in statements)
    assert any("guidance_selection_analytics" in statement for statement in statements)
    analytics = next(
        parameters
        for statement, parameters in connection.executions
        if "guidance_selection_analytics" in statement
    )
    assert isinstance(analytics, dict)
    assert "note" not in analytics
    assert analytics["outcome"] == "CANDIDATE_RECORDED"


def test_replayed_refused_invocation_returns_original_reason_without_recounting() -> None:
    connection = _ScriptedConnection(
        [
            None,
            None,
            None,
            (
                "gir_prior",
                CANDIDATE.guidance_key,
                CANDIDATE.version,
                CANDIDATE.revision_hash,
                "REFUSED",
            ),
            ("AUTHOR_DECLARED_INCOMPATIBLE",),
        ]
    )
    result = PostgresSkillSelector(connection).record_invocation(
        scope=SCOPE,
        thread_id="thr_demo",
        answer_message_id="msg_demo",
        anchor_kind="INCIDENT",
        anchor_record_type="incident",
        anchor_record_id="inc_demo",
        parsed=parse_skill_selector("/reliability/triage-latency retry note"),
        candidate=CANDIDATE,
        principal="operator@example.com",
        membership_epoch=3,
        policy_epoch=7,
    )
    assert result == SkillInvocationRequest(
        request_id="gir_prior",
        candidate=CANDIDATE,
        status="REFUSED",
        conflict_reason="AUTHOR_DECLARED_INCOMPATIBLE",
    )
    statements = [statement for statement, _ in connection.executions]
    assert not any("guidance_selection_analytics" in statement for statement in statements)
    assert not any("guidance_operator_notes" in statement for statement in statements)


def test_replayed_pending_invocation_does_not_recount_analytics() -> None:
    connection = _ScriptedConnection(
        [
            None,
            None,
            None,
            (
                "gir_prior",
                CANDIDATE.guidance_key,
                CANDIDATE.version,
                CANDIDATE.revision_hash,
                "PENDING_COORDINATOR",
            ),
        ]
    )
    result = PostgresSkillSelector(connection).record_invocation(
        scope=SCOPE,
        thread_id="thr_demo",
        answer_message_id="msg_demo",
        anchor_kind="INCIDENT",
        anchor_record_type="incident",
        anchor_record_id="inc_demo",
        parsed=parse_skill_selector("/reliability/triage-latency"),
        candidate=CANDIDATE,
        principal="operator@example.com",
        membership_epoch=3,
        policy_epoch=7,
    )
    assert (result.request_id, result.status, result.conflict_reason) == (
        "gir_prior",
        "PENDING_COORDINATOR",
        None,
    )
    statements = [statement for statement, _ in connection.executions]
    assert not any("guidance_selection_analytics" in statement for statement in statements)


def test_replayed_invocation_with_changed_material_conflicts() -> None:
    connection = _ScriptedConnection(
        [
            None,
            None,
            None,
            ("gir_prior", "reliability.other", "1", CANDIDATE.revision_hash, "PENDING_COORDINATOR"),
        ]
    )
    with pytest.raises(ValueError, match="GUIDANCE_INVOCATION_REPLAY_CONFLICT"):
        PostgresSkillSelector(connection).record_invocation(
            scope=SCOPE,
            thread_id="thr_demo",
            answer_message_id="msg_demo",
            anchor_kind="INCIDENT",
            anchor_record_type="incident",
            anchor_record_id="inc_demo",
            parsed=parse_skill_selector("/reliability/triage-latency"),
            candidate=CANDIDATE,
            principal="operator@example.com",
            membership_epoch=3,
            policy_epoch=7,
        )
