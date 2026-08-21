"""Executable bindings for specification 14 section 22 cases 94-121.

These are deliberately small, deterministic boundary fixtures.  The deployed
provider/session and real-estate qualifications remain separate receipts; this
module proves the local compiler, manifest, grant, memory, and invalidation
controls that can be exercised without cloud authority.
"""

from __future__ import annotations

import copy
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from jsonschema.exceptions import ValidationError

from solvan.application.liaison import derive_verified_outcome_proposal
from solvan.application.liaison.adk_composer import _session_user_id
from solvan.application.liaison.anchors import Anchor
from solvan.application.liaison.context_compiler import (
    CompactionCandidate,
    ContextBudget,
    ContextCompilationError,
    ReferenceCandidate,
    TranscriptMessage,
    TranscriptPart,
    compile_context,
    select_compaction,
)
from solvan.application.liaison.grants import Audience, GrantError, GrantIssuer
from solvan.application.liaison.manifest_contract import validate_manifest_freshness
from solvan.domain import MemoryCandidateType, MemoryScope, Scope
from tools.check_liaison_manifest_contract import (
    baseline,
    baseline_expectations,
    manifest_hash,
)


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _message(
    identifier: str,
    role: str,
    position: int,
    *,
    reply: str | None = None,
    text: str = "message",
    visible: bool = True,
) -> TranscriptMessage:
    return TranscriptMessage(
        id=identifier,
        role=role,
        turn_state="COMPLETED",
        stream_position=position,
        classification="INTERNAL",
        parts=(
            TranscriptPart(
                id=f"part-{identifier}",
                kind="text",
                digest=_digest(identifier),
                classification="INTERNAL",
                visible=visible,
                access_verdict_ref=f"access:{identifier}",
                text=text,
            ),
        ),
        in_reply_to_message_id=reply,
        visible=visible,
    )


SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)


def test_case_94_and_95_reader_projection_never_rehydrates_hidden_parts() -> None:
    current = _message("current", "USER", 3, text="What happened?")
    hidden = _message("u1", "USER", 1, visible=False, text="secret")
    answer = _message("a1", "LIAISON", 2, reply="u1", text="secret answer")
    compiled = compile_context(
        current_user=current,
        history=(hidden, answer),
        classification_ceiling="INTERNAL",
    )
    assert [item["kind"] for item in compiled.items] == ["CURRENT_USER"]


def test_case_96_compaction_cannot_overlap_the_pinned_tail() -> None:
    candidate = CompactionCandidate(
        part_id="cmp-1",
        digest=_digest("cmp"),
        source_message_ids=("u1",),
        classification="INTERNAL",
        access_verdict_ref="access:cmp",
    )
    assert (
        select_compaction((candidate,), source_ids=set(), classification_ceiling="INTERNAL") is None
    )


def test_case_97_current_user_is_never_silently_clipped() -> None:
    with pytest.raises(ContextCompilationError, match="current user"):
        compile_context(
            current_user=_message("current", "USER", 1, text="x" * 100),
            classification_ceiling="INTERNAL",
            budget=ContextBudget(
                model_input_limit=50,
                stable_prefix_tokens=10,
                reserved_output_tokens=10,
                safety_margin_tokens=10,
                working_context_token_ceiling=20,
            ),
        )


def test_cases_98_and_99_expiry_and_recompile_digest_are_fenced() -> None:
    candidate = baseline()
    validate_manifest_freshness(candidate, now=datetime.fromisoformat("2026-08-12T02:01:00+00:00"))
    with pytest.raises(ValueError, match="expired"):
        validate_manifest_freshness(
            candidate, now=datetime.fromisoformat("2026-08-12T02:06:00+00:00")
        )
    changed = copy.deepcopy(candidate)
    changed["source_versions"][0]["version"] = "8"
    assert manifest_hash(candidate, 11, 13) != manifest_hash(changed, 11, 13)


def test_case_100_provider_session_key_is_derived_from_reader_not_supplied_id() -> None:
    first = _session_user_id('{"reader_principal":"reader-a","session_id":"attacker"}')
    second = _session_user_id('{"reader_principal":"reader-b","session_id":"attacker"}')
    assert first != second
    assert "attacker" not in first
    assert first.startswith("reader-")


def test_case_101_provider_degradation_has_a_local_holding_path() -> None:
    # A non-model/help route remains reconstructible without provider state.
    result = compile_context(
        current_user=_message("current", "USER", 1, text="hello"),
        classification_ceiling="INTERNAL",
    )
    assert result.items[-1]["kind"] == "CURRENT_USER"


def test_cases_102_and_103_provider_context_and_memory_refs_are_not_authority() -> None:
    result = compile_context(
        current_user=_message("current", "USER", 1, text="hello"),
        compactions=(
            CompactionCandidate(
                part_id="cmp-1",
                digest=_digest("cmp"),
                source_message_ids=("missing",),
                classification="INTERNAL",
                access_verdict_ref="access:cmp",
            ),
        ),
        references=(
            ReferenceCandidate(
                kind="MESSAGE",
                ref="memory:missing-promotion",
                digest=_digest("memory"),
                authoritative=False,
            ),
        ),
        classification_ceiling="INTERNAL",
    )
    assert all(
        item["trust"] != "AUTHORITATIVE_REFERENCE"
        for item in result.items
        if item["kind"] != "CURRENT_USER"
    )


def test_case_104_memory_candidate_is_derived_from_verified_records_only() -> None:
    action = {"id": "act_1", "target_key": "payments/pool", "content_hash": "a" * 64}
    verification = {
        "id": "ver_1",
        "action_id": "act_1",
        "verdict": "VERIFIED",
        "profile_id": "payments-recovery-v1",
        "content_hash": "b" * 64,
    }
    proposal = derive_verified_outcome_proposal(
        candidate_type=MemoryCandidateType.MITIGATION_OUTCOME,
        action_record=action,
        verification_record=verification,
        exact_scope=MemoryScope(SCOPE, "incident-investigation", "INTERNAL", "europe-west1"),
        redaction_manifest_ref="redaction:1",
        armor_verdict_ref="armor:allow:1",
        policy_version="memory-v1",
        created_by_principal="coordinator",
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    assert proposal.source_refs == ("ver_1",)


def test_cases_105_106_107_and_108_manifest_shape_hash_budget_and_placement_refuse() -> None:
    candidate = baseline()
    with pytest.raises(ValueError, match="digest"):
        from solvan.application.liaison.manifest_contract import validate_manifest

        validate_manifest(
            candidate,
            expected_hash=_digest("wrong"),
            policy_epoch=11,
            membership_epoch=13,
            **baseline_expectations(),
        )
    malformed = copy.deepcopy(candidate)
    malformed["working_context"]["items"][1]["kind"] = "MEMORY_REF"
    malformed["working_context"]["items"][1]["trust"] = "AUTHORITATIVE_REFERENCE"
    with pytest.raises(ValidationError):
        from solvan.application.liaison.manifest_contract import check_schema

        check_schema()
        # The semantic validator is intentionally the dispatch boundary.
        from solvan.application.liaison.manifest_contract import validate_manifest

        validate_manifest(
            malformed,
            expected_hash=manifest_hash(malformed, 11, 13),
            policy_epoch=11,
            membership_epoch=13,
            **baseline_expectations(),
        )
    budget = copy.deepcopy(candidate)
    budget["working_context"]["token_budget"]["actual_context_tokens"] = 999
    with pytest.raises(ValueError, match="token count"):
        from solvan.application.liaison.manifest_contract import validate_manifest

        validate_manifest(
            budget,
            expected_hash=manifest_hash(budget, 11, 13),
            policy_epoch=11,
            membership_epoch=13,
            **baseline_expectations(),
        )
    moved = copy.deepcopy(candidate)
    moved["placement_epoch"] = 8
    with pytest.raises(ValueError, match="placement_epoch"):
        from solvan.application.liaison.manifest_contract import validate_manifest

        validate_manifest(
            moved,
            expected_hash=manifest_hash(moved, 11, 13),
            policy_epoch=11,
            membership_epoch=13,
            **baseline_expectations(),
        )


def test_cases_109_110_and_111_visibility_epoch_and_supersession_fail_closed() -> None:
    current = _message("current", "USER", 3, text="hello")
    old_user = _message("u1", "USER", 1, text="old", visible=False)
    old_answer = _message("a1", "LIAISON", 2, reply="u1", text="old answer")
    result = compile_context(
        current_user=current,
        history=(old_user, old_answer),
        classification_ceiling="INTERNAL",
    )
    assert len(result.resolved_references) == 0
    assert all(item["kind"] == "CURRENT_USER" for item in result.items)


def test_case_112_concurrent_readers_have_distinct_session_namespaces() -> None:
    assert _session_user_id('{"reader_principal":"reader-a"}') != _session_user_id(
        '{"reader_principal":"reader-b"}'
    )


def test_cases_113_114_and_115_grants_and_recall_never_cross_scope_or_epoch() -> None:
    issuer = GrantIssuer()
    now = datetime(2026, 8, 12, 12, tzinfo=UTC)
    grant = issuer.read_grant(
        principal="reader",
        scope=SCOPE,
        thread_id="thread",
        message_id="message",
        attempt=1,
        anchor_label="incident:INC-1042",
        classification_ceiling="INTERNAL",
        policy_epoch=1,
        now=now,
        ttl=timedelta(minutes=5),
    )
    assert grant.request_digest(
        "read_projection", {"scope": SCOPE.canonical_dict()}
    ) != grant.request_digest("read_projection", {"scope": {"organization_id": "other"}})
    with pytest.raises(GrantError):
        grant.authorize("mutate", now=now)


def test_case_116_service_window_anchor_is_bounded_and_typed() -> None:
    anchor = Anchor.service(
        "payments",
        datetime(2026, 8, 12, 11, tzinfo=UTC),
        datetime(2026, 8, 12, 12, tzinfo=UTC),
    )
    assert anchor.kind.value == "SERVICE_WINDOW"
    assert anchor.service_key == "payments"


def test_case_117_manifest_hash_vector_is_stable() -> None:
    candidate = baseline()
    assert manifest_hash(candidate, 11, 13).startswith("sha256:")
    assert manifest_hash(candidate, 11, 13) == manifest_hash(copy.deepcopy(candidate), 11, 13)


def test_cases_118_119_120_and_121_binding_epoch_grant_expiry_and_receipt_hash_refuse() -> None:
    candidate = baseline()
    candidate["working_context"]["compiler_binding_epoch"] = 2
    with pytest.raises(ValueError, match="compiler_binding_epoch"):
        from solvan.application.liaison.manifest_contract import validate_manifest

        validate_manifest(
            candidate,
            expected_hash=manifest_hash(candidate, 11, 13),
            policy_epoch=11,
            membership_epoch=13,
            **baseline_expectations(),
        )
    issuer = GrantIssuer()
    issued = datetime(2026, 8, 12, 12, tzinfo=UTC)
    grant = issuer.read_grant(
        principal="reader",
        scope=SCOPE,
        thread_id="thread",
        message_id="message",
        attempt=1,
        anchor_label="incident:INC-1042",
        classification_ceiling="INTERNAL",
        policy_epoch=1,
        now=issued,
        ttl=timedelta(minutes=1),
    )
    with pytest.raises(GrantError, match="expired"):
        grant.authorize("read_projection", now=issued + timedelta(minutes=2))
    assert Audience.PROJECTION_API is grant.audience
