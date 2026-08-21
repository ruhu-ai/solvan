from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import pytest

from solvan.application.liaison.context_compiler import (
    CompactionCandidate,
    ContextBudget,
    ContextCompilationError,
    ReferenceCandidate,
    TranscriptMessage,
    TranscriptPart,
    compile_context,
    context_from_rows,
    select_complete_turns,
)


def _part(identifier: str, text: str, *, visible: bool = True) -> TranscriptPart:
    return TranscriptPart(
        id=identifier,
        kind="text",
        digest="sha256:" + hashlib.sha256(identifier.encode()).hexdigest(),
        classification="INTERNAL",
        visible=visible,
        access_verdict_ref=f"access:{identifier}",
        text=text,
    )


def _message(
    identifier: str,
    role: str,
    position: int,
    *,
    reply: str | None = None,
    state: str = "COMPLETED",
    text: str = "message",
    visible: bool = True,
) -> TranscriptMessage:
    return TranscriptMessage(
        id=identifier,
        role=role,
        turn_state=state,
        stream_position=position,
        classification="INTERNAL",
        parts=(_part(f"part-{identifier}", text, visible=visible),),
        in_reply_to_message_id=reply,
        visible=visible,
    )


def test_only_complete_visible_whole_turns_are_selected() -> None:
    history = (
        _message("u1", "USER", 1),
        _message("a1", "LIAISON", 2, reply="u1"),
        _message("u2", "USER", 3),
        _message("a2", "LIAISON", 4, reply="u2", state="PARKED"),
        _message("u3", "USER", 5, visible=False),
        _message("a3", "LIAISON", 6, reply="u3"),
    )
    selected = select_complete_turns(
        history,
        current_user_id="current",
        classification_ceiling="INTERNAL",
    )
    assert [(user.id, answer.id) for user, answer in selected] == [("u1", "a1")]


def test_unredacted_liaison_answer_never_enters_working_context() -> None:
    history = (
        _message("u1", "USER", 1),
        TranscriptMessage(
            id="a1",
            role="LIAISON",
            turn_state="COMPLETED",
            stream_position=2,
            classification="INTERNAL",
            parts=(_part("part-a1", "answer"),),
            in_reply_to_message_id="u1",
            redaction_complete=False,
        ),
    )

    assert (
        select_complete_turns(
            history,
            current_user_id="current",
            classification_ceiling="INTERNAL",
        )
        == ()
    )


def test_compiler_keeps_current_user_and_emits_typed_history_and_refs() -> None:
    result = compile_context(
        current_user=_message("current", "USER", 9, text="What happened?"),
        history=(
            _message("u0", "USER", 1, text="Older question"),
            _message("a0", "LIAISON", 2, reply="u0", text="Older answer"),
            _message("u1", "USER", 3, text="First question"),
            _message("a1", "LIAISON", 4, reply="u1", text="Recorded answer"),
        ),
        compactions=(
            CompactionCandidate(
                part_id="cmp-1",
                digest="sha256:" + "1" * 64,
                source_message_ids=("u0", "a0"),
                classification="INTERNAL",
                access_verdict_ref="cmp-access",
                token_count=12,
            ),
        ),
        references=(
            ReferenceCandidate(
                kind="RECORD",
                ref="record:incident:INC-1042",
                digest="sha256:" + "2" * 64,
                authoritative=True,
            ),
        ),
        classification_ceiling="INTERNAL",
        budget=ContextBudget(preserve_recent_tokens=40),
        now=datetime(2026, 8, 12, 12, tzinfo=UTC),
    )
    assert [item["kind"] for item in result.items] == [
        "COMPACTION",
        "THREAD_TURN",
        "RECORD",
        "CURRENT_USER",
    ]
    assert result.items[-1]["trust"] == "UNTRUSTED_USER_CONTENT"
    assert result.items[0]["trust"] == "UNTRUSTED_CONTEXT_ONLY"
    assert result.items[2]["trust"] == "AUTHORITATIVE_REFERENCE"
    assert result.token_budget["actual_context_tokens"] == sum(
        item["token_count"] for item in result.items
    )
    assert result.expires_at.isoformat() == "2026-08-12T12:05:00+00:00"
    assert result.processors == (
        "validate_bindings",
        "filter_reader_projection",
        "select_complete_turns",
        "select_compaction_and_pinned_tail",
        "resolve_typed_references",
        "add_artifact_and_memory_refs",
        "prune_and_budget",
        "assemble_stable_prefix_and_variable_suffix",
    )


def test_compiler_prunes_old_context_with_an_explicit_marker() -> None:
    result = compile_context(
        current_user=_message("current", "USER", 9, text="current"),
        history=(
            _message("u1", "USER", 1, text="old question"),
            _message("a1", "LIAISON", 2, reply="u1", text="old answer"),
        ),
        classification_ceiling="INTERNAL",
        budget=ContextBudget(
            model_input_limit=100,
            stable_prefix_tokens=10,
            reserved_output_tokens=10,
            safety_margin_tokens=10,
            working_context_token_ceiling=20,
            preserve_recent_tokens=20,
        ),
    )
    assert any(item["kind"] == "TRUNCATION_MARKER" for item in result.items)
    assert result.items[-1]["kind"] == "CURRENT_USER"
    assert result.omitted_counts["budget"] == 1


def test_references_over_the_reader_ceiling_are_absent_from_items_and_refs() -> None:
    result = compile_context(
        current_user=_message("current", "USER", 9, text="What happened?"),
        references=(
            ReferenceCandidate(
                kind="RECORD",
                ref="record:visible",
                digest="sha256:" + "1" * 64,
                classification="INTERNAL",
                authoritative=True,
            ),
            ReferenceCandidate(
                kind="RECORD",
                ref="record:hidden",
                digest="sha256:" + "2" * 64,
                classification="CONFIDENTIAL",
                authoritative=True,
            ),
        ),
        classification_ceiling="INTERNAL",
    )

    assert [item["ref"] for item in result.items if item["kind"] == "RECORD"] == ["record:visible"]
    assert result.resolved_references == ({"kind": "RECORD", "ref": "record:visible"},)


def test_row_adapter_does_not_reintroduce_withheld_part_text() -> None:
    compiled = context_from_rows(
        current_user={
            "id": "msg-current",
            "role": "USER",
            "parts": [
                {
                    "id": "part-current",
                    "kind": "text",
                    "digest": "sha256:" + "1" * 64,
                    "classification": "INTERNAL",
                    "visible": True,
                    "access_verdict_ref": "access:current",
                    "text": "current question",
                }
            ],
        },
        history=[
            {
                "id": "msg-old",
                "role": "USER",
                "parts": [
                    {
                        "id": "part-old",
                        "kind": "text",
                        "digest": "sha256:" + "2" * 64,
                        "classification": "INTERNAL",
                        "visible": False,
                        "access_verdict_ref": "access:old",
                        "text": "secret old question",
                    }
                ],
            },
            {
                "id": "msg-old-answer",
                "role": "LIAISON",
                "in_reply_to_message_id": "msg-old",
                "parts": [
                    {
                        "id": "part-old-answer",
                        "kind": "text",
                        "digest": "sha256:" + "3" * 64,
                        "classification": "INTERNAL",
                        "visible": False,
                        "access_verdict_ref": "access:old-answer",
                        "text": "secret old answer",
                    }
                ],
            },
        ],
        classification_ceiling="INTERNAL",
        current_user_text="current question",
    )

    assert [item["kind"] for item in compiled.items] == ["CURRENT_USER"]


def test_row_adapter_excludes_streaming_parts_from_model_context() -> None:
    compiled = context_from_rows(
        current_user={
            "id": "msg-current",
            "role": "USER",
            "parts": [
                {
                    "id": "part-current",
                    "kind": "text",
                    "digest": "sha256:" + "1" * 64,
                    "classification": "INTERNAL",
                    "visible": True,
                    "status": "COMPLETED",
                    "access_verdict_ref": "access:current",
                    "text": "current question",
                }
            ],
        },
        history=[
            {
                "id": "msg-old",
                "role": "USER",
                "parts": [
                    {
                        "id": "part-old",
                        "kind": "text",
                        "digest": "sha256:" + "2" * 64,
                        "classification": "INTERNAL",
                        "visible": True,
                        "status": "STREAMING",
                        "access_verdict_ref": "access:old",
                        "text": "partial provider content",
                    }
                ],
            },
            {
                "id": "msg-old-answer",
                "role": "LIAISON",
                "in_reply_to_message_id": "msg-old",
                "parts": [
                    {
                        "id": "part-answer",
                        "kind": "text",
                        "digest": "sha256:" + "3" * 64,
                        "classification": "INTERNAL",
                        "visible": True,
                        "status": "COMPLETED",
                        "access_verdict_ref": "access:answer",
                        "text": "completed answer",
                    }
                ],
            },
        ],
        classification_ceiling="INTERNAL",
        current_user_text="current question",
    )
    assert not any("partial provider content" in str(item) for item in compiled.items)


def test_current_user_is_never_silently_clipped() -> None:
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


def test_current_user_text_override_must_match_reader_filtered_parts() -> None:
    with pytest.raises(ContextCompilationError, match="stored message parts"):
        compile_context(
            current_user=_message("current", "USER", 1, text="canonical question"),
            current_user_text="untrusted replacement",
            classification_ceiling="INTERNAL",
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("model_input_limit", 0, "model input limit"),
        ("stable_prefix_tokens", -1, "stable prefix"),
        ("reserved_output_tokens", 0, "reserved output"),
        ("ttl_seconds", 3601, "TTL"),
    ),
)
def test_context_budget_rejects_invalid_policy_operands(
    field: str, value: int, message: str
) -> None:
    values = {
        "model_input_limit": 100,
        "stable_prefix_tokens": 10,
        "reserved_output_tokens": 10,
        "safety_margin_tokens": 10,
        "working_context_token_ceiling": 20,
        "preserve_recent_tokens": 10,
        "ttl_seconds": 300,
    }
    values[field] = value
    with pytest.raises(ValueError, match=message):
        ContextBudget(**values)


@pytest.mark.parametrize(
    ("factory", "message"),
    (
        (
            lambda: TranscriptPart(
                id="part-1",
                kind="text",
                digest="not-a-digest",
                classification="INTERNAL",
                access_verdict_ref="access:part-1",
            ),
            "digest",
        ),
        (
            lambda: ReferenceCandidate(
                kind="RECORD",
                ref="record:1",
                digest="not-a-digest",
            ),
            "digest",
        ),
        (
            lambda: ReferenceCandidate(
                kind="RECORD",
                ref="record:1",
                digest="sha256:" + "1" * 64,
                access_verdict_ref="",
            ),
            "access verdict",
        ),
    ),
)
def test_typed_context_inputs_fail_closed_at_the_value_boundary(
    factory: object, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        factory()  # type: ignore[operator]


def test_stable_prefix_digest_binds_only_static_registry_material() -> None:
    first = compile_context(
        current_user=_message("current", "USER", 1, text="hello"),
        classification_ceiling="INTERNAL",
        stable_prefix_material={
            "revision": "prefix-v1",
            "template_registry_digest": "sha256:" + "a" * 64,
            "tool_registry_digest": "sha256:" + "b" * 64,
        },
    )
    second = compile_context(
        current_user=_message("current", "USER", 1, text="hello"),
        classification_ceiling="INTERNAL",
        stable_prefix_material={
            "revision": "prefix-v2",
            "template_registry_digest": "sha256:" + "a" * 64,
            "tool_registry_digest": "sha256:" + "b" * 64,
        },
    )
    assert first.stable_prefix_digest != second.stable_prefix_digest
    assert first.variable_suffix_digest == second.variable_suffix_digest


def test_compaction_selection_is_newest_and_not_incidental_input_order() -> None:
    from solvan.application.liaison.context_compiler import select_compaction

    old = CompactionCandidate(
        part_id="old",
        digest="sha256:" + "1" * 64,
        source_message_ids=("u0",),
        classification="INTERNAL",
        access_verdict_ref="old-access",
        created_at=datetime(2026, 8, 12, 11, tzinfo=UTC),
    )
    newest = CompactionCandidate(
        part_id="newest",
        digest="sha256:" + "2" * 64,
        source_message_ids=("u0",),
        classification="INTERNAL",
        access_verdict_ref="new-access",
        created_at=datetime(2026, 8, 12, 12, tzinfo=UTC),
    )

    selected = select_compaction(
        (newest, old), source_ids={"u0"}, classification_ceiling="INTERNAL"
    )

    assert selected is newest


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("digest", "sha256:not-a-digest", "digest"),
        ("source_message_ids", ("u0", "u0"), "unique"),
        ("token_count", -1, "negative"),
        ("created_at", datetime(2026, 8, 12, 12), "timezone-aware"),
    ),
)
def test_compaction_metadata_fails_closed_before_context_selection(
    field: str, value: object, message: str
) -> None:
    values: dict[str, Any] = {
        "part_id": "cmp-1",
        "digest": "sha256:" + "1" * 64,
        "source_message_ids": ("u0",),
        "classification": "INTERNAL",
        "access_verdict_ref": "cmp-access",
        "token_count": 12,
        "created_at": datetime(2026, 8, 12, 12, tzinfo=UTC),
    }
    values[field] = value

    with pytest.raises(ValueError, match=message):
        CompactionCandidate(**values)
