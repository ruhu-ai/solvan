"""Anchors, the registry's refusals, and the turn engine's honest exits.

The paths here are the ones a happy-path test never reaches: a malformed
anchor, a registry that must refuse to serve, a doom loop, an exhausted
budget, and a reader who may not see what a turn produced. Each has to fail
in a stated way rather than a convenient one.

Specification 14 §4, §7, §12, and fixtures 26-31.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from solvan.application.liaison import (
    Anchor,
    AnchorError,
    AnchorKind,
    Citation,
    ClaimDraft,
    GrantError,
    GrantIssuer,
    TemplateRegistryError,
    anchor_from_mapping,
    entity_set,
    load_registry,
    registry_manifest,
    resolve_anchor,
)
from solvan.application.liaison.engine import (
    Composition,
    ConnectiveDraft,
    DoomLoopGuard,
    Escalation,
    GrantedReader,
    TurnBudget,
    TurnState,
    TurnUsage,
    default_daily_budget,
    default_turn_budget,
    run_turn,
    visible_parts,
)
from solvan.application.liaison.predicates import KNOWN_PREDICATES
from solvan.application.liaison.questions import (
    QUESTIONS,
    EnumeratedComposer,
    match_question,
    offered_questions,
    question_prompt,
)
from solvan.domain import Scope

REGISTRY_PATH = Path(__file__).resolve().parents[2] / "config/liaison-claim-templates.yaml"
SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)


class _Ledger:
    def __init__(self, records: dict[tuple[str, str], dict[str, Any]] | None = None) -> None:
        self._records = records or {}

    def read(self, record_type: str, record_id: str) -> dict[str, Any] | None:
        return self._records.get((record_type, record_id))

    def exists(self, record_type: str, record_id: str) -> bool:
        return (record_type, record_id) in self._records

    def children(self, record_type: str, record_id: str) -> tuple[tuple[str, str], ...]:
        return tuple(key for key in self._records if key != (record_type, record_id))

    def authorized_records(self) -> tuple[tuple[str, str], ...]:
        return tuple(self._records)

    def resolve_reference(self, reference: str) -> tuple[str, str] | None:
        record_type, separator, record_id = reference.partition(":")
        key = (record_type, record_id)
        return key if separator and key in self._records else None

    def search_records(self, **_: object) -> tuple[dict[str, str], ...]:
        return tuple(
            {"record_type": record_type, "record_id": record_id}
            for record_type, record_id in self._records
        )

    def recall_memory(self, **_: object) -> tuple[dict[str, object], ...]:
        return (
            {
                "promotion_id": "memp_1",
                "source_refs": [{"record_type": "incident", "record_id": "INC-1042"}],
                "historical_hint_only": True,
            },
        )

    def recall_conversation(self, **_: object) -> tuple[dict[str, object], ...]:
        return (
            {
                "thread_id": "thr_1",
                "message_id": "lms_1",
                "part_sequence": 0,
                "part_kind": "CLAIM",
                "reference": "liaison-part:lms_1:0",
            },
        )


@pytest.fixture(scope="module")
def registry():
    return load_registry(REGISTRY_PATH, known_predicates=KNOWN_PREDICATES)


def _grant(issuer: GrantIssuer, anchor: Anchor):
    return issuer.read_grant(
        principal="operator@example.com",
        scope=SCOPE,
        thread_id="thr_1",
        message_id="lms_1",
        attempt=1,
        anchor_label=anchor.label(),
        classification_ceiling="INTERNAL",
        policy_epoch=1,
    )


# -- anchors ---------------------------------------------------------------


def test_each_anchor_shape_rejects_the_fields_it_must_not_carry() -> None:
    with pytest.raises(AnchorError, match="needs a record type"):
        Anchor(kind=AnchorKind.RECORD)
    with pytest.raises(AnchorError, match="no service or window"):
        Anchor(kind=AnchorKind.RECORD, record_type="incident", record_id="INC-1", service_key="s")
    with pytest.raises(AnchorError, match="not anchorable"):
        Anchor.record("secret_table", "row-1")
    with pytest.raises(AnchorError, match="closed window"):
        Anchor(kind=AnchorKind.SERVICE_WINDOW, service_key="payments-api")
    with pytest.raises(AnchorError, match="no detail"):
        Anchor(kind=AnchorKind.SCOPE, service_key="payments-api")

    now = datetime.now(UTC)
    with pytest.raises(AnchorError, match="must end after"):
        Anchor.service("payments-api", now, now - timedelta(hours=1))


def test_anchor_labels_and_payload_round_trip() -> None:
    now = datetime.now(UTC)
    record = Anchor.record("incident", "INC-1042")
    service = Anchor.service("payments-api", now - timedelta(hours=1), now)
    scope = Anchor.scope()
    assert record.label() == "incident:INC-1042"
    assert service.label() == "service:payments-api"
    assert scope.label() == "scope"
    assert anchor_from_mapping(record.canonical_dict()) == record
    assert anchor_from_mapping(service.canonical_dict()) == service
    assert anchor_from_mapping(scope.canonical_dict()) == scope


def test_a_malformed_anchor_payload_fails_closed() -> None:
    with pytest.raises(AnchorError, match="unknown anchor kind"):
        anchor_from_mapping({"anchor_kind": "EVERYTHING"})
    with pytest.raises(AnchorError, match="datetime window bounds"):
        anchor_from_mapping({"anchor_kind": "SERVICE_WINDOW", "anchor_service_key": "s"})


def test_an_anchor_must_exist_before_anything_reads_for_it() -> None:
    ledger = _Ledger({("incident", "INC-1042"): {"id": "INC-1042"}})
    resolve_anchor(ledger, Anchor.record("incident", "INC-1042"))
    with pytest.raises(AnchorError, match="does not exist"):
        resolve_anchor(ledger, Anchor.record("incident", "INC-9999"))


def test_an_anchor_reaches_its_children_for_context() -> None:
    ledger = _Ledger(
        {
            ("incident", "INC-1042"): {"id": "INC-1042"},
            ("evidence_item", "evd_1"): {"incident": "INC-1042"},
        }
    )
    reached = entity_set(ledger, Anchor.record("incident", "INC-1042"))
    # A record anchor always includes itself, then whatever the directory says
    # it reaches; authority is still evaluated per record by the caller.
    assert reached[0] == ("incident", "INC-1042")
    assert ("evidence_item", "evd_1") in reached
    assert entity_set(ledger, Anchor.scope())


def test_the_complete_read_belt_is_grant_counted_and_authority_filtered() -> None:
    anchor = Anchor.record("incident", "INC-1042")
    ledger = _Ledger(
        {
            ("incident", "INC-1042"): {"id": "INC-1042", "state": "MITIGATED"},
            ("incident", "INC-HIDDEN"): {"id": "INC-HIDDEN", "state": "DETECTED"},
        }
    )
    usage = TurnUsage()
    reader = GrantedReader(ledger, grant=_grant(GrantIssuer(), anchor), usage=usage)

    assert reader.resolve_anchor("incident:INC-1042")["found"] is True
    assert reader.resolve_anchor("incident:ABSENT") == {"found": False}
    projection = reader.read_projection("incident:INC-1042", "incident")
    assert projection["addressable"] is True
    assert reader.search_records(
        service_key=None,
        state=None,
        window_start=None,
        window_end=None,
        record_type="incident",
    )
    recalled = reader.recall_memory(
        anchor_ref="incident:INC-1042", purpose="incident-investigation"
    )
    assert recalled[0]["historical_hint_only"] is True
    conversation = reader.recall_conversation(
        anchor_ref="incident:INC-1042", purpose="incident-investigation"
    )
    assert conversation[0]["reference"] == "liaison-part:lms_1:0"
    assert usage.tool_calls == 6


def test_the_read_belt_fails_closed_when_optional_projection_callbacks_are_absent() -> None:
    class BareLedger:
        def read(self, record_type: str, record_id: str) -> dict[str, str] | None:
            return {"record_type": record_type, "record_id": record_id}

    anchor = Anchor.record("incident", "INC-1042")
    reader = GrantedReader(BareLedger(), grant=_grant(GrantIssuer(), anchor), usage=TurnUsage())

    assert reader._authorized_records() == ()
    assert reader.resolve_anchor(anchor.label()) == {
        "found": False,
        "reason": "record_directory_unavailable",
    }
    assert reader.read_projection(anchor.label(), "incident") == {"addressable": False}
    assert (
        reader.list_prior_incidents(service_key="payments-api", window_start=None, window_end=None)
        == ()
    )
    assert (
        reader.search_records(
            service_key=None,
            state=None,
            window_start=None,
            window_end=None,
            record_type=None,
        )
        == ()
    )
    assert reader.catch_up(anchor_ref=anchor.label(), cursor=None) == {
        "available": False,
        "reason": "durable_event_reader_unavailable",
    }
    assert reader.recall_memory(anchor_ref=anchor.label(), purpose="incident-investigation") == ()
    assert (
        reader.recall_conversation(anchor_ref=anchor.label(), purpose="incident-investigation")
        == ()
    )
    assert reader.recall_memory(anchor_ref="incident:other", purpose="incident-investigation") == ()


# -- registry --------------------------------------------------------------


def test_the_registry_refuses_a_template_naming_an_unimplemented_predicate(tmp_path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        "schema_version: 1\n"
        "templates:\n"
        "  - id: X\n    kind: K\n    polarity: NEUTRAL\n    held: false\n"
        '    sentence: "{a}"\n    slots: [a]\n    predicate: NO_SUCH_VERIFIER\n'
        "    releasing_record: null\n    holding_template: null\n",
        encoding="utf-8",
    )
    with pytest.raises(TemplateRegistryError, match="no implementation"):
        load_registry(path, known_predicates=KNOWN_PREDICATES)


def test_the_registry_refuses_a_sentence_whose_slots_disagree(tmp_path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        "schema_version: 1\n"
        "templates:\n"
        "  - id: X\n    kind: K\n    polarity: NEUTRAL\n    held: false\n"
        '    sentence: "{a} and {b}"\n    slots: [a]\n    predicate: ALWAYS\n'
        "    releasing_record: null\n    holding_template: null\n",
        encoding="utf-8",
    )
    with pytest.raises(TemplateRegistryError, match="do not match declared slots"):
        load_registry(path, known_predicates=KNOWN_PREDICATES)


def test_the_registry_refuses_a_held_template_without_a_release(tmp_path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        "schema_version: 1\n"
        "templates:\n"
        "  - id: X\n    kind: K\n    polarity: AFFIRMATIVE\n    held: true\n"
        '    sentence: "{a}"\n    slots: [a]\n'
        "    slot_sources:\n      a: SUBJECT\n"
        "    predicate: ALWAYS\n"
        "    releasing_record: null\n    holding_template: null\n",
        encoding="utf-8",
    )
    with pytest.raises(TemplateRegistryError, match="must name a releasing record"):
        load_registry(path, known_predicates=KNOWN_PREDICATES)


def test_an_unreadable_or_unversioned_registry_refuses_to_serve(tmp_path) -> None:
    with pytest.raises(TemplateRegistryError, match="unreadable"):
        load_registry(tmp_path / "absent.yaml", known_predicates=KNOWN_PREDICATES)
    path = tmp_path / "v0.yaml"
    path.write_text("schema_version: 99\ntemplates: []\n", encoding="utf-8")
    with pytest.raises(TemplateRegistryError, match="schema_version 1"):
        load_registry(path, known_predicates=KNOWN_PREDICATES)


def test_rendering_refuses_missing_or_unknown_slots(registry) -> None:
    template = registry.claim("STATE_REPORT")
    with pytest.raises(TemplateRegistryError, match="missing slot values"):
        template.render({"subject_label": "INC-1042"})
    with pytest.raises(TemplateRegistryError, match="unknown slots"):
        template.render({"subject_label": "a", "state": "b", "extra": "c"})


def test_a_connective_may_only_speak_enumerated_phrases(registry) -> None:
    connective = registry.connective("LEAD_IN")
    assert connective.render("Here is what happened.") == "Here is what happened."
    with pytest.raises(TemplateRegistryError, match="does not permit"):
        connective.render("Everything is completely fine.")
    with pytest.raises(TemplateRegistryError, match="unknown connective"):
        registry.connective("NO_SUCH_CONNECTIVE")


def test_the_registry_manifest_is_stable_and_names_every_gate(registry) -> None:
    manifest = registry_manifest(registry)
    assert registry.digest in manifest
    assert "RECOVERY_VERIFIED" in manifest
    assert manifest == registry_manifest(registry)


# -- questions -------------------------------------------------------------


def test_question_matching_declines_to_guess() -> None:
    assert match_question("is it fixed yet?") is not None
    assert match_question("") is None
    assert match_question("xyzzy plugh") is None
    assert question_prompt("IS_IT_FIXED") == "Is it fixed?"
    assert question_prompt("NOT_A_QUESTION") == "NOT_A_QUESTION"


def test_question_matching_reads_words_not_substrings() -> None:
    """A keyword buried inside another word is not a request for that answer.

    Substring scoring routed "summarise the incident for me" to the human
    attention shape, because `"me"` sits inside "for me" — and `"ok"` sits
    inside "look". Both are whole-word matches now, so the answer follows what
    the person asked rather than what their spelling happened to contain.
    """

    matched = match_question("summarise the incident for me")
    assert matched is not None and matched.id == "WHAT_HAPPENED"
    assert match_question("What caused the payment failures?").id == "WHAT_HAPPENED"  # type: ignore[union-attr]
    assert match_question("give me a summary") is not None
    assert match_question("give me a summary").id == "WHAT_HAPPENED"  # type: ignore[union-attr]
    # "ok" inside "look", with nothing else in the sentence to match.
    assert match_question("look at the dashboard") is None


def test_a_shape_the_record_cannot_admit_is_never_selected() -> None:
    """The offered set and the answerable set are the same set (§4.2).

    A closed case is not waiting on anybody, so the attention question must be
    unreachable for one — not merely unlisted.
    """

    closed = {"id": "INC-1", "state": "CLOSED"}
    mitigated = {"id": "INC-1", "state": "MITIGATED"}
    assert match_question("what needs a person", closed) is None
    selected = match_question("what needs a person", mitigated)
    assert selected is not None and selected.id == "WHAT_NEEDS_ME"
    # Without a record there is nothing to gate against, so routing still works.
    assert match_question("what needs a person") is not None


def test_offered_questions_depend_on_the_records_state() -> None:
    assert offered_questions(None) == ()
    closed = offered_questions({"state": "CLOSED"})
    mitigated = offered_questions({"state": "MITIGATED"})
    # The attention question is only worth offering when someone is blocked.
    assert "WHAT_NEEDS_ME" not in closed
    assert "WHAT_NEEDS_ME" in mitigated


def test_an_unreadable_anchor_yields_the_escalation_not_a_guess(registry) -> None:
    composer = EnumeratedComposer()
    composition = composer.compose(
        question="Is it fixed?", anchor=Anchor.record("incident", "INC-1"), reader=_Ledger()
    )
    assert composition.drafts == ()
    # Held, not escalated. The reader is attached to a record they cannot read,
    # which is a grant condition; the old escalation proposed a fresh telemetry
    # read, which would not have fixed it and was never the missing thing.
    assert composition.escalation is None
    assert composition.hold is not None
    assert composition.hold.held_reason == "ANCHOR_UNREADABLE"


def test_every_closed_question_shape_composes_from_one_rich_projection() -> None:
    """Exercise the entire ordinary-conversation vocabulary as one contract."""

    incident_id = "INC-1042"
    record = {
        "id": incident_id,
        "state": "MITIGATED",
        "service": "payments-api",
        "next_action": "Review the exact rollback proposal.",
        "causal_chain": [
            {"detail": "Revision v2.8.1 retained checked-out connections."},
            "invalid chain material",
        ],
        "brief": {
            "data_loss": "No duplicate charges were observed.",
            "impact_lines": [
                {
                    "metric": "payment failures",
                    "scope": "payments-api",
                    "detail": "18.4% at peak",
                    "citation": "evd_impact",
                },
                {
                    "metric": "downstream errors",
                    "scope": "checkout",
                    "detail": "No downstream propagation was observed.",
                    "citation": "evd_blast",
                },
                "invalid impact material",
            ],
        },
        "verification": {
            "id": "ver_1042",
            "threshold": "error ratio below 2% for five minutes",
        },
        "evidence_index": [
            {"ref": "evd_impact", "label": "Payment failure series"},
            "invalid evidence material",
        ],
        "actions": [
            {
                "id": "act_1042",
                "name": "Recycle the bounded pool",
                "receipt": "effect reconciled",
                "status": "VERIFIED",
            },
            "invalid action material",
        ],
    }
    reader = _Ledger({("incident", incident_id): record})
    composer = EnumeratedComposer()

    for question in QUESTIONS:
        composition = composer.compose(
            question=question.prompt,
            anchor=Anchor.record("incident", incident_id),
            reader=reader,
        )
        assert composition.drafts, question.id
        assert composition.escalation is None
        assert question.id in composition.suggested


def test_closed_shapes_hold_safe_defaults_when_optional_projection_fields_are_absent() -> None:
    reader = _Ledger(
        {
            ("incident", "INC-1042"): {
                "id": "INC-1042",
                "state": "MITIGATED",
                "service": "payments-api",
            }
        }
    )
    composer = EnumeratedComposer()

    data_loss = composer.compose(
        question="Was any data lost?",
        anchor=Anchor.record("incident", "INC-1042"),
        reader=reader,
    )
    blast_radius = composer.compose(
        question="Is anything else affected?",
        anchor=Anchor.record("incident", "INC-1042"),
        reader=reader,
    )
    assert data_loss.drafts
    assert blast_radius.drafts


# -- the turn engine -------------------------------------------------------


class _StaticComposer:
    def __init__(self, composition: Composition) -> None:
        self._composition = composition

    def compose(self, *, question: str, anchor: Anchor, reader: Any) -> Composition:
        del question, anchor, reader
        return self._composition


class _LoopingComposer:
    """Reads the same record until the guard stops it."""

    def compose(self, *, question: str, anchor: Anchor, reader: Any) -> Composition:
        del question, anchor
        for _ in range(5):
            reader.read("incident", "INC-1042")
        return Composition()


class _PartSink:
    def __init__(self) -> None:
        self.parts = []

    def emit(self, part) -> None:
        self.parts.append(part)


def test_part_sink_sees_only_typed_gated_parts(registry) -> None:
    issuer = GrantIssuer()
    anchor = Anchor.record("incident", "INC-1042")
    sink = _PartSink()
    result = run_turn(
        question="why",
        anchor=anchor,
        reader=_Ledger({("incident", "INC-1042"): {"id": "INC-1042"}}),
        registry=registry,
        composer=_StaticComposer(
            Composition(
                drafts=(
                    ConnectiveDraft(template_id="LEAD_IN", phrase="Here is what the ledger holds."),
                ),
            )
        ),
        grant=_grant(issuer, anchor),
        part_sink=sink,
    )
    assert tuple(sink.parts) == result.parts
    assert all(part.kind.value != "raw_model_delta" for part in sink.parts)


def test_a_repeated_read_parks_a_question_instead_of_burning_budget(registry) -> None:
    issuer = GrantIssuer()
    anchor = Anchor.record("incident", "INC-1042")
    result = run_turn(
        question="why",
        anchor=anchor,
        reader=_Ledger({("incident", "INC-1042"): {"id": "INC-1042"}}),
        registry=registry,
        composer=_LoopingComposer(),
        grant=_grant(issuer, anchor),
    )
    assert result.state is TurnState.PARKED
    assert result.parts[0].kind.value == "parked_request"


def test_a_park_tool_emits_one_author_scoped_typed_request(registry) -> None:
    issuer = GrantIssuer()
    anchor = Anchor.record("incident", "INC-1042")
    result = run_turn(
        question="compare another window",
        anchor=anchor,
        reader=_Ledger({("incident", "INC-1042"): {"id": "INC-1042"}}),
        registry=registry,
        composer=_StaticComposer(
            Composition(
                model_calls=1,
                tool_calls=1,
                parked_request={
                    "kind": "QUESTION",
                    "prompt": "Which window should I compare?",
                },
            )
        ),
        grant=_grant(issuer, anchor),
    )
    assert result.state is TurnState.PARKED
    part = result.parts[0]
    assert part.kind.value == "parked_request"
    assert part.access_mode.value == "AUTHOR_ONLY"
    assert part.author_principal == "operator@example.com"
    assert str(part.payload["request_id"]).startswith("prk_")
    assert result.usage.tool_calls == 1


def test_the_doom_loop_guard_resets_on_a_different_read() -> None:
    guard = DoomLoopGuard(threshold=3)
    assert not guard.observe("read", "a")
    assert not guard.observe("read", "b")
    assert not guard.observe("read", "a")
    assert not guard.observe("read", "a")
    assert guard.observe("read", "a")


def test_a_grant_that_does_not_cover_the_read_ends_the_turn_with_an_error(registry) -> None:
    """A refused grant is a stated failure, never a quietly degraded answer."""

    issuer = GrantIssuer()
    anchor = Anchor.record("incident", "INC-1042")
    grant = issuer.read_grant(
        principal="operator@example.com",
        scope=SCOPE,
        thread_id="thr_1",
        message_id="lms_1",
        attempt=1,
        anchor_label=anchor.label(),
        classification_ceiling="INTERNAL",
        policy_epoch=1,
        methods=frozenset({"catch_up"}),
    )
    result = run_turn(
        question="why",
        anchor=anchor,
        reader=_Ledger({("incident", "INC-1042"): {"id": "INC-1042"}}),
        registry=registry,
        composer=_LoopingComposer(),
        grant=grant,
    )
    assert result.state is TurnState.ERROR
    assert "does not authorize" in str(result.parts[0].payload["error"])


def test_a_grant_cannot_be_minted_already_expired() -> None:
    issuer = GrantIssuer()
    with pytest.raises(GrantError, match="must expire after"):
        issuer.read_grant(
            principal="operator@example.com",
            scope=SCOPE,
            thread_id="thr_1",
            message_id="lms_1",
            attempt=1,
            anchor_label="incident:INC-1042",
            classification_ceiling="INTERNAL",
            policy_epoch=1,
            ttl=timedelta(seconds=-1),
        )


def test_an_exhausted_budget_stops_visibly(registry) -> None:
    issuer = GrantIssuer()
    anchor = Anchor.record("incident", "INC-1042")
    result = run_turn(
        question="why",
        anchor=anchor,
        reader=_Ledger(),
        registry=registry,
        composer=_StaticComposer(Composition(model_calls=1)),
        grant=_grant(issuer, anchor),
        budget=TurnBudget(model_calls=0),
    )
    assert result.parts[0].kind.value == "budget_note"
    assert "model-call ceiling" in str(result.parts[0].payload["ceiling"])


def test_a_platform_screening_block_is_visible_and_contains_no_input(registry) -> None:
    issuer = GrantIssuer()
    anchor = Anchor.record("incident", "INC-1042")
    result = run_turn(
        question="untrusted inbound text",
        anchor=anchor,
        reader=_Ledger(),
        registry=registry,
        composer=_StaticComposer(Composition(screening_blocked=True)),
        grant=_grant(issuer, anchor),
    )

    assert [part.kind.value for part in result.parts] == ["content_withheld"]
    assert result.parts[0].payload == {
        "verdict": "MODEL_ARMOR_BLOCKED",
        "content_stored": False,
    }
    assert "untrusted inbound text" not in str(result.parts[0].payload)


def test_budget_ceilings_name_which_one_was_reached() -> None:
    budget = TurnBudget(tool_calls=1, model_calls=1, tokens=10)
    assert budget.exceeded_by(TurnUsage()) is None
    assert "tool-call" in (budget.exceeded_by(TurnUsage(tool_calls=2)) or "")
    assert "model-call" in (budget.exceeded_by(TurnUsage(model_calls=2)) or "")
    assert "token" in (budget.exceeded_by(TurnUsage(tokens=99)) or "")


def test_an_escalation_becomes_a_steer_draft_needing_confirmation(registry) -> None:
    issuer = GrantIssuer()
    anchor = Anchor.record("incident", "INC-1042")
    result = run_turn(
        question="what is the error rate now",
        anchor=anchor,
        reader=_Ledger(),
        registry=registry,
        composer=_StaticComposer(
            Composition(
                drafts=(ConnectiveDraft("LEAD_IN", "Here is what I can confirm."),),
                escalation=Escalation("no live telemetry", "request a bounded read"),
                suggested=("IS_IT_FIXED",),
            )
        ),
        grant=_grant(issuer, anchor),
    )
    kinds = [part.kind.value for part in result.parts]
    assert kinds == ["text", "steer_draft"]
    assert result.parts[1].payload["requires_confirmation"] is True
    assert result.suggested == ("IS_IT_FIXED",)
    assert result.sentences() == ("Here is what I can confirm.",)


def test_a_reader_without_authority_sees_withheld_parts_not_content(registry) -> None:
    issuer = GrantIssuer()
    anchor = Anchor.record("incident", "INC-1042")
    ledger = _Ledger(
        {
            ("incident", "INC-1042"): {"id": "INC-1042", "state": "MITIGATED"},
            ("evidence_item", "evd_1"): {"incident": "INC-1042", "statement": "a stored fact"},
        }
    )
    result = run_turn(
        question="what happened",
        anchor=anchor,
        reader=ledger,
        registry=registry,
        composer=_StaticComposer(
            Composition(
                drafts=(
                    ClaimDraft(
                        template_id="RECORD_STATEMENT",
                        subject_ref="INC-1042",
                        values={"quoted_text": "a stored fact"},
                        citations=(Citation("evidence_item", "evd_1"),),
                    ),
                )
            )
        ),
        grant=_grant(issuer, anchor),
    )
    assert [part.kind.value for part in result.parts] == ["claim"]

    # The same turn, projected for someone who may not see the cited evidence.
    projected = visible_parts(
        result,
        reader_principal="narrow@example.com",
        authorized_records=[("incident", "INC-1042")],
        participants=["narrow@example.com"],
    )
    assert [part.kind.value for part in projected] == ["content_withheld"]
    assert "outside your authority" in str(projected[0].payload["reason"])


class _AnchoredLedger(_Ledger):
    """A directory where authority comes from the anchor, not from a record.

    A record's own `incident` field is data the projection copied; it is the
    entity set of the turn's anchor that decides what this grant may reach.
    """

    def __init__(self, records, *, reachable) -> None:  # type: ignore[no-untyped-def]
        super().__init__(records)
        self._reachable = tuple(reachable)

    def authorized_records_for_anchor(self, anchor) -> tuple[tuple[str, str], ...]:  # type: ignore[no-untyped-def]
        del anchor
        return self._reachable


def _planted_ledger(reachable) -> _AnchoredLedger:  # type: ignore[no-untyped-def]
    return _AnchoredLedger(
        {
            ("incident", "INC-1042"): {"id": "INC-1042", "state": "MITIGATED"},
            # Readable by this principal somewhere in the workspace, and it
            # even names the anchored incident — but the grant's anchor entity
            # set never contained it.
            ("evidence_item", "evd_planted"): {
                "incident": "INC-1042",
                "statement": "the fault was fully contained",
            },
        },
        reachable=reachable,
    )


def _quote_composer() -> _StaticComposer:
    return _StaticComposer(
        Composition(
            drafts=(
                ClaimDraft(
                    template_id="RECORD_STATEMENT",
                    subject_ref="INC-1042",
                    values={"quoted_text": "the fault was fully contained"},
                    citations=(Citation("evidence_item", "evd_planted"),),
                ),
            )
        )
    )


def test_the_claim_gate_verifies_through_the_grant_rather_than_around_it(registry) -> None:
    """A model-drafted citation the anchor never covered cannot be rendered.

    The gate used to resolve citations, fill slots, and evaluate predicates
    through the raw reader while the drafter read through the grant. So the
    one thing the grant exists to bound — which records this turn may stand on
    — was enforced against the model's exploration and then dropped at the
    moment the claim became a delivered fact.
    """

    issuer = GrantIssuer()
    anchor = Anchor.record("incident", "INC-1042")
    result = run_turn(
        question="what happened",
        anchor=anchor,
        reader=_planted_ledger((("incident", "INC-1042"),)),
        registry=registry,
        composer=_quote_composer(),
        grant=_grant(issuer, anchor),
    )
    assert result.state is TurnState.COMPLETED
    assert result.parts == ()
    assert result.sentences() == ()
    assert result.defects.unresolved_citations == 1
    assert "do not resolve" in " ".join(result.defects.reasons)
    # The gate's own reads are authorized and counted, but they are not the
    # drafter's tool calls and must not be charged to that ceiling.
    assert result.usage.verification_reads > 0
    assert result.usage.tool_calls == 0

    # The identical draft is delivered once the anchor's entity set covers it.
    covered = run_turn(
        question="what happened",
        anchor=anchor,
        reader=_planted_ledger(
            (("incident", "INC-1042"), ("evidence_item", "evd_planted")),
        ),
        registry=registry,
        composer=_quote_composer(),
        grant=_grant(issuer, anchor),
    )
    assert [part.kind.value for part in covered.parts] == ["claim"]
    assert covered.sentences() == ("the fault was fully contained",)


def test_verifying_several_claims_is_not_mistaken_for_a_doom_loop(registry) -> None:
    """Verification re-reads the same record by design; that is not a loop.

    One claim reads its cited record to resolve the citation, again for each
    record-bound slot, and again inside the predicate. Watching those with the
    drafter's guard would park every well-cited answer as a repeated read.
    """

    issuer = GrantIssuer()
    anchor = Anchor.record("incident", "INC-1042")
    draft = ClaimDraft(
        template_id="STATE_REPORT",
        subject_ref="INC-1042",
        values={"subject_label": "INC-1042", "state": "MITIGATED"},
        citations=(Citation("incident", "INC-1042"),),
    )
    result = run_turn(
        question="what is the state",
        anchor=anchor,
        reader=_Ledger({("incident", "INC-1042"): {"id": "INC-1042", "state": "MITIGATED"}}),
        registry=registry,
        composer=_StaticComposer(Composition(drafts=(draft, draft, draft, draft))),
        grant=_grant(issuer, anchor),
        budget=TurnBudget(tool_calls=1, model_calls=1, tokens=10),
    )
    assert result.state is TurnState.COMPLETED
    assert [part.kind.value for part in result.parts] == ["claim"] * 4
    assert result.usage.tool_calls == 0
    assert result.usage.verification_reads >= 4


def test_a_grant_that_lapses_before_the_gate_ends_the_turn_with_an_error(registry) -> None:
    """An expired authority is stated, never rendered as a short answer."""

    issuer = GrantIssuer()
    anchor = Anchor.record("incident", "INC-1042")
    grant = issuer.read_grant(
        principal="operator@example.com",
        scope=SCOPE,
        thread_id="thr_1",
        message_id="lms_1",
        attempt=1,
        anchor_label=anchor.label(),
        classification_ceiling="INTERNAL",
        policy_epoch=1,
        now=datetime.now(UTC) - timedelta(minutes=20),
    )
    result = run_turn(
        question="what happened",
        anchor=anchor,
        reader=_planted_ledger(
            (("incident", "INC-1042"), ("evidence_item", "evd_planted")),
        ),
        registry=registry,
        # A composer that reads nothing, so only the gate meets the grant.
        composer=_quote_composer(),
        grant=grant,
    )
    assert result.state is TurnState.ERROR
    assert "expired" in str(result.parts[0].payload["error"])


def test_the_turn_reports_the_ceilings_it_actually_ran_under(registry) -> None:
    """One source for the budget, so nothing downstream keeps its own copy.

    The response model and the browser each used to restate 25/10/60,000, which
    meant a changed ceiling silently left two of the three lying to the reader.
    """

    issuer = GrantIssuer()
    anchor = Anchor.record("incident", "INC-1042")
    ceilings = TurnBudget(tool_calls=3, model_calls=2, tokens=1_000)
    result = run_turn(
        question="Is it fixed?",
        anchor=anchor,
        reader=_Ledger({("incident", "INC-1042"): {"id": "INC-1042", "state": "MITIGATED"}}),
        registry=registry,
        composer=EnumeratedComposer(),
        grant=_grant(issuer, anchor),
        budget=ceilings,
    )
    assert result.budget is ceilings
    assert result.budget.as_dict() == {"tool_calls": 3, "model_calls": 2, "tokens": 1_000}


def test_configured_ceilings_never_widen_themselves_away(monkeypatch) -> None:
    """Absent or unparsable configuration takes the specification default.

    A ceiling that disappears when a variable is mistyped is not a ceiling.
    """

    monkeypatch.setenv("SOLVAN_LIAISON_TURN_TOOL_CALLS", "5")
    monkeypatch.setenv("SOLVAN_LIAISON_TURN_MODEL_CALLS", "not-a-number")
    monkeypatch.setenv("SOLVAN_LIAISON_TURN_TOKENS", "0")
    budget = default_turn_budget()
    assert budget.tool_calls == 5
    assert budget.model_calls == 10
    assert budget.tokens == 60_000

    monkeypatch.setenv("SOLVAN_LIAISON_THREAD_DAILY_MODEL_CALLS", "-1")
    daily = default_daily_budget()
    assert daily.thread_model_calls == 200
    assert daily.principal_model_calls == 500
