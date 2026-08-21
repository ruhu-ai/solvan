"""Deterministic, reader-scoped context compilation for Liaison turns.

The provider never receives a replayed transcript.  This module turns the
canonical ledger projection into a small, typed reference envelope.  It is
deliberately provider independent: ADK, a local test runner, and a future
provider all receive the same manifest inputs and therefore cannot create a
second source of conversation authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any


class ContextCompilationError(ValueError):
    """The requested context cannot be compiled without weakening a gate."""


_RANK = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2}
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _digest(value: Any) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def _bytes(value: str) -> int:
    return max(1, len(value.encode("utf-8")))


@dataclass(frozen=True, slots=True)
class TranscriptPart:
    id: str
    kind: str
    digest: str
    classification: str
    visible: bool = True
    access_verdict_ref: str | None = None
    text: str = ""

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("transcript part id must be non-empty")
        if not self.kind.strip():
            raise ValueError("transcript part kind must be non-empty")
        if not _SHA256.fullmatch(self.digest):
            raise ValueError("transcript part digest must be a sha256 digest")
        if self.classification not in _RANK:
            raise ValueError("transcript part classification is not supported")
        if self.visible and (
            self.access_verdict_ref is None or not self.access_verdict_ref.strip()
        ):
            raise ValueError("visible transcript part requires an access verdict")


@dataclass(frozen=True, slots=True)
class TranscriptMessage:
    id: str
    role: str
    turn_state: str
    stream_position: int
    classification: str
    parts: tuple[TranscriptPart, ...] = ()
    in_reply_to_message_id: str | None = None
    redaction_complete: bool = True
    visible: bool = True


@dataclass(frozen=True, slots=True)
class CompactionCandidate:
    part_id: str
    digest: str
    source_message_ids: tuple[str, ...]
    classification: str
    access_verdict_ref: str
    visible: bool = True
    token_count: int = 0
    created_at: datetime | None = None

    def __post_init__(self) -> None:
        """Reject malformed durable metadata before it can affect selection.

        Compactions are persisted projections, not free-form provider output.
        A malformed timestamp would make recency ordering depend on a runtime
        exception (or a naive/aware comparison), while an invalid digest or
        empty source envelope would make the resulting context unverifiable.
        Fail closed at the value boundary so every compiler caller gets the
        same behavior.
        """

        if not self.part_id.strip():
            raise ValueError("compaction part_id must be non-empty")
        if not _SHA256.fullmatch(self.digest):
            raise ValueError("compaction digest must be a sha256 digest")
        if not self.source_message_ids or any(
            not source_id.strip() for source_id in self.source_message_ids
        ):
            raise ValueError("compaction source_message_ids must be non-empty")
        if len(set(self.source_message_ids)) != len(self.source_message_ids):
            raise ValueError("compaction source_message_ids must be unique")
        if self.classification not in _RANK:
            raise ValueError("compaction classification is not supported")
        if not self.access_verdict_ref.strip():
            raise ValueError("compaction access_verdict_ref must be non-empty")
        if self.token_count < 0:
            raise ValueError("compaction token_count cannot be negative")
        if self.created_at is not None and (
            self.created_at.tzinfo is None or self.created_at.utcoffset() is None
        ):
            raise ValueError("compaction created_at must be timezone-aware")


@dataclass(frozen=True, slots=True)
class ReferenceCandidate:
    kind: str
    ref: str
    digest: str
    classification: str = "INTERNAL"
    access_verdict_ref: str = "reference-access"
    authoritative: bool = False

    def __post_init__(self) -> None:
        if not self.kind.strip():
            raise ValueError("reference kind must be non-empty")
        if not self.ref.strip():
            raise ValueError("reference ref must be non-empty")
        if not _SHA256.fullmatch(self.digest):
            raise ValueError("reference digest must be a sha256 digest")
        if self.classification not in _RANK:
            raise ValueError("reference classification is not supported")
        if not self.access_verdict_ref.strip():
            raise ValueError("reference access verdict must be non-empty")


@dataclass(frozen=True, slots=True)
class ContextBudget:
    model_input_limit: int = 1_000_000
    stable_prefix_tokens: int = 1_200
    reserved_output_tokens: int = 8_192
    safety_margin_tokens: int = 8_192
    working_context_token_ceiling: int = 60_000
    preserve_recent_tokens: int = 8_000
    ttl_seconds: int = 300

    def __post_init__(self) -> None:
        if self.model_input_limit < 1:
            raise ValueError("model input limit must be positive")
        if self.stable_prefix_tokens < 0:
            raise ValueError("stable prefix token budget cannot be negative")
        if self.reserved_output_tokens < 1:
            raise ValueError("reserved output token budget must be positive")
        if self.safety_margin_tokens < 1:
            raise ValueError("safety margin token budget must be positive")
        if self.working_context_token_ceiling < 1:
            raise ValueError("working context token ceiling must be positive")
        if self.preserve_recent_tokens < 0:
            raise ValueError("preserved recent token budget cannot be negative")
        if not 1 <= self.ttl_seconds <= 3600:
            raise ValueError("working context TTL must be between one second and one hour")
        if self.usable <= 0:
            raise ValueError("context budget has no usable model input")

    @property
    def usable(self) -> int:
        return (
            self.model_input_limit
            - self.stable_prefix_tokens
            - self.reserved_output_tokens
            - self.safety_margin_tokens
        )

    @property
    def dynamic_ceiling(self) -> int:
        return min(self.working_context_token_ceiling, self.usable)


@dataclass(frozen=True, slots=True)
class CompiledContext:
    items: tuple[dict[str, Any], ...]
    resolved_references: tuple[dict[str, Any], ...]
    source_versions: tuple[dict[str, Any], ...]
    omitted_counts: dict[str, Any]
    token_budget: dict[str, int]
    compiled_at: datetime
    expires_at: datetime
    stable_prefix_digest: str
    variable_suffix_digest: str
    context_digest: str
    processors: tuple[str, ...] = field(default_factory=tuple)


def select_complete_turns(
    messages: Sequence[TranscriptMessage],
    *,
    current_user_id: str,
    classification_ceiling: str,
) -> tuple[tuple[TranscriptMessage, TranscriptMessage], ...]:
    """Select only visible, complete USER/LIAISON pairs before the current turn."""

    by_id = {message.id: message for message in messages}
    pairs: list[tuple[TranscriptMessage, TranscriptMessage]] = []
    for answer in sorted(messages, key=lambda value: value.stream_position):
        if answer.id == current_user_id or answer.role != "LIAISON":
            continue
        if answer.turn_state != "COMPLETED" or not answer.visible:
            continue
        if answer.in_reply_to_message_id is None:
            continue
        user = by_id.get(answer.in_reply_to_message_id)
        if user is None or user.id == current_user_id or user.role != "USER":
            continue
        if any(not part.visible for part in (*user.parts, *answer.parts)):
            continue
        if (
            user.turn_state != "COMPLETED"
            or not user.visible
            or not user.redaction_complete
            or not answer.redaction_complete
        ):
            continue
        if not all(part.visible for part in (*user.parts, *answer.parts)):
            continue
        if _RANK.get(user.classification, 99) > _RANK.get(classification_ceiling, -1):
            continue
        if _RANK.get(answer.classification, 99) > _RANK.get(classification_ceiling, -1):
            continue
        pairs.append((user, answer))
    return tuple(pairs)


def select_compaction(
    candidates: Sequence[CompactionCandidate],
    *,
    source_ids: set[str],
    classification_ceiling: str,
) -> CompactionCandidate | None:
    """Pick the newest eligible compaction whose source envelope is intact."""

    eligible = [
        item
        for item in candidates
        if item.visible
        and set(item.source_message_ids).issubset(source_ids)
        and _RANK.get(item.classification, 99) <= _RANK.get(classification_ceiling, -1)
    ]
    if not eligible:
        return None
    # Persistence supplies newest-first rows, but the pure compiler must not
    # silently depend on a caller's incidental ordering.  A missing timestamp
    # preserves the supplied order; a bound timestamp makes “newest” explicit.
    return max(
        enumerate(eligible),
        key=lambda value: (value[1].created_at or datetime.min.replace(tzinfo=UTC), -value[0]),
    )[1]


def _part_digest(message: TranscriptMessage) -> str:
    return _digest(
        {
            "message": message.id,
            "parts": [(part.id, part.kind, part.digest) for part in message.parts],
        }
    )


def compile_context(
    *,
    current_user: TranscriptMessage,
    history: Sequence[TranscriptMessage] = (),
    compactions: Sequence[CompactionCandidate] = (),
    references: Sequence[ReferenceCandidate] = (),
    source_versions: Sequence[Mapping[str, str]] = (),
    classification_ceiling: str,
    budget: ContextBudget | None = None,
    now: datetime | None = None,
    current_user_text: str | None = None,
    stable_prefix_material: Mapping[str, Any] | None = None,
) -> CompiledContext:
    """Run the named §12.1 processors in order and emit manifest material."""

    budget = budget or ContextBudget()
    if current_user.role != "USER" or current_user.turn_state != "COMPLETED":
        raise ContextCompilationError("current user message is not a complete terminal message")
    if not current_user.visible or not current_user.redaction_complete:
        raise ContextCompilationError("current user message is withheld or unclassified")
    if _RANK.get(classification_ceiling, -1) < _RANK.get(current_user.classification, 99):
        raise ContextCompilationError("current user exceeds the classification ceiling")
    if budget.usable <= 0 or budget.dynamic_ceiling <= 0:
        raise ContextCompilationError("context budget has no usable model input")

    processors = (
        "validate_bindings",
        "filter_reader_projection",
        "select_complete_turns",
        "select_compaction_and_pinned_tail",
        "resolve_typed_references",
        "add_artifact_and_memory_refs",
        "prune_and_budget",
        "assemble_stable_prefix_and_variable_suffix",
    )
    pairs = select_complete_turns(
        history,
        current_user_id=current_user.id,
        classification_ceiling=classification_ceiling,
    )
    eligible_ids = {message.id for pair in pairs for message in pair}
    tail_pairs = list(pairs)
    # Keep the newest complete turns verbatim. Older source turns represented by
    # a compaction never appear a second time.
    tail: list[tuple[TranscriptMessage, TranscriptMessage]] = []
    tail_tokens = 0
    for pair in reversed(tail_pairs):
        pair_tokens = sum(
            _bytes(part.text) for message in pair for part in message.parts if part.text
        )
        if tail and tail_tokens + pair_tokens > budget.preserve_recent_tokens:
            break
        if not tail and pair_tokens > budget.preserve_recent_tokens:
            # A single oversized historical turn is represented by its digest,
            # never silently clipped into model input.
            break
        tail.insert(0, pair)
        tail_tokens += pair_tokens

    pinned_ids = {message.id for pair in tail for message in pair}
    compaction = select_compaction(
        compactions,
        source_ids=eligible_ids - pinned_ids,
        classification_ceiling=classification_ceiling,
    )
    compacted_ids = set(compaction.source_message_ids) if compaction else set()

    items: list[dict[str, Any]] = []
    if compaction and not (
        set(compaction.source_message_ids) & {message.id for pair in tail for message in pair}
    ):
        items.append(
            {
                "sequence": 0,
                "kind": "COMPACTION",
                "ref": f"part:{compaction.part_id}",
                "digest": compaction.digest,
                "token_count": compaction.token_count,
                "classification": compaction.classification,
                "trust": "UNTRUSTED_CONTEXT_ONLY",
                "access_verdict_ref": compaction.access_verdict_ref,
            }
        )
    for user, answer in tail:
        if user.id in compacted_ids or answer.id in compacted_ids:
            continue
        digest = _digest(
            {"user": user.id, "answer": answer.id, "answer_digest": _part_digest(answer)}
        )
        items.append(
            {
                "sequence": 0,
                "kind": "THREAD_TURN",
                "ref": f"turn:{user.id}:{answer.id}",
                "digest": digest,
                "token_count": sum(
                    _bytes(part.text)
                    for message in (user, answer)
                    for part in message.parts
                    if part.text
                ),
                "classification": max(
                    (user.classification, answer.classification), key=lambda value: _RANK[value]
                ),
                "trust": "UNTRUSTED_CONTEXT_ONLY",
                "access_verdict_ref": f"turn-access:{user.id}:{answer.id}",
            }
        )
    selected_references: list[ReferenceCandidate] = []
    for reference in references:
        if _RANK.get(reference.classification, 99) > _RANK.get(classification_ceiling, -1):
            continue
        selected_references.append(reference)
        items.append(
            {
                "sequence": 0,
                "kind": "RECORD" if reference.authoritative else "MEMORY_REF",
                "ref": reference.ref,
                "digest": reference.digest,
                "token_count": 0,
                "classification": reference.classification,
                "trust": "AUTHORITATIVE_REFERENCE"
                if reference.authoritative
                else "UNTRUSTED_CONTEXT_ONLY",
                "access_verdict_ref": reference.access_verdict_ref,
            }
        )
    derived_current_text = " ".join(part.text for part in current_user.parts if part.text)
    if current_user_text is not None and current_user_text != derived_current_text:
        raise ContextCompilationError("current user text does not match the stored message parts")
    current_text = derived_current_text
    current = {
        "sequence": 0,
        "kind": "CURRENT_USER",
        "ref": f"message:{current_user.id}",
        "digest": _digest(
            {
                "message": current_user.id,
                "content_hash": [part.digest for part in current_user.parts],
            }
        ),
        "token_count": _bytes(current_text),
        "classification": current_user.classification,
        "trust": "UNTRUSTED_USER_CONTENT",
        "access_verdict_ref": f"message-access:{current_user.id}",
    }
    mandatory = [*items, current]
    if _bytes(current_text) > budget.dynamic_ceiling:
        raise ContextCompilationError("current user message exceeds dynamic context ceiling")
    omitted_budget = sum(
        1
        for pair in pairs
        if not ({message.id for message in pair} & pinned_ids)
        and not ({message.id for message in pair} & compacted_ids)
    )
    selected = list(mandatory)
    selected_tokens = sum(int(item["token_count"]) for item in selected)
    while selected_tokens > budget.dynamic_ceiling and len(selected) > 1:
        removable = next((item for item in selected if item["kind"] != "CURRENT_USER"), None)
        if removable is None:
            break
        selected.remove(removable)
        selected_tokens -= int(removable["token_count"])
        omitted_budget += 1
    if selected_tokens > budget.dynamic_ceiling:
        raise ContextCompilationError("mandatory current context cannot fit model input")
    if omitted_budget:
        selected.insert(
            0,
            {
                "sequence": 0,
                "kind": "TRUNCATION_MARKER",
                "ref": "truncation:budget",
                "digest": _digest({"omitted": omitted_budget}),
                "token_count": 0,
                "classification": "PUBLIC",
                "trust": "UNTRUSTED_CONTEXT_ONLY",
                "access_verdict_ref": None,
            },
        )
    for index, item in enumerate(selected, start=1):
        item["sequence"] = index
    compiled_at = now or datetime.now(UTC)
    if compiled_at.tzinfo is None or compiled_at.utcoffset() is None:
        raise ContextCompilationError("compilation time must be timezone-aware")
    variable_digest = _digest(selected)
    # The stable prefix is intentionally represented by its digest only.  It
    # contains static instructions and registry/schema bindings, never tenant
    # data or transcript text.  Callers must provide the exact immutable
    # material they bind into the provider request; a default remains useful
    # for the pure compiler contract tests.
    stable_digest = _digest(
        stable_prefix_material
        if stable_prefix_material is not None
        else {"revision": "solvan-liaison-query-planner-v1"}
    )
    return CompiledContext(
        items=tuple(selected),
        resolved_references=tuple(
            {"kind": ref.kind, "ref": ref.ref} for ref in selected_references
        ),
        source_versions=tuple(dict(value) for value in source_versions),
        omitted_counts={
            "expired_or_purged": 0,
            "superseded": 0,
            "budget": omitted_budget,
            "context_reduced_by_policy": False,
        },
        token_budget={
            "model_input_limit": budget.model_input_limit,
            "stable_prefix_tokens": budget.stable_prefix_tokens,
            "reserved_output_tokens": budget.reserved_output_tokens,
            "safety_margin_tokens": budget.safety_margin_tokens,
            "dynamic_context_ceiling": budget.dynamic_ceiling,
            "actual_context_tokens": selected_tokens,
        },
        compiled_at=compiled_at,
        expires_at=compiled_at + timedelta(seconds=budget.ttl_seconds),
        stable_prefix_digest=stable_digest,
        variable_suffix_digest=variable_digest,
        context_digest=variable_digest,
        processors=processors,
    )


def context_from_rows(
    *,
    current_user: Mapping[str, Any],
    history: Iterable[Mapping[str, Any]],
    classification_ceiling: str,
    current_user_text: str,
) -> CompiledContext:
    """Adapter for persistence rows; no database objects enter the compiler."""

    def part(value: Mapping[str, Any]) -> TranscriptPart:
        status = str(value.get("status", "COMPLETED"))
        is_completed = status == "COMPLETED"
        return TranscriptPart(
            id=str(value["id"]),
            kind=str(value.get("kind", "text")),
            digest=str(value.get("digest") or _digest(value.get("payload", {}))),
            classification=str(value.get("classification", "INTERNAL")),
            # A streaming row is never eligible for model context, even when
            # a transport adapter accidentally marks it visible.  The
            # initiating reader may watch it in the private transcript view,
            # but only the completed projection can enter a manifest.
            visible=bool(value.get("visible", True)) and is_completed,
            access_verdict_ref=value.get("access_verdict_ref"),
            text=str(value.get("text", "")) if is_completed else "",
        )

    def message(value: Mapping[str, Any]) -> TranscriptMessage:
        return TranscriptMessage(
            id=str(value["id"]),
            role=str(value["role"]),
            turn_state=str(value.get("turn_state", "COMPLETED")),
            stream_position=int(value.get("stream_position", 0)),
            classification=str(value.get("classification", "INTERNAL")),
            parts=tuple(part(item) for item in value.get("parts", ())),
            in_reply_to_message_id=value.get("in_reply_to_message_id"),
            redaction_complete=bool(value.get("redaction_complete", True)),
            visible=bool(value.get("visible", True)),
        )

    current = message(current_user)
    return compile_context(
        current_user=current,
        history=tuple(message(value) for value in history),
        classification_ceiling=classification_ceiling,
        current_user_text=current_user_text,
    )
