"""Lazy, hash-bound loading of already-selected Operational Guidance content."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from solvan.application.operational_guidance import GuidanceError
from solvan.application.tool_output_security import secure_tool_output


class SelectedGuidance(Protocol):
    @property
    def selection_id(self) -> str: ...

    @property
    def content_ref(self) -> str: ...

    @property
    def content_hash(self) -> str: ...

    @property
    def selected(self) -> bool: ...


class GuidanceObjectReader(Protocol):
    def get_json(self, *, uri: str, expected_hash: str, max_bytes: int) -> dict[str, Any]: ...


class GuidanceFetchAudit(Protocol):
    def __call__(
        self,
        *,
        selection_id: str,
        content_hash: str,
        outcome: str,
        reason_codes: tuple[str, ...],
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class LoadedGuidanceContent:
    selection_id: str
    content_hash: str
    value: dict[str, Any]
    reason_codes: tuple[str, ...]


def load_selected_guidance(
    *,
    selection: SelectedGuidance,
    reader: GuidanceObjectReader,
    audit: GuidanceFetchAudit,
) -> LoadedGuidanceContent:
    """Fetch only after selection, verify bytes, and re-scan before prompt use."""

    if not selection.selected:
        raise GuidanceError("guidance content cannot be fetched before durable selection")
    try:
        document = reader.get_json(
            uri=selection.content_ref,
            expected_hash=selection.content_hash,
            max_bytes=262_144,
        )
    except Exception as error:
        retrieval_reasons = ("CONTENT_RETRIEVAL_OR_HASH_FAILED",)
        audit(
            selection_id=selection.selection_id,
            content_hash=selection.content_hash,
            outcome="BLOCKED",
            reason_codes=retrieval_reasons,
        )
        raise GuidanceError("selected guidance content failed exact retrieval") from error
    secured = secure_tool_output(document)
    if secured.reason_codes:
        security_reasons = tuple(secured.reason_codes)
        audit(
            selection_id=selection.selection_id,
            content_hash=selection.content_hash,
            outcome="BLOCKED",
            reason_codes=security_reasons,
        )
        raise GuidanceError("selected guidance content failed the second security scan")
    audit(
        selection_id=selection.selection_id,
        content_hash=selection.content_hash,
        outcome="ALLOWED",
        reason_codes=("HASH_AND_SECOND_SCAN_PASSED",),
    )
    return LoadedGuidanceContent(
        selection_id=selection.selection_id,
        content_hash=selection.content_hash,
        value=secured.value,
        reason_codes=("HASH_AND_SECOND_SCAN_PASSED",),
    )
