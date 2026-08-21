"""Typed durable agent-result commits after provider-boundary validation."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from solvan.application.investigation import CoordinatorAuthority
from solvan.domain import Scope


class AgentResultConflict(RuntimeError):
    """A result does not match the live durable attempt or evidence ledger."""


class AgentSemanticStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class FindingKind(StrEnum):
    OBSERVATION = "OBSERVATION"
    INFERENCE = "INFERENCE"


@dataclass(frozen=True, slots=True)
class FindingCommit:
    finding_key: str
    kind: FindingKind
    statement: str
    evidence_refs: tuple[str, ...]
    confidence: float | None = None
    contradiction_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.finding_key.strip() or not self.statement.strip() or not self.evidence_refs:
            raise ValueError("finding key, statement, and supporting citations are required")
        if self.confidence is not None and not 0 <= self.confidence <= 1:
            raise ValueError("finding confidence must be between zero and one")


@dataclass(frozen=True, slots=True)
class AgentCompletion:
    agent_resource: str
    agent_revision: str
    invocation_id: str
    incident_id: str
    workflow_version: int
    input_scope_hash: str
    output_ref: str
    output_hash: str
    output_size_bytes: int
    semantic_status: AgentSemanticStatus
    summary: str
    evidence_refs: tuple[str, ...]
    findings: tuple[FindingCommit, ...]
    completed_at: datetime
    trace_id: str

    def __post_init__(self) -> None:
        if self.output_size_bytes < 1:
            raise ValueError("agent output must be nonempty")
        if self.completed_at.tzinfo is None or self.completed_at.utcoffset() is None:
            raise ValueError("agent completion timestamp must be timezone-aware")


class AgentCompletionDisposition(StrEnum):
    APPLIED = "APPLIED"
    DUPLICATE = "DUPLICATE"
    STALE = "STALE"
    REJECTED = "REJECTED"


@dataclass(frozen=True, slots=True)
class AgentCompletionRecord:
    run_id: str
    step_id: str
    disposition: AgentCompletionDisposition
    finding_ids: tuple[str, ...] = ()
    reason_code: str | None = None


class AgentResultRepository(Protocol):
    def transaction(self) -> AbstractContextManager[None]: ...

    def commit_agent_completion(
        self,
        *,
        scope: Scope,
        authority: CoordinatorAuthority,
        completion: AgentCompletion,
    ) -> AgentCompletionRecord: ...


class AgentResultCoordinator:
    def __init__(self, repository: AgentResultRepository) -> None:
        self._repository = repository

    def complete(
        self,
        *,
        scope: Scope,
        authority: CoordinatorAuthority,
        completion: AgentCompletion,
    ) -> AgentCompletionRecord:
        with self._repository.transaction():
            return self._repository.commit_agent_completion(
                scope=scope,
                authority=authority,
                completion=completion,
            )
