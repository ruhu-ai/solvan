"""Governed memory candidate, promotion, and fail-open recall services."""

from __future__ import annotations

import hashlib
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from solvan.domain import (
    MemoryCandidateProposal,
    MemoryGateDecision,
    MemoryGatePolicy,
    MemoryScope,
    evaluate_memory_candidate,
    new_identifier,
)


class MemoryConflict(RuntimeError):
    """The local candidate or promotion state no longer grants authority."""


class MemoryBankUnavailable(RuntimeError):
    """Memory Bank could not safely serve the requested operation."""


@dataclass(frozen=True, slots=True)
class StoredMemoryCandidate:
    candidate_id: str
    proposal: MemoryCandidateProposal
    decision: MemoryGateDecision


@dataclass(frozen=True, slots=True)
class PromotionCandidate:
    candidate_id: str
    exact_scope: MemoryScope
    fact_text: str
    content_hash: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class MemoryBankReceipt:
    memory_resource: str
    memory_revision: str | None
    exact_scope: MemoryScope
    fact_text: str


@dataclass(frozen=True, slots=True)
class MemoryPromotionRecord:
    promotion_id: str
    candidate_id: str
    memory_resource: str
    memory_revision: str | None
    exact_scope: MemoryScope
    content_hash: str
    retention_until: datetime


@dataclass(frozen=True, slots=True)
class PromotionPreparation:
    candidate: PromotionCandidate | None
    completed: MemoryPromotionRecord | None

    def __post_init__(self) -> None:
        if (self.candidate is None) == (self.completed is None):
            raise ValueError("promotion preparation must contain exactly one outcome")


@dataclass(frozen=True, slots=True)
class MemoryHint:
    memory_resource: str
    fact_text: str
    exact_scope: MemoryScope
    memory_revision: str | None = None
    distance: float | None = None
    source_refs: tuple[str, ...] = ()
    trust_label: str = "UNTRUSTED_HISTORICAL_CONTEXT"

    def __post_init__(self) -> None:
        if self.trust_label != "UNTRUSTED_HISTORICAL_CONTEXT":
            raise ValueError("retrieved memory cannot be promoted to trusted authority")


class MemoryCandidateRepository(Protocol):
    def transaction(self) -> AbstractContextManager[None]: ...

    def save_candidate(self, candidate: StoredMemoryCandidate) -> None: ...

    def begin_promotion(
        self, *, candidate_id: str, promoter_identity: str, now: datetime
    ) -> PromotionPreparation: ...

    def complete_promotion(
        self,
        *,
        candidate: PromotionCandidate,
        receipt: MemoryBankReceipt,
        promoter_identity: str,
        now: datetime,
    ) -> MemoryPromotionRecord: ...


class MemoryBankPort(Protocol):
    def upsert_exact(self, *, exact_scope: MemoryScope, fact_text: str) -> MemoryBankReceipt: ...

    def retrieve_exact(self, *, exact_scope: MemoryScope) -> tuple[MemoryHint, ...]: ...


@dataclass(frozen=True, slots=True)
class MemoryReadGrant:
    grant_ref: str
    audience: str
    exact_scope: MemoryScope
    expires_at: datetime

    def validate(self, *, now: datetime, audience: str, exact_scope: MemoryScope) -> None:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("memory search time must be timezone-aware")
        if (
            not self.grant_ref.strip()
            or self.audience != audience
            or self.exact_scope != exact_scope
            or self.expires_at <= now
        ):
            raise MemoryConflict("memory read grant is absent, expired, or audience mismatched")


@dataclass(frozen=True, slots=True)
class MemorySearchQuery:
    exact_scope: MemoryScope
    read_grant: MemoryReadGrant
    objective: str
    maximum_results: int
    token_budget: int
    current_time_cutoff: datetime

    def validate(self, *, audience: str) -> None:
        objective = self.objective.strip()
        if not objective or len(objective) > 1_000:
            raise ValueError("memory search objective must contain at most 1000 characters")
        if not 1 <= self.maximum_results <= 20 or not 32 <= self.token_budget <= 4_096:
            raise ValueError("memory search result or token budget is outside bounds")
        self.read_grant.validate(
            now=self.current_time_cutoff,
            audience=audience,
            exact_scope=self.exact_scope,
        )


@dataclass(frozen=True, slots=True)
class MemorySearchCandidate:
    memory_resource: str
    fact_text: str
    exact_scope: MemoryScope
    memory_revision: str | None
    distance: float

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(self.fact_text.strip().encode()).hexdigest()


class MemorySearchPort(Protocol):
    def search(self, *, query: MemorySearchQuery) -> tuple[MemorySearchCandidate, ...]: ...


class MemorySearchRepository(Protocol):
    def revalidate_search_hits(
        self,
        *,
        exact_scope: MemoryScope,
        candidates: tuple[MemorySearchCandidate, ...],
        now: datetime,
    ) -> tuple[MemoryHint, ...]: ...


class GovernedMemorySearchService:
    """Treat semantic results as hints only after exact SQL revalidation."""

    def __init__(
        self,
        *,
        search_port: MemorySearchPort,
        repository: MemorySearchRepository,
        audience: str = "evidence-agent",
    ) -> None:
        self._search_port = search_port
        self._repository = repository
        self._audience = audience

    def search(self, *, query: MemorySearchQuery) -> tuple[MemoryHint, ...]:
        query.validate(audience=self._audience)
        try:
            candidates = self._search_port.search(query=query)
        except MemoryBankUnavailable:
            return ()
        if len(candidates) > query.maximum_results:
            raise MemoryBankUnavailable("Memory Bank exceeded the requested result bound")
        hints = self._repository.revalidate_search_hits(
            exact_scope=query.exact_scope,
            candidates=candidates,
            now=query.current_time_cutoff,
        )
        bounded: list[MemoryHint] = []
        used_tokens = 0
        for hint in hints:
            estimated = max(1, (len(hint.fact_text) + 3) // 4)
            if used_tokens + estimated > query.token_budget:
                break
            used_tokens += estimated
            bounded.append(hint)
        return tuple(bounded)


class MemoryCandidateService:
    def __init__(self, repository: MemoryCandidateRepository) -> None:
        self._repository = repository

    def evaluate_and_store(
        self,
        *,
        proposal: MemoryCandidateProposal,
        policy: MemoryGatePolicy,
        now: datetime,
    ) -> StoredMemoryCandidate:
        decision = evaluate_memory_candidate(proposal, policy=policy, now=now)
        candidate = StoredMemoryCandidate(new_identifier("memc"), proposal, decision)
        with self._repository.transaction():
            self._repository.save_candidate(candidate)
        return candidate


class MemoryPromotionService:
    """Reconcile-before-create without holding a database transaction externally."""

    def __init__(self, repository: MemoryCandidateRepository, memory_bank: MemoryBankPort) -> None:
        self._repository = repository
        self._memory_bank = memory_bank

    def promote(
        self, *, candidate_id: str, promoter_identity: str, now: datetime
    ) -> MemoryPromotionRecord:
        if not promoter_identity.strip():
            raise ValueError("promoter identity is required")
        with self._repository.transaction():
            preparation = self._repository.begin_promotion(
                candidate_id=candidate_id,
                promoter_identity=promoter_identity,
                now=now,
            )
        if preparation.completed is not None:
            return preparation.completed
        candidate = preparation.candidate
        if candidate is None:  # pragma: no cover - dataclass invariant
            raise AssertionError("promotion preparation has no candidate")

        # A failure here deliberately leaves PROMOTING for a later reconciler.
        receipt = self._memory_bank.upsert_exact(
            exact_scope=candidate.exact_scope,
            fact_text=candidate.fact_text,
        )
        with self._repository.transaction():
            return self._repository.complete_promotion(
                candidate=candidate,
                receipt=receipt,
                promoter_identity=promoter_identity,
                now=now,
            )


class MemoryRecallService:
    """Recall is optional context and therefore degrades to no hints."""

    def __init__(self, memory_bank: MemoryBankPort) -> None:
        self._memory_bank = memory_bank

    def recall(self, *, exact_scope: MemoryScope) -> tuple[MemoryHint, ...]:
        try:
            return self._memory_bank.retrieve_exact(exact_scope=exact_scope)
        except MemoryBankUnavailable:
            return ()
