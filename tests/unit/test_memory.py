from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime, timedelta

import pytest

from solvan.application import (
    GovernedMemorySearchService,
    MemoryBankReceipt,
    MemoryBankUnavailable,
    MemoryCandidateService,
    MemoryConflict,
    MemoryHint,
    MemoryPromotionRecord,
    MemoryPromotionService,
    MemoryReadGrant,
    MemoryRecallService,
    MemorySearchCandidate,
    MemorySearchQuery,
    PromotionCandidate,
    PromotionPreparation,
    StoredMemoryCandidate,
)
from solvan.domain import (
    MemoryCandidateProposal,
    MemoryCandidateStatus,
    MemoryCandidateType,
    MemoryConfirmation,
    MemoryGateError,
    MemoryGatePolicy,
    MemoryReviewRequirement,
    MemoryScope,
    Scope,
    evaluate_memory_candidate,
)

NOW = datetime(2026, 8, 8, 12, tzinfo=UTC)
SCOPE = Scope(
    "org_00000000000000000000000000",
    "prj_00000000000000000000000000",
    "env_00000000000000000000000000",
)
EXACT_SCOPE = MemoryScope(SCOPE, "incident-investigation", "INTERNAL", "europe-west1")
POLICY = MemoryGatePolicy("memory-v1", frozenset({"INTERNAL"}), frozenset({"europe-west1"}))


def proposal(**changes: object) -> MemoryCandidateProposal:
    values: dict[str, object] = {
        "candidate_type": MemoryCandidateType.ROOT_CAUSE,
        "exact_scope": EXACT_SCOPE,
        "fact_text": "Connection pool exhaustion caused the payment errors.",
        "source_refs": ("hyp_00000000000000000000000000",),
        "source_hashes": ("a" * 64,),
        "confirmation": MemoryConfirmation.CONFIRMED,
        "verification_ref": None,
        "classification": "INTERNAL",
        "residency": "europe-west1",
        "redaction_manifest_ref": "redaction:manifest-1",
        "armor_verdict_ref": "armor:allow:verdict-1",
        "provenance": (("confirmation_rule", "root-cause-v1"),),
        "policy_version": "memory-v1",
        "created_by_principal": "supervisor@solvan.example",
        "expires_at": NOW + timedelta(days=30),
    }
    values.update(changes)
    return MemoryCandidateProposal(**values)


@pytest.mark.parametrize(
    ("candidate_type", "confirmation", "source", "verification", "review"),
    [
        (
            MemoryCandidateType.ROOT_CAUSE,
            MemoryConfirmation.CONFIRMED,
            "hyp_00000000000000000000000000",
            None,
            MemoryReviewRequirement.AUTOMATIC,
        ),
        (
            MemoryCandidateType.MITIGATION_OUTCOME,
            MemoryConfirmation.VERIFIED,
            "ver_00000000000000000000000000",
            "ver_00000000000000000000000000",
            MemoryReviewRequirement.AUTOMATIC,
        ),
        (
            MemoryCandidateType.TEAM_PREFERENCE,
            MemoryConfirmation.HUMAN_APPROVED,
            "aud_00000000000000000000000000",
            None,
            MemoryReviewRequirement.HUMAN,
        ),
        (
            MemoryCandidateType.RUNBOOK_FACT,
            MemoryConfirmation.OWNER_APPROVED,
            "pgs_00000000000000000000000000",
            None,
            MemoryReviewRequirement.HUMAN,
        ),
        (
            MemoryCandidateType.PATTERN,
            MemoryConfirmation.SAMPLE_CONFIRMED,
            "hyp_00000000000000000000000000",
            None,
            MemoryReviewRequirement.AUTOMATIC,
        ),
    ],
)
def test_only_type_specific_confirmations_pass(
    candidate_type: MemoryCandidateType,
    confirmation: MemoryConfirmation,
    source: str,
    verification: str | None,
    review: MemoryReviewRequirement,
) -> None:
    decision = evaluate_memory_candidate(
        proposal(
            candidate_type=candidate_type,
            confirmation=confirmation,
            source_refs=(source,),
            verification_ref=verification,
        ),
        policy=POLICY,
        now=NOW,
    )
    assert decision.status is MemoryCandidateStatus.APPROVED
    assert decision.review_requirement is review
    assert len(decision.content_hash) == 64


def test_unconfirmed_or_poisoned_candidate_is_quarantined() -> None:
    unconfirmed = evaluate_memory_candidate(
        proposal(confirmation=MemoryConfirmation.UNCONFIRMED), policy=POLICY, now=NOW
    )
    poisoned = evaluate_memory_candidate(
        proposal(armor_verdict_ref="armor:block:prompt-injection"),
        policy=POLICY,
        now=NOW,
    )
    outside_region = evaluate_memory_candidate(
        proposal(
            exact_scope=MemoryScope(SCOPE, "incident-investigation", "INTERNAL", "us-east4"),
            residency="us-east4",
        ),
        policy=POLICY,
        now=NOW,
    )
    assert unconfirmed.status is MemoryCandidateStatus.QUARANTINED
    assert poisoned.rationale_codes == ("MODEL_ARMOR_NOT_ALLOWED",)
    assert outside_region.rationale_codes == ("RESIDENCY_NOT_ALLOWED",)


def test_wrong_source_type_and_missing_verification_fail_closed() -> None:
    with pytest.raises(MemoryGateError, match="cannot cite"):
        evaluate_memory_candidate(
            proposal(source_refs=("ver_00000000000000000000000000",)),
            policy=POLICY,
            now=NOW,
        )
    with pytest.raises(MemoryGateError, match="verification"):
        evaluate_memory_candidate(
            proposal(
                candidate_type=MemoryCandidateType.MITIGATION_OUTCOME,
                confirmation=MemoryConfirmation.VERIFIED,
                source_refs=("ver_00000000000000000000000000",),
            ),
            policy=POLICY,
            now=NOW,
        )


class InMemoryRepository:
    def __init__(self) -> None:
        self.saved: StoredMemoryCandidate | None = None
        self.preparation: PromotionPreparation | None = None
        self.completed = 0

    def transaction(self) -> nullcontext[None]:
        return nullcontext()

    def save_candidate(self, candidate: StoredMemoryCandidate) -> None:
        self.saved = candidate

    def begin_promotion(
        self, *, candidate_id: str, promoter_identity: str, now: datetime
    ) -> PromotionPreparation:
        del candidate_id, promoter_identity, now
        if self.preparation is None:
            raise MemoryConflict("fixture has no candidate")
        return self.preparation

    def complete_promotion(
        self,
        *,
        candidate: PromotionCandidate,
        receipt: MemoryBankReceipt,
        promoter_identity: str,
        now: datetime,
    ) -> MemoryPromotionRecord:
        del promoter_identity, now
        self.completed += 1
        return MemoryPromotionRecord(
            "memp_00000000000000000000000000",
            candidate.candidate_id,
            receipt.memory_resource,
            receipt.memory_revision,
            candidate.exact_scope,
            candidate.content_hash,
            candidate.expires_at,
        )


class UnavailableBank:
    def upsert_exact(self, *, exact_scope: MemoryScope, fact_text: str) -> MemoryBankReceipt:
        del exact_scope, fact_text
        raise MemoryBankUnavailable("fixture outage")

    def retrieve_exact(self, *, exact_scope: MemoryScope) -> tuple[()]:
        del exact_scope
        raise MemoryBankUnavailable("fixture outage")


def test_candidate_is_stored_and_platform_failure_does_not_fake_completion() -> None:
    repository = InMemoryRepository()
    stored = MemoryCandidateService(repository).evaluate_and_store(
        proposal=proposal(), policy=POLICY, now=NOW
    )
    assert repository.saved == stored
    repository.preparation = PromotionPreparation(
        PromotionCandidate(
            stored.candidate_id,
            stored.proposal.exact_scope,
            stored.proposal.fact_text,
            stored.decision.content_hash,
            stored.proposal.expires_at,
        ),
        None,
    )
    with pytest.raises(MemoryBankUnavailable):
        MemoryPromotionService(repository, UnavailableBank()).promote(
            candidate_id=stored.candidate_id,
            promoter_identity="promotion-service@solvan.example",
            now=NOW,
        )
    assert repository.completed == 0
    assert MemoryRecallService(UnavailableBank()).recall(exact_scope=EXACT_SCOPE) == ()


def test_memory_scope_is_exact_and_immutable() -> None:
    assert EXACT_SCOPE.canonical_dict() == {
        "organization_id": SCOPE.organization_id,
        "project_id": SCOPE.project_id,
        "environment_id": SCOPE.environment_id,
        "purpose": "incident-investigation",
        "classification": "INTERNAL",
        "region": "europe-west1",
    }
    with pytest.raises(MemoryGateError, match="purpose"):
        MemoryScope(SCOPE, " ", "INTERNAL", "europe-west1")


class SearchPort:
    def __init__(
        self, candidates: tuple[MemorySearchCandidate, ...] = (), *, unavailable: bool = False
    ) -> None:
        self.candidates = candidates
        self.unavailable = unavailable

    def search(self, *, query: MemorySearchQuery) -> tuple[MemorySearchCandidate, ...]:
        del query
        if self.unavailable:
            raise MemoryBankUnavailable("fixture outage")
        return self.candidates


class SearchRepository:
    def revalidate_search_hits(
        self,
        *,
        exact_scope: MemoryScope,
        candidates: tuple[MemorySearchCandidate, ...],
        now: datetime,
    ) -> tuple[MemoryHint, ...]:
        del now
        return tuple(
            MemoryHint(
                item.memory_resource,
                item.fact_text,
                exact_scope,
                item.memory_revision,
                item.distance,
                ("hyp_00000000000000000000000000",),
            )
            for item in candidates
        )


def search_query(*, audience: str = "evidence-agent") -> MemorySearchQuery:
    return MemorySearchQuery(
        exact_scope=EXACT_SCOPE,
        read_grant=MemoryReadGrant("grant:test", audience, EXACT_SCOPE, NOW + timedelta(minutes=1)),
        objective="connection exhaustion",
        maximum_results=5,
        token_budget=64,
        current_time_cutoff=NOW,
    )


def test_governed_search_requires_audience_grant_and_degrades_outage() -> None:
    service = GovernedMemorySearchService(
        search_port=SearchPort(unavailable=True), repository=SearchRepository()
    )
    assert service.search(query=search_query()) == ()
    with pytest.raises(MemoryConflict, match="audience"):
        service.search(query=search_query(audience="supervisor"))


def test_governed_search_applies_token_budget_after_sql_revalidation() -> None:
    candidates = tuple(
        MemorySearchCandidate(
            f"projects/p/locations/europe-west1/reasoningEngines/e/memories/{index}",
            "x" * 160,
            EXACT_SCOPE,
            str(index),
            float(index),
        )
        for index in range(2)
    )
    hints = GovernedMemorySearchService(
        search_port=SearchPort(candidates), repository=SearchRepository()
    ).search(query=search_query())
    assert len(hints) == 1


def test_resolve_engine_id_accepts_both_project_spellings_and_nothing_else() -> None:
    """Vertex returns resource names with the project number while local
    canonical forms use the project ID. Both name the same boundary; a third
    project, another region, or a malformed tail still refuses.
    staging-20260823-04: the ID-only comparison refused the deployed value in
    the coordinator, the promoter, and the release probe at once."""

    from solvan.platform.memory_bank import resolve_engine_id

    kwargs = {
        "project_id": "solvan-staging",
        "project_number": "599862894051",
        "location": "europe-west1",
    }
    for spelling in ("solvan-staging", "599862894051"):
        assert (
            resolve_engine_id(
                f"projects/{spelling}/locations/europe-west1/reasoningEngines/re-1", **kwargs
            )
            == "re-1"
        )
    import pytest

    with pytest.raises(ValueError, match="outside the exact deployment scope"):
        resolve_engine_id(
            "projects/other-project/locations/europe-west1/reasoningEngines/re-1", **kwargs
        )
    with pytest.raises(ValueError, match="outside the exact deployment scope"):
        resolve_engine_id(
            "projects/solvan-staging/locations/us-central1/reasoningEngines/re-1", **kwargs
        )
    with pytest.raises(ValueError, match="malformed"):
        resolve_engine_id(
            "projects/solvan-staging/locations/europe-west1/reasoningEngines/re-1/extra", **kwargs
        )


def test_memory_validation_accepts_the_number_spelling_vertex_returns() -> None:
    """Creation succeeded and validation refused the created resource: the API
    names memories with the project number while the config's canonical
    resource uses the ID (staging-20260824-02). Both spellings must pass; a
    third project must not."""

    from solvan.platform.memory_bank import MemoryBankConfiguration

    config = MemoryBankConfiguration(
        "solvan-staging", "europe-west1", "re-1", project_number="599862894051"
    )
    prefixes = config.memory_prefixes()
    assert any(p.startswith("projects/solvan-staging/") for p in prefixes)
    assert any(p.startswith("projects/599862894051/") for p in prefixes)
    assert not any("projects/other" in p for p in prefixes)
    # Without a number, only the ID form is acceptable.
    bare = MemoryBankConfiguration("solvan-staging", "europe-west1", "re-1")
    assert len(bare.memory_prefixes()) == 1
