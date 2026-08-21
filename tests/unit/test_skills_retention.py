from datetime import UTC, datetime, timedelta

import pytest

from solvan.application.skills_retention import (
    ObjectDeleter,
    RetentionCandidate,
    RetentionRecord,
    deletion_decision,
    execute_due_deletions,
)
from solvan.domain import Scope

SCOPE = Scope(
    "org_01J4QZK8Q4J8Q6B95KQY4M9R2S",
    "prj_01J4QZK8Q4J8Q6B95KQY4M9R2S",
    "env_01J4QZK8Q4J8Q6B95KQY4M9R2S",
)


def record(**updates: object) -> RetentionRecord:
    value: dict[str, object] = {
        "object_kind": "SOURCE_PACKAGE",
        "object_id": "obj_1",
        "storage_region": "europe-west1",
        "retention_until": datetime.now(UTC) - timedelta(seconds=1),
        "legal_hold_ref": None,
    }
    value.update(updates)
    return RetentionRecord(**value)


def candidate(**updates: object) -> RetentionCandidate:
    value: dict[str, object] = {
        "record": record(),
        "object_uri": "gs://bucket/source.bin",
        "object_generation": "42",
        "deletion_job_ref": "srd_1",
    }
    value.update(updates)
    return RetentionCandidate(**value)


def test_expired_same_region_is_deletion_eligible() -> None:
    assert deletion_decision(record(), requested_region="europe-west1") == "DELETE_ELIGIBLE"


@pytest.mark.parametrize(
    ("updates", "code"),
    [
        ({"storage_region": "us-central1"}, "REGION_DENIED"),
        ({"legal_hold_ref": "hold_1"}, "LEGAL_HOLD_ACTIVE"),
        ({"retention_until": datetime.now(UTC) + timedelta(days=1)}, "RETENTION_NOT_EXPIRED"),
    ],
)
def test_deletion_refuses_unsafe_state(updates: dict[str, object], code: str) -> None:
    with pytest.raises(ValueError, match=code):
        deletion_decision(record(**updates), requested_region="europe-west1")


class Repository:
    def __init__(self, candidate: RetentionCandidate, outcome: str = "DELETED") -> None:
        self.candidate = candidate
        self.outcome = outcome
        self.settled: list[str] = []

    def claim_due(self, **_kwargs: object) -> tuple[RetentionCandidate, ...]:
        return (self.candidate,)

    def settle(
        self,
        *,
        scope: Scope,
        candidate: RetentionCandidate,
        deleter: ObjectDeleter,
        requested_region: str,
        now: datetime,
    ) -> str:
        del scope, requested_region, now
        if self.outcome == "DELETED":
            deleter.delete(
                uri=candidate.object_uri,
                expected_generation=candidate.object_generation,
            )
        self.settled.append(self.outcome)
        return self.outcome


class Deleter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    def delete(self, *, uri: str, expected_generation: str | None = None) -> str:
        self.calls.append((uri, expected_generation))
        return "provider:deleted:1"


def test_execute_due_deletions_settles_inside_the_repository_boundary() -> None:
    repository = Repository(candidate())
    deleter = Deleter()
    count = execute_due_deletions(
        repository=repository,
        deleter=deleter,
        scope=SCOPE,
        region="europe-west1",
    )
    assert count == 1
    assert repository.settled == ["DELETED"]
    assert deleter.calls == [("gs://bucket/source.bin", "42")]


def test_execute_due_deletions_does_not_count_a_refused_candidate() -> None:
    repository = Repository(candidate(), outcome="LEGAL_HOLD_ACTIVE")
    deleter = Deleter()
    count = execute_due_deletions(
        repository=repository,
        deleter=deleter,
        scope=SCOPE,
        region="europe-west1",
    )
    assert count == 0
    assert repository.settled == ["LEGAL_HOLD_ACTIVE"]
    assert deleter.calls == []


def test_execute_due_deletions_refuses_an_unknown_settlement_outcome() -> None:
    repository = Repository(candidate(), outcome="SOFT_DELETED")
    with pytest.raises(ValueError, match="DELETION_OUTCOME_UNKNOWN"):
        execute_due_deletions(
            repository=repository,
            deleter=Deleter(),
            scope=SCOPE,
            region="europe-west1",
        )


def test_execute_due_deletions_rejects_invalid_batch_limit() -> None:
    with pytest.raises(ValueError, match="batch limit"):
        execute_due_deletions(
            repository=Repository(candidate(object_generation=None)),
            deleter=Deleter(),
            scope=SCOPE,
            region="europe-west1",
            limit=0,
        )
