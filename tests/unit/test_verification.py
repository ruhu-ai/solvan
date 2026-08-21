from datetime import UTC, datetime, timedelta

import pytest

from solvan.domain import (
    Comparator,
    SignalRequirement,
    SignalSample,
    SyntheticReceipt,
    VerificationBinding,
    VerificationError,
    VerificationVerdict,
    evaluate_verification,
    resolve_verification_binding,
)

START = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)
END = START + timedelta(minutes=5)


def binding(**overrides: object) -> VerificationBinding:
    values: dict[str, object] = {
        "graph_snapshot_id": "graph-v1",
        "service_id": "payments-api",
        "incident_class": "connection_exhaustion",
        "profile_id": "payments-recovery",
        "profile_version": 3,
        "effective_at": START - timedelta(days=1),
        "superseded_at": None,
        "profile_approved": True,
    }
    values.update(overrides)
    return VerificationBinding(**values)  # type: ignore[arg-type]


def test_policy_binding_is_resolved_independently() -> None:
    resolved = resolve_verification_binding(
        bindings=(binding(), binding(service_id="checkout-api")),
        graph_snapshot_id="graph-v1",
        service_id="payments-api",
        incident_class="connection_exhaustion",
        at=START,
        caller_profile=("payments-recovery", 3),
    )
    assert (resolved.profile_id, resolved.profile_version) == ("payments-recovery", 3)


def test_caller_cannot_substitute_verification_profile() -> None:
    with pytest.raises(VerificationError, match="substitution"):
        resolve_verification_binding(
            bindings=(binding(),),
            graph_snapshot_id="graph-v1",
            service_id="payments-api",
            incident_class="connection_exhaustion",
            at=START,
            caller_profile=("weaker-profile", 1),
        )


def requirement() -> SignalRequirement:
    return SignalRequirement("http_5xx_ratio", Comparator.LTE, 0.01, 2)


def sample(offset: int, value: float, key: str = "http_5xx_ratio") -> SignalSample:
    return SignalSample(key, START + timedelta(minutes=offset), value)


def receipt(**overrides: object) -> SyntheticReceipt:
    values: dict[str, object] = {
        "observed_at": END,
        "succeeded": True,
        "isolated_fixture": True,
        "idempotency_key": "synthetic-1",
    }
    values.update(overrides)
    return SyntheticReceipt(**values)  # type: ignore[arg-type]


def test_fresh_sustained_signals_and_probe_verify_recovery() -> None:
    result = evaluate_verification(
        requirements=(requirement(),),
        samples=(sample(3, 0.005), sample(4, 0.004)),
        window_start=START,
        window_end=END,
        synthetic_receipt=receipt(),
    )
    assert result.verdict is VerificationVerdict.VERIFIED


@pytest.mark.parametrize(
    ("samples", "synthetic", "reason"),
    [
        ((), receipt(), "MISSING:http_5xx_ratio"),
        ((sample(-1, 0.0),), receipt(), "STALE:http_5xx_ratio"),
        ((sample(3, 0.0),), receipt(), "INSUFFICIENT:http_5xx_ratio"),
        (
            (sample(3, 0.0), sample(3, 0.5)),
            receipt(),
            "CONTRADICTORY:http_5xx_ratio",
        ),
        ((sample(3, 0.0), sample(4, 0.0)), None, "SYNTHETIC_MISSING"),
        (
            (sample(3, 0.0), sample(4, 0.0)),
            receipt(observed_at=END + timedelta(seconds=1)),
            "SYNTHETIC_STALE",
        ),
        (
            (sample(3, 0.0), sample(4, 0.0)),
            receipt(isolated_fixture=False),
            "SYNTHETIC_INVALID",
        ),
    ],
)
def test_missing_stale_contradictory_or_insufficient_evidence_is_inconclusive(
    samples: tuple[SignalSample, ...], synthetic: SyntheticReceipt | None, reason: str
) -> None:
    result = evaluate_verification(
        requirements=(requirement(),),
        samples=samples,
        window_start=START,
        window_end=END,
        synthetic_receipt=synthetic,
    )
    assert result.verdict is VerificationVerdict.INCONCLUSIVE
    assert reason in result.rationale_codes


def test_connector_success_cannot_override_failed_production_evidence() -> None:
    result = evaluate_verification(
        requirements=(requirement(),),
        samples=(sample(3, 0.2), sample(4, 0.1)),
        window_start=START,
        window_end=END,
        synthetic_receipt=receipt(succeeded=False),
    )
    assert result.verdict is VerificationVerdict.FAILED
    assert result.rationale_codes == (
        "THRESHOLD_FAILED:http_5xx_ratio",
        "SYNTHETIC_FAILED",
    )
