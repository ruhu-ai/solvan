from __future__ import annotations

import pytest

from apps.verifier.main import _guardrail, _requirements
from solvan.domain import VerificationError


def test_verifier_accepts_only_typed_policy_owned_profile_fields() -> None:
    requirements = _requirements(
        [
            {
                "signal_key": "http_5xx_ratio",
                "provider_signal_kind": "HTTP_5XX_RATIO",
                "comparator": "LTE",
                "threshold": 0.01,
                "sustained_samples": 2,
            }
        ]
    )
    amount, required = _guardrail({"synthetic_payment": {"amount_minor": 100, "required": True}})

    assert requirements[0][0].signal_key == "http_5xx_ratio"
    assert requirements[0][1] == "HTTP_5XX_RATIO"
    assert (amount, required) == (100, True)


@pytest.mark.parametrize(
    "profile",
    [
        [],
        [
            {
                "signal_key": "http_5xx_ratio",
                "provider_signal_kind": "ARBITRARY_QUERY",
                "comparator": "LTE",
                "threshold": 0.01,
                "sustained_samples": 2,
            }
        ],
        [
            {
                "signal_key": "http_5xx_ratio",
                "provider_signal_kind": "HTTP_5XX_RATIO",
                "comparator": "LTE",
                "threshold": float("nan"),
                "sustained_samples": 2,
            }
        ],
    ],
)
def test_verifier_rejects_empty_arbitrary_or_nonfinite_profile(profile: object) -> None:
    with pytest.raises(VerificationError):
        _requirements(profile)


def test_synthetic_is_mandatory_and_cannot_be_disabled_by_profile() -> None:
    with pytest.raises(VerificationError, match="fields"):
        _guardrail({"synthetic_payment": {"amount_minor": 100, "required": False}})
