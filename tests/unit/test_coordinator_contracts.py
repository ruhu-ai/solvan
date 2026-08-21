"""Closed configuration contracts at the coordinator boundary."""

import pytest

from apps.coordinator.contracts import GovernedAgentBinding

_RESOURCE = "projects/123456789/locations/europe-west1/reasoningEngines/evidence-agent"
_IDENTITY = (
    f"principal://agents.global.project-123456789.system.id.goog/resources/aiplatform/{_RESOURCE}"
)


def _binding(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "profile_ref": "evidence.core@2",
        "identity_ref": _IDENTITY,
        "accepted_tool_ordinals": [1, 3],
        "connection_epochs": {},
        "gateway_destinations": ["compute.internal"],
        "data_classification": "INTERNAL",
    }
    value.update(changes)
    return value


def test_governed_binding_accepts_an_explicit_ordered_subset() -> None:
    binding = GovernedAgentBinding.from_json(
        "evidence-agent", _binding(), expected_agent_resource=_RESOURCE
    )

    assert binding.accepted_tool_ordinals == (1, 3)


@pytest.mark.parametrize(
    "accepted",
    ([1, 1], [3, 1], [0, 1], [1, True], "1,3", None),
)
def test_governed_binding_refuses_ambiguous_or_malformed_subsets(accepted: object) -> None:
    with pytest.raises(ValueError, match="invalid accepted Tool ordinals"):
        GovernedAgentBinding.from_json("evidence-agent", _binding(accepted_tool_ordinals=accepted))


@pytest.mark.parametrize(
    ("identity_ref", "expected_resource", "message"),
    [
        ("UNCONFIGURED", _RESOURCE, "attested Agent Identity"),
        (
            _IDENTITY,
            "projects/123456789/locations/europe-west1/reasoningEngines/other",
            "Runtime resource",
        ),
    ],
)
def test_governed_binding_refuses_unattested_or_mismatched_identity(
    identity_ref: str, expected_resource: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        GovernedAgentBinding.from_json(
            "evidence-agent",
            _binding(identity_ref=identity_ref),
            expected_agent_resource=expected_resource,
        )
