from __future__ import annotations

import pytest

from tools.configure_agent_iap import EndpointPolicy, apply_policies, build_policies

AGENTS = (
    "workspace-agent",
    "evidence-agent",
    "execution-agent",
    "incident-supervisor",
    "infrastructure-agent",
    "verification-agent",
)


def principal(agent: str) -> str:
    return (
        "principal://agents.global.project-123.system.id.goog/resources/"
        f"aiplatform/projects/123/locations/europe-west1/reasoningEngines/{agent}"
    )


def receipt() -> dict[str, object]:
    return {
        "status": "DEPLOYED_UNVERIFIED",
        "resources": [{"agent_key": agent, "iam_principal": principal(agent)} for agent in AGENTS],
    }


def test_iap_plan_grants_only_read_agents_to_evidence_endpoint() -> None:
    policies = build_policies(receipt(), environment="staging")
    by_endpoint = {policy.endpoint_id: policy.members for policy in policies}

    assert by_endpoint["solvan-staging-evidence-broker"] == tuple(
        sorted((principal("evidence-agent"), principal("infrastructure-agent")))
    )
    assert principal("incident-supervisor") not in by_endpoint["solvan-staging-evidence-broker"]
    assert policies[0].value()["policy"]["bindings"][0]["role"] == "roles/iap.egressor"


def test_iap_plan_fails_without_complete_runtime_fleet() -> None:
    value = receipt()
    value["resources"] = value["resources"][:-1]  # type: ignore[index]
    with pytest.raises(ValueError, match="missing Runtime agents"):
        build_policies(value, environment="staging")


def test_iap_plan_separates_execution_and_verification_endpoints() -> None:
    policies = build_policies(receipt(), environment="staging")
    by_endpoint = {policy.endpoint_id: policy.members for policy in policies}
    assert by_endpoint["solvan-staging-actuator"] == (principal("execution-agent"),)
    assert by_endpoint["solvan-staging-verifier"] == (principal("verification-agent"),)


def test_iap_plan_allows_fleet_startup_and_telemetry_dependencies() -> None:
    policies = build_policies(receipt(), environment="staging")
    by_endpoint = {policy.endpoint_id: policy.members for policy in policies}
    all_members = tuple(sorted(principal(agent) for agent in AGENTS))
    assert by_endpoint["solvan-staging-aiplatform"] == all_members
    assert by_endpoint["solvan-staging-aiplatform-mtls"] == all_members
    assert by_endpoint["solvan-staging-aiplatform-rep"] == all_members
    assert by_endpoint["solvan-staging-resource-manager"] == all_members
    assert by_endpoint["solvan-staging-resource-manager-mtls"] == all_members
    assert by_endpoint["solvan-staging-logging"] == all_members
    assert by_endpoint["solvan-staging-telemetry"] == all_members
    assert by_endpoint["solvan-staging-telemetry-mtls"] == all_members
    assert set(by_endpoint) == {
        "solvan-staging-actuator",
        "solvan-staging-aiplatform",
        "solvan-staging-aiplatform-mtls",
        "solvan-staging-aiplatform-rep",
        "solvan-staging-evidence-broker",
        "solvan-staging-logging",
        "solvan-staging-resource-manager",
        "solvan-staging-resource-manager-mtls",
        "solvan-staging-telemetry",
        "solvan-staging-telemetry-mtls",
        "solvan-staging-verifier",
    }


def test_iap_apply_uses_versioned_agent_registry_rest_resource() -> None:
    class Response:
        def __init__(self, value):
            self.value = value

        def raise_for_status(self) -> None:
            return None

        def json(self):
            return self.value

    class Session:
        def __init__(self) -> None:
            self.posts = []

        def get(self, url, **kwargs):
            return Response({"name": "projects/123"})

        def post(self, url, **kwargs):
            self.posts.append((url, kwargs))
            return Response(kwargs["json"]["policy"])

    session = Session()
    results = apply_policies(
        (EndpointPolicy("solvan-staging-actuator", (principal("execution-agent"),)),),
        project="solvan-demo",
        region="europe-west1",
        session=session,  # type: ignore[arg-type]
    )
    assert (
        "/iap_web/agentRegistry/endpoints/solvan-staging-actuator:setIamPolicy"
        in (session.posts[0][0])
    )
    assert results[0]["status"] == "APPLIED_UNVERIFIED"
