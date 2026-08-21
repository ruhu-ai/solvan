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


def registered_endpoints() -> dict[str, str]:
    keys = {
        "evidence",
        "actuator",
        "verifier",
        "aiplatform",
        "aiplatform_mtls",
        "aiplatform_rep",
        "aiplatform_eu_rep",
        "resource_manager",
        "resource_manager_mtls",
        "logging",
        "telemetry",
        "telemetry_mtls",
    }
    return {
        key: "projects/123/locations/europe-west1/endpoints/"
        f"agentregistry-00000000-0000-0000-{index:012d}"
        for index, key in enumerate(sorted(keys), start=1)
    }


def test_iap_plan_grants_only_read_agents_to_evidence_endpoint() -> None:
    endpoints = registered_endpoints()
    policies = build_policies(receipt(), registered_endpoints=endpoints)
    by_endpoint = {policy.endpoint_key: policy.members for policy in policies}

    assert by_endpoint["evidence"] == tuple(
        sorted((principal("evidence-agent"), principal("infrastructure-agent")))
    )
    assert principal("incident-supervisor") not in by_endpoint["evidence"]
    assert policies[0].value()["policy"]["bindings"][0]["role"] == "roles/iap.egressor"
    assert policies[0].endpoint_id == endpoints["evidence"].rsplit("/", 1)[-1]


def test_iap_plan_fails_without_complete_runtime_fleet() -> None:
    value = receipt()
    value["resources"] = value["resources"][:-1]  # type: ignore[index]
    with pytest.raises(ValueError, match="missing Runtime agents"):
        build_policies(value, registered_endpoints=registered_endpoints())


def test_iap_plan_separates_execution_and_verification_endpoints() -> None:
    policies = build_policies(receipt(), registered_endpoints=registered_endpoints())
    by_endpoint = {policy.endpoint_key: policy.members for policy in policies}
    assert by_endpoint["actuator"] == (principal("execution-agent"),)
    assert by_endpoint["verifier"] == (principal("verification-agent"),)


def test_iap_plan_allows_fleet_startup_and_telemetry_dependencies() -> None:
    policies = build_policies(receipt(), registered_endpoints=registered_endpoints())
    by_endpoint = {policy.endpoint_key: policy.members for policy in policies}
    all_members = tuple(sorted(principal(agent) for agent in AGENTS))
    assert by_endpoint["aiplatform"] == all_members
    assert by_endpoint["aiplatform_mtls"] == all_members
    assert by_endpoint["aiplatform_rep"] == all_members
    assert by_endpoint["aiplatform_eu_rep"] == all_members
    assert by_endpoint["resource_manager"] == all_members
    assert by_endpoint["resource_manager_mtls"] == all_members
    assert by_endpoint["logging"] == all_members
    assert by_endpoint["telemetry"] == all_members
    assert by_endpoint["telemetry_mtls"] == all_members
    assert set(by_endpoint) == {
        "actuator",
        "aiplatform",
        "aiplatform_mtls",
        "aiplatform_rep",
        "aiplatform_eu_rep",
        "evidence",
        "logging",
        "resource_manager",
        "resource_manager_mtls",
        "telemetry",
        "telemetry_mtls",
        "verifier",
    }


def test_iap_plan_refuses_a_missing_or_malformed_terraform_endpoint() -> None:
    endpoints = registered_endpoints()
    del endpoints["aiplatform_eu_rep"]
    with pytest.raises(ValueError, match="missing registered endpoint: aiplatform_eu_rep"):
        build_policies(receipt(), registered_endpoints=endpoints)

    endpoints = registered_endpoints()
    endpoints["actuator"] = "solvan-staging-actuator"
    with pytest.raises(ValueError, match="malformed registered endpoint: actuator"):
        build_policies(receipt(), registered_endpoints=endpoints)


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
        (
            EndpointPolicy(
                "actuator",
                "agentregistry-00000000-0000-0000-ff51-d949fc4c0f25",
                (principal("execution-agent"),),
            ),
        ),
        project="solvan-demo",
        region="europe-west1",
        session=session,  # type: ignore[arg-type]
    )
    assert (
        "/iap_web/agentRegistry/endpoints/agentregistry-00000000-0000-0000-ff51-d949fc4c0f25:setIamPolicy"
        in (session.posts[0][0])
    )
    assert results[0]["endpoint_key"] == "actuator"
    assert results[0]["status"] == "APPLIED_UNVERIFIED"
