from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from tools.deploy_agent_platform import build_plan, deploy


class FakeAgentEngineClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def create(self, *, agent: Any, config: dict[str, Any]) -> Any:
        self.calls.append({"agent": agent, "config": config})
        agent_key = str(config["labels"]["agent"])
        engine_id = agent_key.replace("-", "_")
        gateway_config = config["agent_gateway_config"]
        return SimpleNamespace(
            api_resource=SimpleNamespace(
                name=(f"projects/solvan-demo/locations/europe-west1/reasoningEngines/{engine_id}"),
                display_name=config["display_name"],
                create_time=datetime(2026, 8, 8, tzinfo=UTC),
                spec=SimpleNamespace(
                    effective_identity=(
                        "agents.global.project-123456789.system.id.goog/resources/"
                        "aiplatform/projects/123456789/locations/europe-west1/"
                        f"reasoningEngines/{engine_id}"
                    ),
                    identity_type=SimpleNamespace(value="AGENT_IDENTITY"),
                    deployment_spec=SimpleNamespace(
                        agent_gateway_config=SimpleNamespace(
                            agent_to_anywhere_config=SimpleNamespace(
                                agent_gateway=gateway_config["agent_to_anywhere_config"][
                                    "agent_gateway"
                                ]
                            ),
                            client_to_agent_config=SimpleNamespace(
                                agent_gateway=gateway_config["client_to_agent_config"][
                                    "agent_gateway"
                                ]
                            ),
                        )
                    ),
                ),
            )
        )


def test_plan_is_read_only_and_selects_only_implemented_agents() -> None:
    plan = build_plan(
        project_id="solvan-demo",
        staging_bucket="gs://solvan-runtime",
        release_version="0.1.0",
        egress_agent_gateway=(
            "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-egress"
        ),
        ingress_agent_gateway=(
            "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-ingress"
        ),
        selected_agents=None,
        apply=False,
    )

    assert plan.mutation_mode == "PLAN_ONLY"
    assert [target.agent_key for target in plan.targets] == [
        "evidence-agent",
        "execution-agent",
        "incident-supervisor",
        "infrastructure-agent",
        "verification-agent",
        "workspace-agent",
    ]
    assert plan.identity_type == "AGENT_IDENTITY"
    assert plan.location == "europe-west1"
    assert plan.model_location == "eu"
    assert plan.model_endpoint == "https://aiplatform.eu.rep.googleapis.com"


def test_plan_rejects_unknown_agent() -> None:
    with pytest.raises(ValueError, match="not implemented"):
        build_plan(
            project_id="solvan-demo",
            staging_bucket="gs://solvan-runtime",
            release_version="0.1.0",
            egress_agent_gateway=(
                "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-egress"
            ),
            ingress_agent_gateway=(
                "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-ingress"
            ),
            selected_agents={"unknown-agent"},
            apply=False,
        )


def test_deploy_wraps_adk_agent_and_requires_attested_identity() -> None:
    plan = build_plan(
        project_id="solvan-demo",
        staging_bucket="gs://solvan-runtime",
        release_version="0.1.0",
        egress_agent_gateway=(
            "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-egress"
        ),
        ingress_agent_gateway=(
            "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-ingress"
        ),
        selected_agents={"incident-supervisor"},
        apply=True,
    )
    client = FakeAgentEngineClient()

    results = deploy(
        plan,
        client=client,
        evidence_broker_url=None,
        actuator_url=None,
        verifier_url=None,
    )

    assert results[0]["status"] == "DEPLOYED_UNVERIFIED"
    assert results[0]["iam_principal"].startswith("principal://agents.global.project-")
    assert client.calls[0]["config"]["identity_type"].value == "AGENT_IDENTITY"
    assert client.calls[0]["config"]["min_instances"] == 0
    assert "agent_gateway_config" in client.calls[0]["config"]


def test_read_agent_requires_https_evidence_broker() -> None:
    plan = build_plan(
        project_id="solvan-demo",
        staging_bucket="gs://solvan-runtime",
        release_version="0.1.0",
        egress_agent_gateway=(
            "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-egress"
        ),
        ingress_agent_gateway=(
            "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-ingress"
        ),
        selected_agents={"evidence-agent"},
        apply=True,
    )

    with pytest.raises(ValueError, match="HTTPS evidence broker"):
        deploy(
            plan,
            client=FakeAgentEngineClient(),
            evidence_broker_url=None,
            actuator_url=None,
            verifier_url=None,
        )


def test_read_agent_receives_fixed_identity_and_broker_configuration() -> None:
    plan = build_plan(
        project_id="solvan-demo",
        staging_bucket="gs://solvan-runtime",
        release_version="0.1.0",
        egress_agent_gateway=(
            "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-egress"
        ),
        ingress_agent_gateway=(
            "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-ingress"
        ),
        selected_agents={"infrastructure-agent"},
        apply=True,
    )
    client = FakeAgentEngineClient()

    deploy(
        plan,
        client=client,
        evidence_broker_url="https://evidence.example",
        actuator_url=None,
        verifier_url=None,
    )

    assert client.calls[0]["config"]["env_vars"] == {
        "SOLVAN_ENVIRONMENT": "staging",
        "GOOGLE_GENAI_USE_VERTEXAI": "true",
        "GOOGLE_CLOUD_PROJECT": "solvan-demo",
        "GOOGLE_CLOUD_LOCATION": "eu",
        "SOLVAN_MODEL_ENDPOINT": "https://aiplatform.eu.rep.googleapis.com",
        "GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY": "true",
        "OTEL_SEMCONV_STABILITY_OPT_IN": "gen_ai_latest_experimental",
        "ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS": "false",
        "SOLVAN_EVIDENCE_BROKER_URL": "https://evidence.example",
        "SOLVAN_EVIDENCE_AUDIENCE": "https://evidence.example",
        "SOLVAN_AGENT_KEY": "infrastructure-agent",
    }


def test_execution_agent_receives_only_the_actuator_endpoint() -> None:
    plan = build_plan(
        project_id="solvan-demo",
        staging_bucket="gs://solvan-runtime",
        release_version="0.1.0",
        egress_agent_gateway=(
            "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-egress"
        ),
        ingress_agent_gateway=(
            "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-ingress"
        ),
        selected_agents={"execution-agent"},
        apply=True,
    )
    client = FakeAgentEngineClient()

    deploy(
        plan,
        client=client,
        evidence_broker_url=None,
        actuator_url="https://actuator.example",
        verifier_url=None,
    )

    env = client.calls[0]["config"]["env_vars"]
    assert env["SOLVAN_ACTUATOR_URL"] == "https://actuator.example"
    assert env["SOLVAN_ACTUATOR_AUDIENCE"] == "https://actuator.example"
    assert env["SOLVAN_AGENT_KEY"] == "execution-agent"
    assert "SOLVAN_EVIDENCE_BROKER_URL" not in env


def test_workspace_agent_requires_and_receives_only_the_tool_broker() -> None:
    plan = build_plan(
        project_id="solvan-demo",
        staging_bucket="gs://solvan-runtime",
        release_version="0.1.0",
        egress_agent_gateway=(
            "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-egress"
        ),
        ingress_agent_gateway=(
            "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-ingress"
        ),
        selected_agents={"workspace-agent"},
        apply=True,
    )
    with pytest.raises(ValueError, match="Workspace Tool broker"):
        deploy(
            plan,
            client=FakeAgentEngineClient(),
            evidence_broker_url=None,
            actuator_url=None,
            verifier_url=None,
        )

    client = FakeAgentEngineClient()
    deploy(
        plan,
        client=client,
        evidence_broker_url=None,
        actuator_url=None,
        verifier_url=None,
        workspace_tool_broker_url="https://coordinator.example",
    )
    env = client.calls[0]["config"]["env_vars"]
    assert env["SOLVAN_WORKSPACE_TOOL_BROKER_URL"] == "https://coordinator.example"
    assert env["SOLVAN_WORKSPACE_TOOL_BROKER_AUDIENCE"] == "https://coordinator.example"
    assert "SOLVAN_ACTUATOR_URL" not in env
    assert "SOLVAN_VERIFIER_URL" not in env
    assert env["SOLVAN_AGENT_KEY"] == "workspace-agent"
    assert "SOLVAN_EVIDENCE_BROKER_URL" not in env


def test_verification_agent_receives_only_the_verifier_endpoint() -> None:
    plan = build_plan(
        project_id="solvan-demo",
        staging_bucket="gs://solvan-runtime",
        release_version="0.1.0",
        egress_agent_gateway=(
            "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-egress"
        ),
        ingress_agent_gateway=(
            "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-ingress"
        ),
        selected_agents={"verification-agent"},
        apply=True,
    )
    client = FakeAgentEngineClient()

    deploy(
        plan,
        client=client,
        evidence_broker_url=None,
        actuator_url=None,
        verifier_url="https://verifier.example",
    )

    env = client.calls[0]["config"]["env_vars"]
    assert env["SOLVAN_VERIFIER_URL"] == "https://verifier.example"
    assert env["SOLVAN_VERIFIER_AUDIENCE"] == "https://verifier.example"
    assert env["SOLVAN_AGENT_KEY"] == "verification-agent"
    assert "SOLVAN_ACTUATOR_URL" not in env
