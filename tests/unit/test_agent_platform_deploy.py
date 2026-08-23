from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tools.deploy_agent_platform import ROOT, build_plan, deploy


class FakeAgentEngineClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.resources: list[Any] = []

    def create(self, *, agent: Any, config: dict[str, Any]) -> Any:
        self.calls.append({"agent": agent, "config": config, "cwd": Path.cwd()})
        agent_key = str(config["labels"]["agent"])
        engine_id = agent_key.replace("-", "_")
        gateway_config = config["agent_gateway_config"]
        remote = SimpleNamespace(
            api_resource=SimpleNamespace(
                name=(f"projects/solvan-demo/locations/europe-west1/reasoningEngines/{engine_id}"),
                display_name=config["display_name"],
                create_time=datetime(2026, 8, 8, tzinfo=UTC),
                labels=config["labels"],
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
        self.resources.append(remote)
        return remote

    def get(self, *, name: str) -> Any:
        return next(item for item in self.resources if item.api_resource.name == name)

    def list(self) -> Any:
        return iter(self.resources)


def test_plan_is_read_only_and_selects_only_implemented_agents() -> None:
    plan = build_plan(
        project_id="solvan-demo",
        deployment_id="demo-20260822",
        release_commit="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
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
            deployment_id="demo-20260822",
            release_commit="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
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
        deployment_id="demo-20260822",
        release_commit="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
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
    original_cwd = Path.cwd()

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
    assert client.calls[0]["config"]["extra_packages"] == ["solvan"]
    assert client.calls[0]["cwd"] == ROOT / "src"
    assert Path.cwd() == original_cwd
    assert "agent_gateway_config" in client.calls[0]["config"]
    assert client.calls[0]["agent"]._tmpl_attrs["app"].name == "solvan_incident_supervisor"
    assert client.calls[0]["config"]["labels"]["deployment"] == "demo-20260822"
    assert client.calls[0]["config"]["labels"]["commit"] == "b" * 40


def test_interrupted_agent_deployment_reuses_checkpoint_and_exact_remote() -> None:
    plan = build_plan(
        project_id="solvan-demo",
        deployment_id="demo-20260822",
        release_commit="b" * 40,
        staging_bucket="gs://solvan-runtime",
        release_version="0.1.0",
        egress_agent_gateway=(
            "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-egress"
        ),
        ingress_agent_gateway=(
            "projects/solvan-demo/locations/europe-west1/agentGateways/solvan-staging-ingress"
        ),
        selected_agents={"execution-agent", "incident-supervisor"},
        apply=True,
    )
    client = FakeAgentEngineClient()
    checkpoint: list[dict[str, Any]] = []

    def interrupt_after_first(results: list[dict[str, Any]]) -> None:
        checkpoint[:] = results
        if len(results) == 1:
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        deploy(
            plan,
            client=client,
            evidence_broker_url=None,
            actuator_url="https://actuator.example",
            verifier_url=None,
            on_result=interrupt_after_first,
        )
    assert len(checkpoint) == 1
    assert len(client.calls) == 1

    resumed = deploy(
        plan,
        client=client,
        evidence_broker_url=None,
        actuator_url="https://actuator.example",
        verifier_url=None,
        existing_results=checkpoint,
    )

    assert len(resumed) == 2
    assert len(client.calls) == 2
    assert resumed[0] == checkpoint[0]


def test_resume_hydrates_provider_populated_create_time_without_recreating() -> None:
    plan = build_plan(
        project_id="solvan-demo",
        deployment_id="demo-20260822",
        release_commit="b" * 40,
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
    initial = deploy(
        plan,
        client=client,
        evidence_broker_url=None,
        actuator_url=None,
        verifier_url=None,
    )
    checkpoint = [{**initial[0], "create_time": None}]

    resumed = deploy(
        plan,
        client=client,
        evidence_broker_url=None,
        actuator_url=None,
        verifier_url=None,
        existing_results=checkpoint,
    )

    assert resumed[0]["create_time"] == "2026-08-08T00:00:00+00:00"
    assert len(client.calls) == 1


def test_resume_refuses_changed_provider_create_time() -> None:
    plan = build_plan(
        project_id="solvan-demo",
        deployment_id="demo-20260822",
        release_commit="b" * 40,
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
    initial = deploy(
        plan,
        client=client,
        evidence_broker_url=None,
        actuator_url=None,
        verifier_url=None,
    )
    checkpoint = [{**initial[0], "create_time": "2026-08-09T00:00:00+00:00"}]

    with pytest.raises(RuntimeError, match="differs from provider state"):
        deploy(
            plan,
            client=client,
            evidence_broker_url=None,
            actuator_url=None,
            verifier_url=None,
            existing_results=checkpoint,
        )


def test_deploy_refuses_insufficient_runtime_capacity_before_create() -> None:
    plan = build_plan(
        project_id="solvan-demo",
        deployment_id="demo-20260822",
        release_commit="b" * 40,
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
    client.resources = [
        SimpleNamespace(api_resource=SimpleNamespace(labels={})) for _ in range(100)
    ]

    with pytest.raises(RuntimeError, match="insufficient Agent Runtime resource capacity"):
        deploy(
            plan,
            client=client,
            evidence_broker_url=None,
            actuator_url=None,
            verifier_url=None,
        )

    assert client.calls == []


def test_agent_deployment_refuses_ambiguous_exact_remote_resources() -> None:
    plan = build_plan(
        project_id="solvan-demo",
        deployment_id="demo-20260822",
        release_commit="b" * 40,
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
    first = deploy(
        plan,
        client=client,
        evidence_broker_url=None,
        actuator_url=None,
        verifier_url=None,
    )
    assert len(first) == 1
    client.resources.append(client.resources[0])

    with pytest.raises(RuntimeError, match="multiple exact Runtime resources"):
        deploy(
            plan,
            client=client,
            evidence_broker_url=None,
            actuator_url=None,
            verifier_url=None,
        )


def test_resume_refuses_duplicate_create_while_interrupted_attempt_is_unresolved() -> None:
    plan = build_plan(
        project_id="solvan-demo",
        deployment_id="demo-20260822",
        release_commit="b" * 40,
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

    with pytest.raises(RuntimeError, match="refusing a duplicate create"):
        deploy(
            plan,
            client=client,
            evidence_broker_url=None,
            actuator_url=None,
            verifier_url=None,
            unresolved_agents={"incident-supervisor"},
        )

    assert client.calls == []


def test_read_agent_requires_https_evidence_broker() -> None:
    plan = build_plan(
        project_id="solvan-demo",
        deployment_id="demo-20260822",
        release_commit="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
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
        deployment_id="demo-20260822",
        release_commit="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
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
        "SOLVAN_MODEL_ENDPOINT": "https://aiplatform.eu.rep.googleapis.com",
        "GOOGLE_API_USE_MTLS_ENDPOINT": "never",
        "GOOGLE_VERTEX_BASE_URL": "https://aiplatform.eu.rep.googleapis.com",
        "GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY": "true",
        "OTEL_SEMCONV_STABILITY_OPT_IN": "gen_ai_latest_experimental",
        "ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS": "false",
        "SOLVAN_EVIDENCE_BROKER_URL": "https://evidence.example",
        "SOLVAN_EVIDENCE_AUDIENCE": "https://evidence.example",
        "SOLVAN_AGENT_KEY": "infrastructure-agent",
    }

    env = client.calls[0]["config"]["env_vars"]
    assert "GOOGLE_CLOUD_PROJECT" not in env
    assert "GOOGLE_CLOUD_LOCATION" not in env


def test_execution_agent_receives_only_the_actuator_endpoint() -> None:
    plan = build_plan(
        project_id="solvan-demo",
        deployment_id="demo-20260822",
        release_commit="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
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
        deployment_id="demo-20260822",
        release_commit="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
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
        deployment_id="demo-20260822",
        release_commit="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
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
