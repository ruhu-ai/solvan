"""Plan or deploy immutable Solvan Google ADK agents to Agent Runtime.

The default mode is deliberately read-only: it validates the checked-in catalog
and prints the exact deployment plan. ``--apply`` is the only mode that calls
Google Cloud. Every applied run writes a receipt, including partial failures.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import re
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast

import yaml
from google.adk.apps import App

from solvan.platform.model_routes import validate_fast_fleet_route

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "specs/artifacts/agent-manifests.yaml"
REQUIREMENTS_PATH = ROOT / "apps/agents/runtime-requirements.txt"
PROJECT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
RELEASE_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$")
RESOURCE_PATTERN = re.compile(r"^projects/[^/]+/locations/[^/]+/reasoningEngines/[^/]+$")
GATEWAY_PATTERN = re.compile(r"^projects/[^/]+/locations/[^/]+/agentGateways/[^/]+$")
IDENTITY_PATTERN = re.compile(
    r"^agents\.global\.(?:org-[0-9]+|project-[0-9]+)\.system\.id\.goog/"
    r"resources/aiplatform/projects/[0-9]+/locations/[a-z0-9-]+/reasoningEngines/[^/]+$"
)


@dataclass(frozen=True, slots=True)
class DeploymentTarget:
    agent_key: str
    app_module: str
    display_name: str
    model_resource: str
    permission_ceiling: str


@dataclass(frozen=True, slots=True)
class DeploymentPlan:
    schema_version: int
    project_id: str
    environment: str
    location: str
    model_location: str
    model_endpoint: str
    staging_bucket: str
    egress_agent_gateway: str
    ingress_agent_gateway: str
    release_version: str
    manifest_version: str
    manifest_sha256: str
    requirements_sha256: str
    identity_type: str
    mutation_mode: str
    targets: tuple[DeploymentTarget, ...]


class RemoteAgentResource(Protocol):
    api_resource: Any


class AgentEngineClient(Protocol):
    def create(self, *, agent: Any, config: dict[str, Any]) -> RemoteAgentResource: ...


def _load_manifest() -> dict[str, Any]:
    value = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("agent manifest must be a mapping")
    return cast(dict[str, Any], value)


def build_plan(
    *,
    project_id: str,
    staging_bucket: str,
    release_version: str,
    egress_agent_gateway: str,
    ingress_agent_gateway: str,
    selected_agents: set[str] | None,
    apply: bool,
    environment: str = "staging",
) -> DeploymentPlan:
    if PROJECT_PATTERN.fullmatch(project_id) is None:
        raise ValueError("project ID is not canonical")
    if environment not in {"dev", "staging"}:
        raise ValueError("environment must be dev or staging")
    if not staging_bucket.startswith("gs://") or "/" in staging_bucket.removeprefix("gs://"):
        raise ValueError("staging bucket must be a bucket-level gs:// URI")
    if RELEASE_PATTERN.fullmatch(release_version) is None:
        raise ValueError("release version must be semver")
    manifest = _load_manifest()
    platform = manifest.get("platform")
    agents = manifest.get("agents")
    if not isinstance(platform, dict) or not isinstance(agents, list):
        raise ValueError("agent manifest platform or agents is malformed")
    implemented = {
        str(item["agent_key"]): item
        for item in agents
        if isinstance(item, dict) and item.get("implementation_status") == "IMPLEMENTED"
    }
    selected = selected_agents or set(implemented)
    unknown = selected - set(implemented)
    if unknown:
        raise ValueError(f"agents are not implemented: {sorted(unknown)}")
    location = str(platform["location"])
    expected_gateway_prefix = f"projects/{project_id}/locations/{location}/agentGateways/"
    for label, gateway in (
        ("egress", egress_agent_gateway),
        ("ingress", ingress_agent_gateway),
    ):
        if GATEWAY_PATTERN.fullmatch(gateway) is None or not gateway.startswith(
            expected_gateway_prefix
        ):
            raise ValueError(f"{label} gateway must be in the release project and location")
    model_resource = str(platform["model_resource"])
    model_location = str(platform["model_location"])
    model_endpoint = str(platform["model_endpoint"])
    validate_fast_fleet_route(
        model=model_resource,
        location=model_location,
        endpoint=model_endpoint,
    )
    targets = tuple(
        DeploymentTarget(
            agent_key=agent_key,
            app_module=str(implemented[agent_key]["app_module"]),
            display_name=f"solvan-{agent_key}-{release_version.replace('.', '-')}",
            model_resource=model_resource,
            permission_ceiling=str(implemented[agent_key]["permission_ceiling"]),
        )
        for agent_key in sorted(selected)
    )
    return DeploymentPlan(
        schema_version=1,
        project_id=project_id,
        environment=environment,
        location=location,
        model_location=model_location,
        model_endpoint=model_endpoint,
        staging_bucket=staging_bucket,
        egress_agent_gateway=egress_agent_gateway,
        ingress_agent_gateway=ingress_agent_gateway,
        release_version=release_version,
        manifest_version=str(manifest["manifest_version"]),
        manifest_sha256=_sha256(MANIFEST_PATH),
        requirements_sha256=_sha256(REQUIREMENTS_PATH),
        identity_type=str(platform["identity_type"]),
        mutation_mode="APPLY" if apply else "PLAN_ONLY",
        targets=targets,
    )


def deploy(
    plan: DeploymentPlan,
    *,
    client: AgentEngineClient,
    evidence_broker_url: str | None,
    actuator_url: str | None,
    verifier_url: str | None,
    workspace_tool_broker_url: str | None = None,
) -> list[dict[str, Any]]:
    if plan.identity_type != "AGENT_IDENTITY":
        raise ValueError("release deployment requires AGENT_IDENTITY")
    if any(
        target.permission_ceiling in {"READ_PRODUCTION_TELEMETRY", "READ_PRODUCTION_METADATA"}
        for target in plan.targets
    ) and (not evidence_broker_url or not evidence_broker_url.startswith("https://")):
        raise ValueError("read agents require an HTTPS evidence broker URL")
    if any(
        target.permission_ceiling == "INVOKE_PRIVATE_ACTUATOR_ONLY" for target in plan.targets
    ) and (not actuator_url or not actuator_url.startswith("https://")):
        raise ValueError("Execution Agent requires an HTTPS actuator URL")
    if any(
        target.permission_ceiling == "READ_TELEMETRY_AND_SYNTHETICS" for target in plan.targets
    ) and (not verifier_url or not verifier_url.startswith("https://")):
        raise ValueError("Verification Agent requires an HTTPS verifier URL")
    if any(
        target.permission_ceiling == "INVOKE_WORKSPACE_TOOL_BROKER_ONLY" for target in plan.targets
    ) and (not workspace_tool_broker_url or not workspace_tool_broker_url.startswith("https://")):
        raise ValueError("Workspace Agent requires an HTTPS Workspace Tool broker URL")

    from agentplatform import agent_engines  # type: ignore[import-untyped]
    from agentplatform._genai.types.common import IdentityType  # type: ignore[import-untyped]

    results: list[dict[str, Any]] = []
    for target in plan.targets:
        module = importlib.import_module(target.app_module)
        root_agent = getattr(module, "root_agent", None)
        if root_agent is None:
            raise RuntimeError(f"{target.agent_key} has no root_agent")
        wrapped_agent = agent_engines.AdkApp(
            app=App(
                name=f"solvan_{target.agent_key.replace('-', '_')}",
                root_agent=root_agent,
            )
        )
        env_vars: dict[str, str] = {
            "SOLVAN_ENVIRONMENT": plan.environment,
            "GOOGLE_GENAI_USE_VERTEXAI": "true",
            "GOOGLE_CLOUD_PROJECT": plan.project_id,
            "GOOGLE_CLOUD_LOCATION": plan.model_location,
            "SOLVAN_MODEL_ENDPOINT": plan.model_endpoint,
            "GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY": "true",
            "OTEL_SEMCONV_STABILITY_OPT_IN": "gen_ai_latest_experimental",
            "ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS": "false",
        }
        if target.permission_ceiling in {
            "READ_PRODUCTION_TELEMETRY",
            "READ_PRODUCTION_METADATA",
        }:
            env_vars["SOLVAN_EVIDENCE_BROKER_URL"] = cast(str, evidence_broker_url)
            env_vars["SOLVAN_EVIDENCE_AUDIENCE"] = cast(str, evidence_broker_url)
            env_vars["SOLVAN_AGENT_KEY"] = target.agent_key
        elif target.permission_ceiling == "INVOKE_PRIVATE_ACTUATOR_ONLY":
            env_vars["SOLVAN_ACTUATOR_URL"] = cast(str, actuator_url)
            env_vars["SOLVAN_ACTUATOR_AUDIENCE"] = cast(str, actuator_url)
            env_vars["SOLVAN_AGENT_KEY"] = target.agent_key
        elif target.permission_ceiling == "READ_TELEMETRY_AND_SYNTHETICS":
            env_vars["SOLVAN_VERIFIER_URL"] = cast(str, verifier_url)
            env_vars["SOLVAN_VERIFIER_AUDIENCE"] = cast(str, verifier_url)
            env_vars["SOLVAN_AGENT_KEY"] = target.agent_key
        elif target.permission_ceiling == "INVOKE_WORKSPACE_TOOL_BROKER_ONLY":
            env_vars["SOLVAN_WORKSPACE_TOOL_BROKER_URL"] = cast(str, workspace_tool_broker_url)
            env_vars["SOLVAN_WORKSPACE_TOOL_BROKER_AUDIENCE"] = cast(str, workspace_tool_broker_url)
            env_vars["SOLVAN_AGENT_KEY"] = target.agent_key
        remote = client.create(
            agent=wrapped_agent,
            config={
                "display_name": target.display_name,
                "description": (
                    f"Solvan {target.agent_key} release {plan.release_version}; "
                    f"ceiling={target.permission_ceiling}"
                ),
                "identity_type": IdentityType.AGENT_IDENTITY,
                "agent_gateway_config": {
                    "agent_to_anywhere_config": {
                        "agent_gateway": plan.egress_agent_gateway,
                    },
                    "client_to_agent_config": {
                        "agent_gateway": plan.ingress_agent_gateway,
                    },
                },
                "staging_bucket": plan.staging_bucket,
                "requirements": str(REQUIREMENTS_PATH),
                "extra_packages": [str(ROOT / "src" / "solvan")],
                "env_vars": env_vars,
                "agent_framework": "google-adk",
                "python_version": "3.12",
                "min_instances": 0,
                "max_instances": 2,
                "labels": {
                    "app": "solvan",
                    "agent": target.agent_key,
                    "release": plan.release_version.replace(".", "-")[:63],
                },
            },
        )
        results.append(_deployment_result(target, remote, plan=plan))
    return results


def _deployment_result(
    target: DeploymentTarget, remote: RemoteAgentResource, *, plan: DeploymentPlan
) -> dict[str, Any]:
    resource = remote.api_resource
    name = getattr(resource, "name", None)
    spec = getattr(resource, "spec", None)
    identity = getattr(spec, "effective_identity", None)
    identity_type = getattr(spec, "identity_type", None)
    identity_type_value = getattr(identity_type, "value", identity_type)
    deployment_spec = getattr(spec, "deployment_spec", None)
    gateway_config = getattr(deployment_spec, "agent_gateway_config", None)
    egress_config = getattr(gateway_config, "agent_to_anywhere_config", None)
    ingress_config = getattr(gateway_config, "client_to_agent_config", None)
    if not isinstance(name, str) or RESOURCE_PATTERN.fullmatch(name) is None:
        raise RuntimeError(f"{target.agent_key} returned no immutable Runtime resource name")
    if not isinstance(identity, str) or IDENTITY_PATTERN.fullmatch(identity) is None:
        raise RuntimeError(f"{target.agent_key} returned no system-attested effective identity")
    if identity_type_value != "AGENT_IDENTITY":
        raise RuntimeError(f"{target.agent_key} was not provisioned with Agent Identity")
    if getattr(egress_config, "agent_gateway", None) != plan.egress_agent_gateway:
        raise RuntimeError(f"{target.agent_key} did not bind the approved egress gateway")
    if getattr(ingress_config, "agent_gateway", None) != plan.ingress_agent_gateway:
        raise RuntimeError(f"{target.agent_key} did not bind the approved ingress gateway")
    return {
        "agent_key": target.agent_key,
        "immutable_resource_name": name,
        "effective_identity": identity,
        "iam_principal": f"principal://{identity}",
        "identity_type": identity_type_value,
        "egress_agent_gateway": plan.egress_agent_gateway,
        "ingress_agent_gateway": plan.ingress_agent_gateway,
        "display_name": getattr(resource, "display_name", target.display_name),
        "create_time": _json_time(getattr(resource, "create_time", None)),
        "status": "DEPLOYED_UNVERIFIED",
    }


def _json_time(value: object) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    return None


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _write_receipt(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(path)


def _client(plan: DeploymentPlan) -> AgentEngineClient:
    import agentplatform

    return cast(
        AgentEngineClient,
        agentplatform.Client(
            project=plan.project_id,
            location=plan.location,
            http_options={"api_version": "v1beta1"},
        ).agent_engines,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--environment", choices=("dev", "staging"), default="staging")
    parser.add_argument("--staging-bucket", required=True)
    parser.add_argument("--release-version", default="0.1.0")
    parser.add_argument("--egress-agent-gateway", required=True)
    parser.add_argument("--ingress-agent-gateway", required=True)
    parser.add_argument("--agent", action="append", dest="agents")
    parser.add_argument("--evidence-broker-url")
    parser.add_argument("--actuator-url")
    parser.add_argument("--verifier-url")
    parser.add_argument("--workspace-tool-broker-url")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        plan = build_plan(
            project_id=args.project,
            staging_bucket=args.staging_bucket,
            release_version=args.release_version,
            egress_agent_gateway=args.egress_agent_gateway,
            ingress_agent_gateway=args.ingress_agent_gateway,
            selected_agents=set(args.agents) if args.agents else None,
            apply=args.apply,
            environment=args.environment,
        )
        plan_value = asdict(plan)
        if not args.apply:
            print(json.dumps(plan_value, indent=2, sort_keys=True))
            return 0
        if args.receipt is None:
            raise ValueError("--receipt is required with --apply")
        started_at = datetime.now(UTC)
        results: list[dict[str, Any]] = []
        error: str | None = None
        try:
            results = deploy(
                plan,
                client=_client(plan),
                evidence_broker_url=args.evidence_broker_url,
                actuator_url=args.actuator_url,
                verifier_url=args.verifier_url,
                workspace_tool_broker_url=args.workspace_tool_broker_url,
            )
        except Exception as exception:
            error = f"{type(exception).__name__}: {exception}"
        receipt = {
            "schema_version": 1,
            "kind": "SOLVAN_AGENT_RUNTIME_DEPLOYMENT",
            "status": "DEPLOYED_UNVERIFIED" if error is None else "FAILED",
            "started_at": started_at.isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
            "plan": plan_value,
            "resources": results,
            "error": error,
            "warning": "This is a deployment receipt, not a platform preflight or release pass.",
        }
        _write_receipt(args.receipt, receipt)
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0 if error is None else 1
    except (KeyError, TypeError, ValueError) as exception:
        print(f"deployment configuration error: {exception}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
