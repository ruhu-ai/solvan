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
from collections.abc import Callable, Iterator
from contextlib import chdir
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
DEPLOYMENT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
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
    deployment_id: str
    release_commit: str
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

    def get(self, *, name: str) -> RemoteAgentResource: ...

    def list(self) -> Iterator[RemoteAgentResource]: ...


AGENT_RUNTIME_RESOURCE_LIMIT = 100


def _load_manifest() -> dict[str, Any]:
    value = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("agent manifest must be a mapping")
    return cast(dict[str, Any], value)


def build_plan(
    *,
    project_id: str,
    deployment_id: str,
    release_commit: str,
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
    if DEPLOYMENT_PATTERN.fullmatch(deployment_id) is None:
        raise ValueError("deployment ID is not canonical")
    if COMMIT_PATTERN.fullmatch(release_commit) is None:
        raise ValueError("release commit must be a full lowercase git SHA")
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
            display_name=f"solvan-{agent_key}-{release_commit[:10]}",
            model_resource=model_resource,
            permission_ceiling=str(implemented[agent_key]["permission_ceiling"]),
        )
        for agent_key in sorted(selected)
    )
    return DeploymentPlan(
        schema_version=1,
        project_id=project_id,
        deployment_id=deployment_id,
        release_commit=release_commit,
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


def _target_labels(plan: DeploymentPlan, target: DeploymentTarget) -> dict[str, str]:
    return {
        "app": "solvan",
        "agent": target.agent_key,
        "release": plan.release_version.replace(".", "-")[:63],
        "deployment": plan.deployment_id,
        "commit": plan.release_commit,
        "manifest": plan.manifest_sha256.removeprefix("sha256:")[:32],
        "requirements": plan.requirements_sha256.removeprefix("sha256:")[:32],
    }


def _remote_labels(remote: RemoteAgentResource) -> dict[str, str]:
    labels = getattr(remote.api_resource, "labels", None)
    if not isinstance(labels, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in labels.items()
    ):
        return {}
    return cast(dict[str, str], labels)


def deploy(
    plan: DeploymentPlan,
    *,
    client: AgentEngineClient,
    evidence_broker_url: str | None,
    actuator_url: str | None,
    verifier_url: str | None,
    workspace_tool_broker_url: str | None = None,
    existing_results: list[dict[str, Any]] | None = None,
    unresolved_agents: set[str] | None = None,
    on_target_start: Callable[[str], None] | None = None,
    on_result: Callable[[list[dict[str, Any]]], None] | None = None,
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

    stored_by_key: dict[str, dict[str, Any]] = {}
    for item in existing_results or []:
        key = item.get("agent_key") if isinstance(item, dict) else None
        if not isinstance(key, str) or key in stored_by_key:
            raise ValueError("existing Agent Runtime results are malformed or duplicated")
        stored_by_key[key] = item
    if set(stored_by_key) - {target.agent_key for target in plan.targets}:
        raise ValueError("existing Agent Runtime result is outside the deployment plan")
    unresolved = unresolved_agents or set()
    if unresolved - {target.agent_key for target in plan.targets}:
        raise ValueError("unresolved Agent Runtime attempt is outside the deployment plan")

    remote_resources = list(client.list())
    remote_by_key: dict[str, list[RemoteAgentResource]] = {
        target.agent_key: [] for target in plan.targets
    }
    for remote in remote_resources:
        for target in plan.targets:
            expected_labels = _target_labels(plan, target)
            labels = _remote_labels(remote)
            if all(labels.get(key) == value for key, value in expected_labels.items()):
                remote_by_key[target.agent_key].append(remote)

    ambiguous = [
        target.agent_key for target in plan.targets if len(remote_by_key[target.agent_key]) > 1
    ]
    if ambiguous:
        raise RuntimeError(f"multiple exact Runtime resources exist for {ambiguous[0]}")
    unresolved_missing = [
        target.agent_key
        for target in plan.targets
        if target.agent_key in unresolved
        and target.agent_key not in stored_by_key
        and not remote_by_key[target.agent_key]
    ]
    if unresolved_missing:
        raise RuntimeError(
            f"interrupted {unresolved_missing[0]} create has no visible exact resource; "
            "refusing a duplicate create"
        )
    missing_count = sum(
        target.agent_key not in stored_by_key and not remote_by_key[target.agent_key]
        for target in plan.targets
    )
    if len(remote_resources) + missing_count > AGENT_RUNTIME_RESOURCE_LIMIT:
        raise RuntimeError(
            "insufficient Agent Runtime resource capacity before create: "
            f"existing={len(remote_resources)}, required_new={missing_count}, "
            f"limit={AGENT_RUNTIME_RESOURCE_LIMIT}; remove superseded resources or "
            "increase the regional quota"
        )

    results: list[dict[str, Any]] = []
    for target in plan.targets:
        if on_target_start is not None:
            on_target_start(target.agent_key)
        stored = stored_by_key.get(target.agent_key)
        if stored is not None:
            name = stored.get("immutable_resource_name")
            if not isinstance(name, str) or RESOURCE_PATTERN.fullmatch(name) is None:
                raise RuntimeError(f"stored {target.agent_key} resource name is malformed")
            result = _reconcile_stored_result(
                target.agent_key,
                stored=stored,
                observed=_deployment_result(target, client.get(name=name), plan=plan),
            )
            results.append(result)
            if on_result is not None:
                on_result(results)
            continue
        candidates = remote_by_key[target.agent_key]
        if len(candidates) == 1:
            results.append(_deployment_result(target, candidates[0], plan=plan))
            if on_result is not None:
                on_result(results)
            continue
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
            # The first live staging query died before reaching the model: the
            # engine container's storage client auto-negotiated the mTLS
            # endpoint (storage.mtls.googleapis.com) and failed certificate
            # verification against a chain its trust store calls self-signed,
            # so downloading the query input crashed the job with exit 1
            # (staging-20260823-04, runtime_query_job_completed). The agents
            # present no client certificate and gain nothing from mTLS
            # negotiation, so pin the documented off-switch rather than trust
            # whatever certificate configuration the managed image ships.
            "GOOGLE_API_USE_MTLS_ENDPOINT": "never",
            "GOOGLE_GENAI_USE_VERTEXAI": "true",
            "SOLVAN_MODEL_ENDPOINT": plan.model_endpoint,
            # SOLVAN_MODEL_ENDPOINT is receipt metadata that no SDK reads;
            # GOOGLE_VERTEX_BASE_URL is the variable google-genai actually
            # honors (google.genai._base_url, verified against the pinned
            # 2.19.0). Without it the fleet's EU-REP endpoint was asserted in
            # receipts and enforced nowhere: the client derived its own URL
            # from the location and the receipts wrote a table lookup.
            "GOOGLE_VERTEX_BASE_URL": plan.model_endpoint,
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
        # The SDK preserves the supplied path inside dependencies.tar.gz. An
        # absolute ROOT/src/solvan path therefore extracts under its host path
        # and is not importable as `solvan` in Runtime. Package from ROOT/src so
        # the archive has exactly `solvan/` at its top level.
        with chdir(ROOT / "src"):
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
                    "extra_packages": ["solvan"],
                    "env_vars": env_vars,
                    "agent_framework": "google-adk",
                    "python_version": "3.12",
                    "min_instances": 0,
                    "max_instances": 2,
                    "labels": _target_labels(plan, target),
                },
            )
        results.append(_deployment_result(target, remote, plan=plan))
        if on_result is not None:
            on_result(results)
    return results


def _reconcile_stored_result(
    agent_key: str,
    *,
    stored: dict[str, Any],
    observed: dict[str, Any],
) -> dict[str, Any]:
    stored_stable = {key: value for key, value in stored.items() if key != "create_time"}
    observed_stable = {key: value for key, value in observed.items() if key != "create_time"}
    if stored_stable != observed_stable:
        raise RuntimeError(f"stored {agent_key} result differs from provider state")
    stored_create_time = stored.get("create_time")
    observed_create_time = observed.get("create_time")
    if (
        stored_create_time is not None
        and observed_create_time is not None
        and stored_create_time != observed_create_time
    ):
        raise RuntimeError(f"stored {agent_key} result differs from provider state")
    if observed_create_time is None:
        observed["create_time"] = stored_create_time
    return observed


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
    labels = _remote_labels(remote)
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
    if any(labels.get(key) != value for key, value in _target_labels(plan, target).items()):
        raise RuntimeError(f"{target.agent_key} did not bind the exact deployment labels")
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
    value.pop("receipt_sha256", None)
    value["receipt_sha256"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
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
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--release-commit", required=True)
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
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    try:
        plan = build_plan(
            project_id=args.project,
            deployment_id=args.deployment_id,
            release_commit=args.release_commit,
            staging_bucket=args.staging_bucket,
            release_version=args.release_version,
            egress_agent_gateway=args.egress_agent_gateway,
            ingress_agent_gateway=args.ingress_agent_gateway,
            selected_agents=set(args.agents) if args.agents else None,
            apply=args.apply,
            environment=args.environment,
        )
        plan_value = json.loads(json.dumps(asdict(plan)))
        if not args.apply:
            if args.resume:
                raise ValueError("--resume requires --apply")
            print(json.dumps(plan_value, indent=2, sort_keys=True))
            return 0
        if args.receipt is None:
            raise ValueError("--receipt is required with --apply")
        if args.resume:
            if not args.receipt.is_file():
                raise ValueError("--resume requires an existing deployment receipt")
            receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
            if not isinstance(receipt, dict):
                raise ValueError("deployment receipt is malformed")
            stored_digest = receipt.pop("receipt_sha256", None)
            expected_digest = (
                "sha256:"
                + hashlib.sha256(
                    json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
            )
            if stored_digest != expected_digest:
                raise ValueError("deployment receipt digest does not match its contents")
            if (
                receipt.get("schema_version") != 2
                or receipt.get("kind") != "SOLVAN_AGENT_RUNTIME_DEPLOYMENT"
                or receipt.get("plan") != plan_value
                or receipt.get("plan_sha256")
                != "sha256:"
                + hashlib.sha256(
                    json.dumps(plan_value, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                or receipt.get("status") not in {"FAILED", "INTERRUPTED"}
            ):
                raise ValueError("deployment receipt is not an exact resumable plan")
            receipt["receipt_sha256"] = stored_digest
            existing = receipt.get("resources")
            if not isinstance(existing, list):
                raise ValueError("deployment receipt resources are malformed")
            results = cast(list[dict[str, Any]], existing)
            current_agent = receipt.get("current_agent")
            if current_agent is not None and not isinstance(current_agent, str):
                raise ValueError("deployment receipt current agent is malformed")
            unresolved_agents = {current_agent} if isinstance(current_agent, str) else set()
            receipt["attempts"] = int(receipt.get("attempts", 0)) + 1
        else:
            if args.receipt.exists():
                raise ValueError("deployment receipt exists; use --resume or a new path")
            now = datetime.now(UTC).isoformat()
            results = []
            unresolved_agents = set()
            receipt = {
                "schema_version": 2,
                "kind": "SOLVAN_AGENT_RUNTIME_DEPLOYMENT",
                "status": "IN_PROGRESS",
                "started_at": now,
                "updated_at": now,
                "attempts": 1,
                "plan": plan_value,
                "plan_sha256": "sha256:"
                + hashlib.sha256(
                    json.dumps(plan_value, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
                "resources": results,
                "current_agent": None,
                "warning": (
                    "This is a deployment receipt, not a platform preflight or release pass."
                ),
            }
        receipt.update({"status": "IN_PROGRESS", "updated_at": datetime.now(UTC).isoformat()})
        receipt.pop("error", None)
        _write_receipt(args.receipt, receipt)

        def on_target_start(agent_key: str) -> None:
            receipt.update(
                {"current_agent": agent_key, "updated_at": datetime.now(UTC).isoformat()}
            )
            _write_receipt(args.receipt, receipt)

        def on_result(current: list[dict[str, Any]]) -> None:
            results[:] = current
            receipt.update(
                {
                    "resources": results,
                    "current_agent": None,
                    "updated_at": datetime.now(UTC).isoformat(),
                }
            )
            _write_receipt(args.receipt, receipt)

        try:
            results = deploy(
                plan,
                client=_client(plan),
                evidence_broker_url=args.evidence_broker_url,
                actuator_url=args.actuator_url,
                verifier_url=args.verifier_url,
                workspace_tool_broker_url=args.workspace_tool_broker_url,
                existing_results=results,
                unresolved_agents=unresolved_agents,
                on_target_start=on_target_start,
                on_result=on_result,
            )
        except KeyboardInterrupt:
            receipt.update(
                {
                    "status": "INTERRUPTED",
                    "resources": results,
                    "error": "KeyboardInterrupt: operator interrupted Agent Runtime deployment",
                    "updated_at": datetime.now(UTC).isoformat(),
                }
            )
            _write_receipt(args.receipt, receipt)
            print("Agent Runtime deployment interrupted; checkpoint retained", file=sys.stderr)
            return 130
        except Exception as exception:
            receipt.update(
                {
                    "status": "FAILED",
                    "resources": results,
                    "error": f"{type(exception).__name__}: {exception}",
                    "updated_at": datetime.now(UTC).isoformat(),
                }
            )
            _write_receipt(args.receipt, receipt)
            print(json.dumps(receipt, indent=2, sort_keys=True))
            return 1
        receipt.update(
            {
                "status": "DEPLOYED_UNVERIFIED",
                "resources": results,
                "current_agent": None,
                "completed_at": datetime.now(UTC).isoformat(),
                "updated_at": datetime.now(UTC).isoformat(),
            }
        )
        _write_receipt(args.receipt, receipt)
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    except (KeyError, TypeError, ValueError) as exception:
        print(f"deployment configuration error: {exception}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
