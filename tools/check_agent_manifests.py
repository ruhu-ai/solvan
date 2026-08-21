"""Validate catalog, implementation, and dependency consistency."""

from __future__ import annotations

import importlib
import importlib.metadata
from pathlib import Path
from typing import Any

import yaml
from google.adk.agents import LlmAgent

from solvan.application.default_tool_catalog import AGENT_PROFILE_KEYS, TOOL_SEEDS
from solvan.platform.model_routes import validate_fast_fleet_route

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "specs/artifacts/agent-manifests.yaml"


def load_manifest() -> dict[str, Any]:
    value = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit("agent manifest must be a YAML mapping")
    return value


def main() -> None:
    manifest = load_manifest()
    if manifest.get("schema_version") != 1:
        raise SystemExit("unsupported agent manifest schema")
    platform = manifest["platform"]
    if platform.get("workspace_contract") != "WorkspaceAgent":
        raise SystemExit("WorkspaceAgent must be the sole workspace contract")
    if platform.get("workspace_compatibility_contracts") != []:
        raise SystemExit("legacy workspace compatibility contracts are prohibited")
    try:
        validate_fast_fleet_route(
            model=str(platform.get("model_resource", "")),
            location=str(platform.get("model_location", "")),
            endpoint=str(platform.get("model_endpoint", "")),
        )
    except ValueError as error:
        raise SystemExit(str(error)) from error
    resolved_adk = importlib.metadata.version("google-adk")
    resolved_runtime = importlib.metadata.version("google-cloud-aiplatform")
    if platform["framework_version"] != resolved_adk:
        raise SystemExit("manifest google-adk version differs from the lockfile environment")
    if platform["runtime_sdk_version"] != resolved_runtime:
        raise SystemExit("manifest Runtime SDK version differs from the lockfile environment")
    agents = manifest.get("agents")
    if not isinstance(agents, list) or not agents:
        raise SystemExit("agent manifest must contain agents")
    keys: set[str] = set()
    modules: set[str] = set()
    display_names: set[str] = set()
    for item in agents:
        if not isinstance(item, dict):
            raise SystemExit("each agent manifest must be a mapping")
        key = str(item["agent_key"])
        display_name = str(item.get("display_name", "")).strip()
        module_name = str(item["app_module"])
        if key in keys or module_name in modules:
            raise SystemExit(f"duplicate agent key or module for {key}")
        keys.add(key)
        modules.add(module_name)
        if not display_name or display_name in display_names:
            raise SystemExit(f"{key} must have a unique public display_name")
        display_names.add(display_name)
        if item.get("registry_kind") != "AGENT":
            raise SystemExit(f"{key} must be catalogued as an AGENT")
        if item.get("execution_role") not in {"SUPERVISOR", "SPECIALIST", "WORKSPACE"}:
            raise SystemExit(f"{key} has an invalid execution_role")
        if key == "incident-supervisor" and item["execution_role"] != "SUPERVISOR":
            raise SystemExit("incident-supervisor must be the SUPERVISOR role")
        expected_role = "WORKSPACE" if key == "workspace-agent" else "SPECIALIST"
        if key != "incident-supervisor" and item["execution_role"] != expected_role:
            raise SystemExit(f"{key} must use coordinator-dispatched {expected_role} role")
        tools = item.get("tools")
        if not isinstance(tools, list) or len(tools) != len(set(tools)):
            raise SystemExit(f"{key} tools must be a unique list")
        if item["implementation_status"] != "IMPLEMENTED":
            continue
        module = importlib.import_module(module_name)
        root_agent = getattr(module, "root_agent", None)
        if not isinstance(root_agent, LlmAgent):
            raise SystemExit(f"{key} implemented module has no Google ADK root_agent")
        actual_tools = sorted(_tool_name(tool) for tool in root_agent.tools)
        if key == "workspace-agent":
            workspace_aliases = {
                "read_workspace_artifact": "workspace.code-repair.read-artifact",
                "write_candidate_artifact": "workspace.code-repair.write-candidate-artifact",
                "run_in_exploratory_sandbox": "workspace.code-repair.run-in-sandbox",
            }
            actual_tools = sorted(workspace_aliases.get(tool, tool) for tool in actual_tools)
        if actual_tools != sorted(str(tool) for tool in tools):
            raise SystemExit(
                f"{key} tools differ: manifest={sorted(tools)} implementation={actual_tools}"
            )
        if root_agent.model != platform["model_resource"]:
            raise SystemExit(f"{key} model differs from the qualified platform manifest")
        if not root_agent.disallow_transfer_to_peers:
            raise SystemExit(f"{key} must prohibit peer transfer")
    required = {
        "incident-supervisor",
        "evidence-agent",
        "infrastructure-agent",
        "execution-agent",
        "verification-agent",
        "workspace-agent",
    }
    if keys != required:
        raise SystemExit(f"agent catalog keys differ: {sorted(keys ^ required)}")
    if set(AGENT_PROFILE_KEYS) != required:
        raise SystemExit("governed profile catalog differs from the Agent manifest")
    catalog_tools = {seed.key for seed in TOOL_SEEDS}
    manifest_tools = {
        str(tool) for item in agents if isinstance(item, dict) for tool in item.get("tools", [])
    }
    if catalog_tools != manifest_tools:
        raise SystemExit(
            f"governed Tool catalog differs from the Agent manifest: "
            f"{sorted(catalog_tools ^ manifest_tools)}"
        )
    optional_agents = manifest.get("optional_agents", [])
    if not isinstance(optional_agents, list):
        raise SystemExit("optional_agents must be a list")
    optional_keys: set[str] = set()
    for item in optional_agents:
        if not isinstance(item, dict):
            raise SystemExit("each optional agent manifest must be a mapping")
        key = str(item["agent_key"])
        if key in keys or key in optional_keys:
            raise SystemExit(f"duplicate optional agent key {key}")
        optional_keys.add(key)
        if not str(item.get("display_name", "")).strip():
            raise SystemExit(f"{key} must have a public display_name")
        if item.get("registry_kind") != "AGENT":
            raise SystemExit(f"{key} must be catalogued as an AGENT")
        if item.get("registry_behavior") != "REGISTER_ONLY_WHEN_ENABLED":
            raise SystemExit(f"{key} must be conditionally registered")
        if key == "antigravity-incident-workspace":
            if item.get("execution_role") != "WORKSPACE_PROVIDER":
                raise SystemExit(f"{key} must declare WORKSPACE_PROVIDER execution role")
            if item.get("data_classes") != ["PUBLIC"]:
                raise SystemExit(f"{key} must accept PUBLIC data only")
            if item.get("synthetic_attestation_required") is not True:
                raise SystemExit(f"{key} must require synthetic attestation")
            expected = {
                "workspace_provider": "AntigravityWorkspaceProvider",
                "implementation_sdk": "google-antigravity",
                "hosting_control_plane": "cloud-run",
                "hosting_data_plane": "private-https",
            }
            mismatches = {
                field: value for field, value in expected.items() if item.get(field) != value
            }
            if mismatches:
                raise SystemExit(f"{key} implementation boundary differs: {mismatches}")
            if not str(item.get("implementation_sdk_version", "")).strip():
                raise SystemExit(f"{key} must pin the official SDK version")
            if item.get("implementation_sdk_version") != "0.1.10":
                raise SystemExit(f"{key} must use the competition-frozen SDK version")
            if item.get("location") != platform["location"]:
                raise SystemExit(f"{key} must use the release region")
            if item.get("model_location") != "global":
                raise SystemExit(f"{key} must use the qualified Gemini 3.x endpoint")
            if item.get("model_resource") != "gemini-3.1-pro-preview":
                raise SystemExit(f"{key} must use the qualified deep-workspace model")
            if item.get("release_stage") != "ALPHA_SDK":
                raise SystemExit(f"{key} must disclose the SDK launch stage")
            if item.get("tools") != [
                "workspace_read_artifact",
                "workspace_write_candidate",
            ]:
                raise SystemExit(f"{key} must expose only the approved custom tools")
            if "base_agent" in item:
                raise SystemExit(f"{key} must not claim a Managed Agents base agent")
            if item.get("implementation_status") != "IMPLEMENTED":
                raise SystemExit(f"{key} provider service must be implemented")
            provider_module = importlib.import_module(str(item.get("provider_module")))
            service_module = importlib.import_module(str(item.get("service_module")))
            if not hasattr(provider_module, "AntigravityWorkspaceProvider"):
                raise SystemExit(f"{key} provider module has no implementation")
            if not hasattr(service_module, "app"):
                raise SystemExit(f"{key} service module has no FastAPI application")
        elif key == "liaison-agent":
            if item.get("execution_role") != "SPECIALIST":
                raise SystemExit(f"{key} must declare the non-privileged SPECIALIST role")
            if item.get("framework") != "google-adk":
                raise SystemExit(f"{key} must declare the implemented Google ADK query head")
            if item.get("framework_version") != resolved_adk:
                raise SystemExit(f"{key} Google ADK version differs from the lockfile environment")
            if item.get("model_resource") != platform["model_resource"]:
                raise SystemExit(f"{key} model differs from the qualified platform manifest")
            if item.get("model_location") != platform["model_location"]:
                raise SystemExit(
                    f"{key} model location differs from the qualified platform manifest"
                )
            if item.get("model_endpoint") != platform["model_endpoint"]:
                raise SystemExit(
                    f"{key} model endpoint differs from the qualified platform manifest"
                )
            module = importlib.import_module(str(item.get("application_module")))
            expected_tools = list(getattr(module, "LIAISON_ADK_TOOL_IDS", ()))
            if item.get("tools") != expected_tools:
                raise SystemExit(f"{key} tools differ from the implemented closed query head")
            for service_name in item.get("service_modules", []):
                service_module = importlib.import_module(str(service_name))
                if not hasattr(service_module, "app"):
                    raise SystemExit(f"{key} service module {service_name} has no application")
            expected_ceiling = {
                "reads": "DELEGATED_PROJECTIONS_ONLY",
                "writes": "CONVERSATION_ROWS_ONLY",
                "proposes": "STEER_VIA_COORDINATOR_INBOX",
            }
            if item.get("authority_ceiling") != expected_ceiling:
                raise SystemExit(f"{key} authority ceiling is incomplete or has drifted")
        else:
            raise SystemExit(f"unknown optional agent {key}")
        prohibited = item.get("prohibited_capabilities")
        if not isinstance(prohibited, list) or not prohibited:
            raise SystemExit(f"{key} must enumerate prohibited authority")
    implemented = sum(item["implementation_status"] == "IMPLEMENTED" for item in agents)
    optional_implemented = sum(
        item.get("implementation_status") == "IMPLEMENTED" for item in optional_agents
    )
    print(
        "Agent manifest check passed "
        f"({len(agents)} required; {implemented} implemented; "
        f"{optional_implemented}/{len(optional_agents)} optional implemented "
        "and disabled by default; "
        f"{check_deterministic_services(manifest)} deterministic service)"
    )


def check_deterministic_services(manifest: dict[str, Any]) -> int:
    """A deterministic seat is registered, identified, and provably model-free.

    The fleet's security claim depends on exactly one component holding
    production mutation capability. Registering it makes that claim legible;
    asserting `model_backed: false` keeps it true.
    """

    services = manifest.get("deterministic_services")
    if not isinstance(services, list) or not services:
        raise SystemExit("the manifest must register every deterministic service seat")
    seen: set[str] = set()
    for item in services:
        if not isinstance(item, dict):
            raise SystemExit("each deterministic service must be a mapping")
        key = str(item["service_key"])
        if key in seen:
            raise SystemExit(f"duplicate deterministic service {key}")
        seen.add(key)
        if item.get("model_backed") is not False:
            raise SystemExit(f"{key} must declare model_backed: false")
        if not str(item.get("display_name", "")).strip():
            raise SystemExit(f"{key} must have a public display_name")
        if item.get("registry_kind") != "DETERMINISTIC_SERVICE":
            raise SystemExit(f"{key} must not be catalogued as a model-backed Agent")
        if not item.get("allowed_operations"):
            raise SystemExit(f"{key} must enumerate its allowed operations")
        if not item.get("preconditions_revalidated"):
            raise SystemExit(f"{key} must state the preconditions it revalidates")
        accepted = item.get("accepts_from_caller") or []
        forbidden = {"payload", "target", "action_type", "expected_target_version"}
        if forbidden.intersection(accepted):
            raise SystemExit(
                f"{key} must not accept mutation material from its caller; "
                "it loads the stored action itself"
            )
    return len(seen)


def _tool_name(tool: object) -> str:
    name = getattr(tool, "name", None) or getattr(tool, "__name__", None)
    if not isinstance(name, str):
        raise SystemExit("implemented agent contains an unnamed tool or toolset")
    return name


if __name__ == "__main__":
    main()
