"""Plan or apply exact Agent Identity-to-Registry-endpoint IAP policies."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from solvan.platform.google_rest import GoogleRestSession, authorized_session

_PRINCIPAL = re.compile(r"^principal://agents\.global\.[^/]+/resources/aiplatform/.+$")


@dataclass(frozen=True, slots=True)
class EndpointPolicy:
    endpoint_id: str
    members: tuple[str, ...]

    def value(self) -> dict[str, Any]:
        return {
            "policy": {
                "version": 1,
                "bindings": [
                    {
                        "role": "roles/iap.egressor",
                        "members": list(self.members),
                    }
                ],
            }
        }


def build_policies(receipt: dict[str, Any], *, environment: str) -> tuple[EndpointPolicy, ...]:
    resources = receipt.get("resources")
    if receipt.get("status") != "DEPLOYED_UNVERIFIED" or not isinstance(resources, list):
        raise ValueError("a successful Agent Runtime deployment receipt is required")
    principals: dict[str, str] = {}
    for item in resources:
        if not isinstance(item, dict):
            continue
        agent_key = item.get("agent_key")
        principal = item.get("iam_principal")
        if isinstance(agent_key, str) and isinstance(principal, str):
            if _PRINCIPAL.fullmatch(principal) is None:
                raise ValueError(f"{agent_key} has an invalid attested principal")
            principals[agent_key] = principal
    required_agents = {
        "workspace-agent",
        "evidence-agent",
        "execution-agent",
        "incident-supervisor",
        "infrastructure-agent",
        "verification-agent",
    }
    missing = required_agents - principals.keys()
    if missing:
        raise ValueError(f"deployment receipt is missing Runtime agents: {sorted(missing)}")
    all_runtime_members = tuple(sorted(principals[key] for key in required_agents))
    read_agents = {"evidence-agent", "infrastructure-agent"}
    policies = [
        EndpointPolicy(
            endpoint_id=f"solvan-{environment}-evidence-broker",
            members=tuple(sorted(principals[key] for key in read_agents)),
        )
    ]
    policies.append(
        EndpointPolicy(
            endpoint_id=f"solvan-{environment}-actuator",
            members=(principals["execution-agent"],),
        )
    )
    policies.append(
        EndpointPolicy(
            endpoint_id=f"solvan-{environment}-verifier",
            members=(principals["verification-agent"],),
        )
    )
    # Agent Gateway is default deny. The platform SDK itself calls these
    # registered destinations during Runtime startup and telemetry export, so
    # omitting them prevents otherwise-correct agents from starting.
    for dependency in (
        "aiplatform",
        "aiplatform-mtls",
        "aiplatform-rep",
        "resource-manager",
        "resource-manager-mtls",
        "logging",
        "telemetry",
        "telemetry-mtls",
    ):
        policies.append(
            EndpointPolicy(
                endpoint_id=f"solvan-{environment}-{dependency}",
                members=all_runtime_members,
            )
        )
    return tuple(policies)


def apply_policies(
    policies: tuple[EndpointPolicy, ...],
    *,
    project: str,
    region: str,
    session: GoogleRestSession | None = None,
) -> list[dict[str, Any]]:
    client = session or authorized_session()
    project_response = client.get(
        f"https://cloudresourcemanager.googleapis.com/v3/projects/{quote(project)}",
        timeout=30,
    )
    project_response.raise_for_status()
    project_value = project_response.json()
    project_name = project_value.get("name") if isinstance(project_value, dict) else None
    if not isinstance(project_name, str) or re.fullmatch(r"projects/[0-9]+", project_name) is None:
        raise RuntimeError("Resource Manager returned no canonical project number")
    project_number = project_name.removeprefix("projects/")
    results: list[dict[str, Any]] = []
    for policy in policies:
        if re.fullmatch(r"[a-z][a-z0-9-]{2,62}", policy.endpoint_id) is None:
            raise ValueError("IAP endpoint ID is malformed")
        response = client.post(
            "https://iap.googleapis.com/v1/"
            f"projects/{project_number}/locations/{quote(region)}/iap_web/"
            f"agentRegistry/endpoints/{quote(policy.endpoint_id)}:setIamPolicy",
            json=policy.value(),
            timeout=30,
        )
        response.raise_for_status()
        value = response.json()
        bindings = value.get("bindings") if isinstance(value, dict) else None
        observed = {
            member
            for binding in bindings or []
            if isinstance(binding, dict) and binding.get("role") == "roles/iap.egressor"
            for member in binding.get("members", [])
            if isinstance(member, str)
        }
        if observed != set(policy.members):
            raise RuntimeError(f"IAP policy reconciliation failed for {policy.endpoint_id}")
        results.append(
            {
                "endpoint_id": policy.endpoint_id,
                "members": list(policy.members),
                "status": "APPLIED_UNVERIFIED",
            }
        )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment-receipt", required=True, type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--region", default="europe-west1")
    parser.add_argument("--environment", choices=("dev", "staging"), default="staging")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    deployment = json.loads(args.deployment_receipt.read_text(encoding="utf-8"))
    if not isinstance(deployment, dict):
        raise ValueError("deployment receipt must be a JSON object")
    policies = build_policies(deployment, environment=args.environment)
    plan = {
        "schema_version": 1,
        "kind": "SOLVAN_AGENT_IAP_ENDPOINT_POLICIES",
        "project": args.project,
        "region": args.region,
        "mutation_mode": "APPLY" if args.apply else "PLAN_ONLY",
        "policies": [
            {"endpoint_id": policy.endpoint_id, "policy": policy.value()} for policy in policies
        ],
    }
    if not args.apply:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0
    if args.receipt is None:
        raise ValueError("--receipt is required with --apply")
    plan["results"] = apply_policies(policies, project=args.project, region=args.region)
    plan["completed_at"] = datetime.now(UTC).isoformat()
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
