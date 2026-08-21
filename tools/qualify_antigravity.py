"""Replace the optional provider revision and prove stateless checkpoint rehydration."""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import httpx

from solvan.application import WorkspaceRehydrationReceipt
from solvan.platform import topology_from_terraform_output
from tools.antigravity_platform_probes import qualification_preflight, subprocess_run


@dataclass(frozen=True, slots=True)
class QualificationPlan:
    schema_version: int
    mutation_mode: str
    project_id: str
    release_commit: str
    deployment_id: str
    provider_service_name: str
    provider_uri: str
    coordinator_uri: str
    evidence_bucket: str


def build_plan(
    *,
    terraform_output: Path,
    project_id: str,
    release_commit: str,
    deployment_id: str,
    apply: bool,
) -> QualificationPlan:
    raw = json.loads(terraform_output.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Terraform output must be a JSON object")
    topology = topology_from_terraform_output(raw)
    optional = topology.antigravity
    if optional is None:
        raise ValueError("Antigravity topology is disabled")
    if topology.cloud_sql_connection_name.split(":", 1)[0] != project_id:
        raise ValueError("Terraform topology belongs to another project")
    if len(release_commit) != 40 or any(ch not in "0123456789abcdef" for ch in release_commit):
        raise ValueError("release commit must be one full lowercase Git SHA")
    if not deployment_id:
        raise ValueError("deployment ID is required")
    return QualificationPlan(
        schema_version=1,
        mutation_mode="APPLY_PROVIDER_REPLACEMENT" if apply else "PLAN_ONLY",
        project_id=project_id,
        release_commit=release_commit,
        deployment_id=deployment_id,
        provider_service_name=optional.provider_service_name,
        provider_uri=optional.provider_uri,
        coordinator_uri=dict(topology.service_uris)["coordinator"],
        evidence_bucket=topology.evidence_bucket,
    )


def _identity_token(*, service_account: str, audience: str) -> str:
    token = subprocess_run(
        [
            "gcloud",
            "auth",
            "print-identity-token",
            f"--impersonate-service-account={service_account}",
            f"--audiences={audience}",
            "--include-email",
            "--quiet",
        ]
    ).strip()
    if not token:
        raise RuntimeError("gcloud returned an empty coordinator identity token")
    return token


def _post(uri: str, *, token: str, body: dict[str, Any]) -> dict[str, Any]:
    response = httpx.post(
        uri,
        headers={"Authorization": f"Bearer {token}"},
        json=body,
        timeout=180,
    )
    response.raise_for_status()
    value = response.json()
    if not isinstance(value, dict):
        raise RuntimeError("coordinator returned a non-object response")
    return value


def qualify(
    plan: QualificationPlan,
    *,
    terraform_output: Path,
    acknowledgement: str | None,
    output: Path,
) -> dict[str, Any]:
    if acknowledgement != plan.deployment_id:
        raise ValueError("--ack-deployment must exactly equal --deployment-id")
    raw = json.loads(terraform_output.read_text(encoding="utf-8"))
    topology = topology_from_terraform_output(raw)
    optional = topology.antigravity
    if optional is None:
        raise ValueError("Antigravity topology is disabled")
    token = _identity_token(
        service_account=optional.coordinator_service_account,
        audience=plan.coordinator_uri,
    )
    candidate = _post(
        f"{plan.coordinator_uri}/internal/v1/workspaces:rehydration-candidate",
        token=token,
        body={"schema_version": 1},
    )
    if set(candidate) != {
        "workspace_id",
        "checkpoint_id",
        "provider_service_revision",
        "reconciliation_pending",
    }:
        raise RuntimeError("coordinator returned a malformed rehydration candidate")
    if not candidate["reconciliation_pending"]:
        suffix = f"q{secrets.token_hex(5)}"
        subprocess_run(
            [
                "gcloud",
                "run",
                "services",
                "update",
                plan.provider_service_name,
                f"--project={plan.project_id}",
                "--region=europe-west1",
                f"--revision-suffix={suffix}",
                "--quiet",
            ]
        )
    receipt_value = _post(
        f"{plan.coordinator_uri}/internal/v1/workspaces:rehydrate",
        token=token,
        body={
            "schema_version": 1,
            "workspace_id": candidate["workspace_id"],
            "expected_checkpoint_id": candidate["checkpoint_id"],
        },
    )
    receipt = WorkspaceRehydrationReceipt.model_validate(receipt_value)
    if receipt.provider_service_revision == candidate["provider_service_revision"]:
        raise RuntimeError("provider replacement reused the prior service revision")
    with tempfile.TemporaryDirectory(prefix="solvan-antigravity-qualification-") as directory:
        proof_results = qualification_preflight(
            optional,
            bucket=plan.evidence_bucket,
            project_id=plan.project_id,
            release_commit=plan.release_commit,
            deployment_id=plan.deployment_id,
            work_dir=Path(directory),
            run=subprocess_run,
        )
    result = {
        "schema_version": 1,
        "kind": "SOLVAN_ANTIGRAVITY_QUALIFICATION_RUN",
        "project_id": plan.project_id,
        "release_commit": plan.release_commit,
        "deployment_id": plan.deployment_id,
        "workspace_id": receipt.workspace_id,
        "checkpoint_id": receipt.checkpoint_id,
        "provider_service_revision_before": candidate["provider_service_revision"],
        "provider_service_revision_after": receipt.provider_service_revision,
        "proofs": {name: passed for name, (passed, _detail) in proof_results.items()},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=output.parent,
        prefix=f".{output.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
        handle.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
        handle.flush()
    temporary.replace(output)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terraform-output", required=True, type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ack-deployment")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        plan = build_plan(
            terraform_output=args.terraform_output,
            project_id=args.project,
            release_commit=args.release_commit,
            deployment_id=args.deployment_id,
            apply=args.apply,
        )
        if not args.apply:
            print(json.dumps(asdict(plan), indent=2, sort_keys=True))
            return 0
        result = qualify(
            plan,
            terraform_output=args.terraform_output,
            acknowledgement=args.ack_deployment,
            output=args.output,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if all(result["proofs"].values()) else 1
    except (OSError, RuntimeError, TypeError, ValueError, httpx.HTTPError) as error:
        print(f"Antigravity qualification error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
