"""Evaluate the exact deployed Google Cloud topology and signed probe manifest."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from solvan.platform import evaluate_platform_preflight, topology_from_terraform_output
from solvan.platform.antigravity_preflight import ANTIGRAVITY_PROOFS
from solvan.platform.preflight import _REQUIRED_PROOFS


def load_proofs(
    path: Path,
    *,
    project_id: str,
    release_commit: str,
    deployment_id: str,
    expected_proofs: frozenset[str] = _REQUIRED_PROOFS,
) -> tuple[dict[str, bool], tuple[str, ...]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "project_id",
        "release_commit",
        "deployment_id",
        "proofs",
    }:
        raise ValueError("platform proof manifest schema is invalid")
    if value["schema_version"] != 1 or (
        value["project_id"],
        value["release_commit"],
        value["deployment_id"],
    ) != (project_id, release_commit, deployment_id):
        raise ValueError("platform proof manifest is not bound to this exact release")
    proofs = value["proofs"]
    if not isinstance(proofs, dict) or set(proofs) != expected_proofs:
        raise ValueError("platform proof manifest has an incomplete proof set")
    results: dict[str, bool] = {}
    references: list[str] = []
    for name, item in proofs.items():
        if not isinstance(item, dict) or set(item) != {"passed", "evidence_ref"}:
            raise ValueError(f"platform proof {name} has an invalid result schema")
        passed = item["passed"]
        evidence_ref = item["evidence_ref"]
        if not isinstance(passed, bool) or not isinstance(evidence_ref, str):
            raise ValueError(f"platform proof {name} has invalid types")
        if not evidence_ref.startswith("gs://"):
            raise ValueError(f"platform proof {name} is not durable GCS evidence")
        results[name] = passed
        references.append(evidence_ref)
    return results, tuple(dict.fromkeys(references))


def observe_project(project_id: str) -> tuple[str, bool, frozenset[str]]:
    project = _gcloud_json(["projects", "describe", project_id])
    billing = _gcloud_json(["billing", "projects", "describe", project_id])
    services = _gcloud_json(["services", "list", "--enabled", f"--project={project_id}"])
    project_number = project.get("projectNumber") if isinstance(project, dict) else None
    if not isinstance(project_number, str):
        raise RuntimeError("gcloud returned no project number")
    billing_enabled = bool(isinstance(billing, dict) and billing.get("billingEnabled") is True)
    if not isinstance(services, list):
        raise RuntimeError("gcloud enabled services response is malformed")
    enabled = frozenset(
        str(item["config"]["name"])
        for item in services
        if isinstance(item, dict)
        and isinstance(item.get("config"), dict)
        and isinstance(item["config"].get("name"), str)
    )
    return project_number, billing_enabled, enabled


def _gcloud_json(arguments: list[str]) -> Any:
    completed = subprocess.run(
        ["gcloud", *arguments, "--format=json", "--quiet"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"gcloud observation failed: {completed.stderr.strip()}")
    return json.loads(completed.stdout)


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terraform-output", required=True, type=Path)
    parser.add_argument("--proof-manifest", required=True, type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--upload-uri")
    args = parser.parse_args()
    terraform_value = json.loads(args.terraform_output.read_text(encoding="utf-8"))
    if not isinstance(terraform_value, dict):
        raise ValueError("Terraform output must be a JSON object")
    topology = topology_from_terraform_output(terraform_value)
    expected_proofs = _REQUIRED_PROOFS
    if topology.antigravity is not None:
        expected_proofs = frozenset(set(_REQUIRED_PROOFS) | set(ANTIGRAVITY_PROOFS))
    proofs, evidence_refs = load_proofs(
        args.proof_manifest,
        project_id=args.project,
        release_commit=args.release_commit,
        deployment_id=args.deployment_id,
        expected_proofs=expected_proofs,
    )
    project_number, billing_enabled, enabled_apis = observe_project(args.project)
    receipt = evaluate_platform_preflight(
        topology=topology,
        release_commit=args.release_commit,
        project_id=args.project,
        project_number=project_number,
        deployment_id=args.deployment_id,
        observed_at=datetime.now(UTC),
        billing_enabled=billing_enabled,
        enabled_apis=enabled_apis,
        proof_results=proofs,
        evidence_refs=evidence_refs,
    )
    _atomic_write(args.output, receipt.canonical_dict())
    if args.upload_uri:
        if not args.upload_uri.startswith("gs://"):
            raise ValueError("preflight upload destination must be a GCS URI")
        completed = subprocess.run(
            ["gcloud", "storage", "cp", str(args.output), args.upload_uri, "--quiet"],
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("failed to upload platform preflight receipt")
    print(json.dumps(receipt.canonical_dict(), indent=2, sort_keys=True))
    return 0 if receipt.status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
