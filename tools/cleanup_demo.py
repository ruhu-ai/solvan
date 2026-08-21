"""Pause fault-drill schedulers and restore the calibrated known-good fixture revision.

Planning is the default. Apply requires the exact deployment acknowledgement,
uses only Terraform-resolved scheduler/job identities, and leaves schedulers
paused. The resulting GCS receipt is recovery evidence, not a scenario pass.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tools.deploy_release import _run
from tools.run_gcp_scenarios import _download_gcs, _execute_job, _output

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class CleanupPlan:
    schema_version: int
    mutation_mode: str
    project_id: str
    release_commit: str
    deployment_id: str
    terraform_output: str
    output: str
    phases: tuple[str, ...]


def build_plan(
    *,
    project_id: str,
    release_commit: str,
    deployment_id: str,
    terraform_output: Path,
    output: Path,
    apply: bool,
) -> CleanupPlan:
    if re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", project_id) is None:
        raise ValueError("project ID is not canonical")
    if re.fullmatch(r"[0-9a-f]{40}", release_commit) is None:
        raise ValueError("release commit must be a full lowercase Git SHA")
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{2,62}", deployment_id) is None:
        raise ValueError("deployment ID is not canonical")
    if apply and not terraform_output.is_file():
        raise ValueError("Terraform output does not exist")
    return CleanupPlan(
        schema_version=1,
        mutation_mode="APPLY" if apply else "PLAN_ONLY",
        project_id=project_id,
        release_commit=release_commit,
        deployment_id=deployment_id,
        terraform_output=str(terraform_output.resolve()),
        output=str(output.resolve()),
        phases=(
            "resolve_exact_deployment_resources",
            "pause_all_release_schedulers",
            "execute_non_agent_cleanup_job",
            "verify_known_good_revision_and_target_epoch_receipt",
            "leave_schedulers_paused_for_operator_reconciliation",
        ),
    )


def _pause_schedulers(*, schedulers: dict[str, Any], project_id: str) -> dict[str, str]:
    if len(schedulers) != 4 or not all(
        isinstance(name, str) and name for name in schedulers.values()
    ):
        raise ValueError("Terraform output has no exact scheduler set")
    states: dict[str, str] = {}
    for key, name in sorted(schedulers.items()):
        _run(
            [
                "gcloud",
                "scheduler",
                "jobs",
                "pause",
                name,
                f"--project={project_id}",
                "--location=europe-west1",
                "--quiet",
            ]
        )
        states[str(key)] = _run(
            [
                "gcloud",
                "scheduler",
                "jobs",
                "describe",
                name,
                f"--project={project_id}",
                "--location=europe-west1",
                "--format=value(state)",
                "--quiet",
            ]
        ).strip()
    if set(states.values()) != {"PAUSED"}:
        raise RuntimeError("one or more release schedulers did not become paused")
    return states


def apply(plan: CleanupPlan, *, acknowledgement: str | None) -> dict[str, Any]:
    if acknowledgement != plan.deployment_id:
        raise ValueError("--ack-cleanup must exactly equal --deployment-id")
    raw = json.loads(Path(plan.terraform_output).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Terraform output is malformed")
    schedulers = _output(raw, "scheduler_jobs")
    jobs = _output(raw, "release_jobs")
    identities = _output(raw, "scenario_identities")
    bucket = _output(raw, "evidence_bucket")
    if not all(isinstance(item, dict) for item in (schedulers, jobs, identities)):
        raise ValueError("cleanup topology is malformed")
    injector_job = jobs.get("scenario_injector")
    oracle_identity = identities.get("oracle")
    if not isinstance(injector_job, str) or not isinstance(oracle_identity, str):
        raise ValueError("cleanup job or receipt-reader identity is unavailable")
    if not isinstance(bucket, str) or not bucket:
        raise ValueError("cleanup evidence bucket is unavailable")
    started_at = datetime.now(UTC)
    scheduler_states = _pause_schedulers(schedulers=schedulers, project_id=plan.project_id)
    cleanup_key = started_at.strftime("%Y%m%dT%H%M%S%fZ").lower()
    object_name = f"releases/{plan.deployment_id}/cleanup/{cleanup_key}.json"
    _execute_job(
        job_name=injector_job,
        project_id=plan.project_id,
        release_commit=plan.release_commit,
        deployment_id=plan.deployment_id,
        object_name=object_name,
        args_override="scenario-cleanup",
    )
    output = Path(plan.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    receipt_uri = f"gs://{bucket}/{object_name}"
    receipt = _download_gcs(
        uri=receipt_uri,
        destination=output,
        identity=oracle_identity,
        project_id=plan.project_id,
    )
    if (
        receipt.get("kind"),
        receipt.get("status"),
        receipt.get("project_id"),
        receipt.get("release_commit"),
        receipt.get("deployment_id"),
    ) != (
        "SOLVAN_DEMO_CLEANUP",
        "RESTORED",
        plan.project_id,
        plan.release_commit,
        plan.deployment_id,
    ):
        raise RuntimeError("cleanup receipt did not prove this release was restored")
    if receipt.get("observed_revision") != receipt.get("known_good_revision"):
        raise RuntimeError("cleanup receipt did not observe the known-good revision")
    return {
        "schema_version": 1,
        "kind": "SOLVAN_CLEANUP_RESULT",
        "status": "RESTORED_SCHEDULERS_PAUSED",
        "project_id": plan.project_id,
        "release_commit": plan.release_commit,
        "deployment_id": plan.deployment_id,
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "scheduler_states": scheduler_states,
        "cleanup_receipt_uri": receipt_uri,
        "local_receipt": str(output),
        "next_required_action": (
            "reconcile scheduler_paused=true through reviewed Terraform before another promotion"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--terraform-output", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--ack-cleanup")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    output = args.output or (
        ROOT / ".solvan" / "releases" / args.deployment_id / "cleanup-receipt.json"
    )
    try:
        plan = build_plan(
            project_id=args.project,
            release_commit=args.release_commit,
            deployment_id=args.deployment_id,
            terraform_output=args.terraform_output,
            output=output,
            apply=args.apply,
        )
        if not args.apply:
            print(json.dumps(asdict(plan), indent=2, sort_keys=True))
            return 0
        print(json.dumps(apply(plan, acknowledgement=args.ack_cleanup), indent=2, sort_keys=True))
        return 0
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"cleanup error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
