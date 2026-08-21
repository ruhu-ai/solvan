"""Promote a passing, durable preflight by unpausing release schedulers.

The default is plan-only. Apply requires the exact deployment acknowledgement,
the clean published commit, the same remote Terraform state, and a preflight
receipt downloaded from the deployment's evidence bucket. Any failed scheduler
reconciliation restores the paused configuration before returning failure.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from solvan.platform.preflight_receipt import parse_platform_preflight_receipt
from tools.deploy_release import TF_ROOT, _run, verify_release_source


@dataclass(frozen=True, slots=True)
class PromotionPlan:
    schema_version: int
    mutation_mode: str
    project_id: str
    release_commit: str
    deployment_id: str
    preflight_uri: str
    backend_config: str
    base_tfvars: str
    generated_tfvars: str
    remote: str


def build_plan(
    *,
    project_id: str,
    release_commit: str,
    deployment_id: str,
    preflight_uri: str,
    backend_config: Path,
    base_tfvars: Path,
    generated_tfvars: Path,
    remote: str,
    apply: bool,
) -> PromotionPlan:
    if re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", project_id) is None:
        raise ValueError("project ID is not canonical")
    if re.fullmatch(r"[0-9a-f]{40}", release_commit) is None:
        raise ValueError("release commit must be a full lowercase Git SHA")
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{2,62}", deployment_id) is None:
        raise ValueError("deployment ID is not canonical")
    if not preflight_uri.startswith("gs://"):
        raise ValueError("preflight receipt must be a durable GCS object")
    if apply:
        for label, path in (
            ("backend config", backend_config),
            ("base tfvars", base_tfvars),
            ("generated tfvars", generated_tfvars),
        ):
            if not path.is_file():
                raise ValueError(f"{label} does not exist: {path}")
    return PromotionPlan(
        schema_version=1,
        mutation_mode="APPLY" if apply else "PLAN_ONLY",
        project_id=project_id,
        release_commit=release_commit,
        deployment_id=deployment_id,
        preflight_uri=preflight_uri,
        backend_config=str(backend_config.resolve()),
        base_tfvars=str(base_tfvars.resolve()),
        generated_tfvars=str(generated_tfvars.resolve()),
        remote=remote,
    )


def validate_preflight(
    value: object, *, project_id: str, release_commit: str, deployment_id: str
) -> str:
    receipt = parse_platform_preflight_receipt(value)
    if (
        receipt.status != "PASS"
        or (receipt.project_id, receipt.release_commit, receipt.deployment_id)
        != (project_id, release_commit, deployment_id)
        or receipt.region != "europe-west1"
        or receipt.reason_codes
    ):
        raise ValueError("preflight receipt is not a passing result for this exact release")
    if not all(passed for _name, passed in receipt.proof_results):
        raise ValueError("preflight receipt does not contain all passing proofs")
    evidence_bucket = receipt.topology.evidence_bucket
    if any(not item.startswith(f"gs://{evidence_bucket}/") for item in receipt.evidence_refs):
        raise ValueError("preflight evidence is outside the release bucket")
    return evidence_bucket


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(path)


def _terraform_apply(plan: PromotionPlan) -> None:
    _run(
        [
            "terraform",
            f"-chdir={TF_ROOT}",
            "apply",
            "-input=false",
            "-auto-approve",
            f"-var-file={plan.base_tfvars}",
            f"-var-file={plan.generated_tfvars}",
        ]
    )


def apply_promotion(plan: PromotionPlan, *, acknowledgement: str | None) -> dict[str, Any]:
    if acknowledgement != plan.deployment_id:
        raise ValueError("--ack-unpause must exactly equal --deployment-id")
    commit, remote_url = verify_release_source(remote=plan.remote)
    if commit != plan.release_commit:
        raise ValueError("checked-out commit differs from the preflight release commit")
    work_dir = Path(plan.generated_tfvars).parent
    local_preflight = work_dir / "promotion-preflight.json"
    _run(["gcloud", "storage", "cp", plan.preflight_uri, str(local_preflight), "--quiet"])
    preflight = json.loads(local_preflight.read_text(encoding="utf-8"))
    evidence_bucket = validate_preflight(
        preflight,
        project_id=plan.project_id,
        release_commit=plan.release_commit,
        deployment_id=plan.deployment_id,
    )
    if not plan.preflight_uri.startswith(f"gs://{evidence_bucket}/"):
        raise ValueError("preflight receipt itself is outside the release evidence bucket")
    generated_path = Path(plan.generated_tfvars)
    generated = json.loads(generated_path.read_text(encoding="utf-8"))
    if not isinstance(generated, dict) or generated.get("project_id") != plan.project_id:
        raise ValueError("generated release variables belong to another project")
    if generated.get("scheduler_paused") is not True:
        raise ValueError("release schedulers are not in the required paused precondition")
    _run(
        [
            "terraform",
            f"-chdir={TF_ROOT}",
            "init",
            "-input=false",
            "-reconfigure",
            f"-backend-config={plan.backend_config}",
        ]
    )
    started_at = datetime.now(UTC)
    generated["scheduler_paused"] = False
    _atomic_json(generated_path, generated)
    try:
        _terraform_apply(plan)
        raw_output = _run(["terraform", f"-chdir={TF_ROOT}", "output", "-json"])
        outputs = json.loads(raw_output)
        scheduler_output = outputs.get("scheduler_jobs") if isinstance(outputs, dict) else None
        schedulers = scheduler_output.get("value") if isinstance(scheduler_output, dict) else None
        if not isinstance(schedulers, dict) or len(schedulers) != 4:
            raise RuntimeError("Terraform returned no exact scheduler job set")
        states: dict[str, str] = {}
        for key, name in schedulers.items():
            value = json.loads(
                _run(
                    [
                        "gcloud",
                        "scheduler",
                        "jobs",
                        "describe",
                        str(name),
                        f"--project={plan.project_id}",
                        "--location=europe-west1",
                        "--format=json",
                        "--quiet",
                    ]
                )
            )
            states[str(key)] = str(value.get("state")) if isinstance(value, dict) else "UNKNOWN"
        if set(states.values()) != {"ENABLED"}:
            raise RuntimeError("one or more release schedulers did not become enabled")
    except Exception:
        generated["scheduler_paused"] = True
        _atomic_json(generated_path, generated)
        try:
            _terraform_apply(plan)
        except Exception as rollback_error:
            raise RuntimeError(
                "promotion failed and scheduler pause rollback also failed"
            ) from rollback_error
        raise
    receipt = {
        "schema_version": 1,
        "kind": "SOLVAN_RELEASE_PROMOTION",
        "status": "PROMOTED_UNVERIFIED_SCENARIOS_PENDING",
        "project_id": plan.project_id,
        "release_commit": plan.release_commit,
        "deployment_id": plan.deployment_id,
        "remote_url": remote_url,
        "preflight_uri": plan.preflight_uri,
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "scheduler_states": states,
        "warning": "Platform preflight passed; S1-S6 are still required for the MSR gate.",
    }
    receipt_path = work_dir / "promotion-receipt.json"
    _atomic_json(receipt_path, receipt)
    receipt_uri = f"gs://{evidence_bucket}/releases/{plan.deployment_id}/promotion.json"
    _run(["gcloud", "storage", "cp", str(receipt_path), receipt_uri, "--quiet"])
    receipt["receipt_uri"] = receipt_uri
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--preflight-uri", required=True)
    parser.add_argument("--backend-config", required=True, type=Path)
    parser.add_argument("--base-tfvars", required=True, type=Path)
    parser.add_argument("--generated-tfvars", required=True, type=Path)
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--ack-unpause")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        plan = build_plan(
            project_id=args.project,
            release_commit=args.release_commit,
            deployment_id=args.deployment_id,
            preflight_uri=args.preflight_uri,
            backend_config=args.backend_config,
            base_tfvars=args.base_tfvars,
            generated_tfvars=args.generated_tfvars,
            remote=args.remote,
            apply=args.apply,
        )
        if not args.apply:
            print(json.dumps(asdict(plan), indent=2, sort_keys=True))
            return 0
        receipt = apply_promotion(plan, acknowledgement=args.ack_unpause)
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    except (OSError, RuntimeError, TypeError, ValueError) as exception:
        print(f"promotion error: {exception}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
