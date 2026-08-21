"""Run exact-deployment GCP release scenarios and emit durable receipts.

Planning is the default. S1 executes the live closed-loop path; S2-S6 execute
fixed, isolated GCP fixtures and independent read-only oracles. Local contract
evidence is never accepted by this runner.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from solvan.application import EvidenceMode, EvidenceStatus, ScenarioReceipt
from solvan.platform import topology_from_terraform_output
from tools.deploy_release import _run, verify_release_source
from tools.promote_release import validate_preflight
from tools.scenario_oracles import S1_ASSERTIONS
from tools.scripted_scenario_contracts import SCRIPTED_ASSERTIONS

ROOT = Path(__file__).resolve().parents[1]
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
DEPLOYMENT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")


@dataclass(frozen=True, slots=True)
class CloudScenarioPlan:
    schema_version: int
    mutation_mode: str
    project_id: str
    release_commit: str
    deployment_id: str
    terraform_output: str
    preflight_receipt: str
    human_identity_token_file: str | None
    output_dir: str
    scenarios: tuple[str, ...]
    phases: tuple[str, ...]


def build_plan(
    *,
    project_id: str,
    release_commit: str,
    deployment_id: str,
    terraform_output: Path,
    preflight_receipt: Path,
    human_identity_token_file: Path | None,
    output_dir: Path,
    scenarios: tuple[str, ...],
    apply: bool,
) -> CloudScenarioPlan:
    if re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", project_id) is None:
        raise ValueError("project ID is not canonical")
    if COMMIT_PATTERN.fullmatch(release_commit) is None:
        raise ValueError("release commit must be a full lowercase Git SHA")
    if DEPLOYMENT_PATTERN.fullmatch(deployment_id) is None:
        raise ValueError("deployment ID is not canonical")
    allowed_scenarios = {f"S{index}" for index in range(1, 7)}
    if not scenarios or any(item not in allowed_scenarios for item in scenarios):
        raise ValueError("scenario selection must contain S1 through S6")
    if apply:
        for label, path in (
            ("Terraform output", terraform_output),
            ("preflight receipt", preflight_receipt),
        ):
            if not path.is_file():
                raise ValueError(f"{label} does not exist: {path}")
        if "S1" in scenarios and (
            human_identity_token_file is None or not human_identity_token_file.is_file()
        ):
            raise ValueError("S1 requires a one-time human identity token file")
    phases = [
        "validate_exact_passing_preflight_and_live_topology",
        "verify_clean_published_release_commit",
        "verify_promoted_scheduler_state",
    ]
    if "S1" in scenarios:
        phases.extend(
            (
                "execute_non_agent_fault_injector_job",
                "run_real_detector_burst_and_durable_coordinator_ticks",
                "pause_at_exact_human_approval",
                "continue_execution_and_independent_verification",
                "execute_read_only_s1_oracle_job",
            )
        )
    if any(item != "S1" for item in scenarios):
        phases.extend(
            (
                "execute_isolated_scripted_gcp_fixture_jobs",
                "execute_read_only_scripted_oracle_jobs",
            )
        )
    phases.append("upload_exact_deployment_scenario_receipts")
    return CloudScenarioPlan(
        schema_version=1,
        mutation_mode="APPLY" if apply else "PLAN_ONLY",
        project_id=project_id,
        release_commit=release_commit,
        deployment_id=deployment_id,
        terraform_output=str(terraform_output.resolve()),
        preflight_receipt=str(preflight_receipt.resolve()),
        human_identity_token_file=(
            None if human_identity_token_file is None else str(human_identity_token_file.resolve())
        ),
        output_dir=str(output_dir.resolve()),
        scenarios=scenarios,
        phases=tuple(phases),
    )


def _output(value: dict[str, Any], name: str) -> Any:
    item = value.get(name)
    if not isinstance(item, dict) or "value" not in item:
        raise ValueError(f"Terraform output is missing {name}")
    return item["value"]


def _scenario_run_id(*, deployment_id: str, scenario_id: str, started_at: datetime) -> str:
    digest = hashlib.sha256(
        f"{deployment_id}:{scenario_id}:{started_at.isoformat()}".encode()
    ).hexdigest()[:16]
    prefix = deployment_id[:38].rstrip("-")
    return f"{prefix}-{scenario_id.lower()}-{digest}"


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    pieces = token.split(".")
    if len(pieces) != 3:
        raise ValueError("human identity token is not a JWT")
    padding = "=" * (-len(pieces[1]) % 4)
    try:
        value = json.loads(base64.urlsafe_b64decode(pieces[1] + padding))
    except (ValueError, json.JSONDecodeError) as error:
        raise ValueError("human identity token payload is malformed") from error
    if not isinstance(value, dict):
        raise ValueError("human identity token payload is not an object")
    return value


def _human_token(path: Path, *, expected_audience: str) -> str:
    token = path.read_text(encoding="utf-8").strip().removeprefix("Bearer ").strip()
    claims = _decode_jwt_payload(token)
    if claims.get("aud") != expected_audience:
        raise ValueError("human identity token audience differs from the deployed approval policy")
    expiry = claims.get("exp")
    if not isinstance(expiry, int | float) or expiry <= time.time() + 120:
        raise ValueError("human identity token expires too soon for S1")
    if claims.get("email_verified") is not True or not isinstance(claims.get("email"), str):
        raise ValueError("human identity token has no verified email")
    return token


def _identity_token(*, identity: str, audience: str, project_id: str) -> str:
    return _run(
        [
            "gcloud",
            "auth",
            "print-identity-token",
            f"--impersonate-service-account={identity}",
            f"--audiences={audience}",
            "--include-email",
            f"--project={project_id}",
            "--quiet",
        ]
    ).strip()


def _request(
    *,
    method: str,
    base_url: str,
    path: str,
    identity: str,
    project_id: str,
    body: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout: float = 90,
) -> dict[str, Any]:
    token = _identity_token(identity=identity, audience=base_url, project_id=project_id)
    response = httpx.request(
        method,
        f"{base_url.rstrip('/')}{path}",
        headers={
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            **(extra_headers or {}),
        },
        json=body,
        timeout=timeout,
    )
    response.raise_for_status()
    if not response.content:
        return {}
    value = response.json()
    if not isinstance(value, dict):
        raise RuntimeError("release service returned a non-object response")
    return value


def _execute_job(
    *,
    job_name: str,
    project_id: str,
    release_commit: str,
    deployment_id: str,
    object_name: str,
    args_override: str | None = None,
    scenario_run_id: str | None = None,
    allow_failed_exit: bool = False,
) -> bool:
    environment = (
        f"SOLVAN_RELEASE_COMMIT={release_commit},"
        f"SOLVAN_DEPLOYMENT_ID={deployment_id},"
        f"SOLVAN_SCENARIO_OBJECT_NAME={object_name}"
    )
    if scenario_run_id is not None:
        environment += f",SOLVAN_SCENARIO_RUN_ID={scenario_run_id}"
    command = [
        "gcloud",
        "run",
        "jobs",
        "execute",
        job_name,
        f"--project={project_id}",
        "--region=europe-west1",
        f"--update-env-vars={environment}",
        "--wait",
        "--quiet",
    ]
    if args_override is not None:
        command.insert(-2, f"--args={args_override}")
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=1200,
    )
    if completed.returncode != 0 and not allow_failed_exit:
        detail = (completed.stderr or completed.stdout or "no output").strip()
        raise RuntimeError(f"scenario job failed: {detail[-1000:]}")
    return completed.returncode == 0


def _download_gcs(*, uri: str, destination: Path, identity: str, project_id: str) -> dict[str, Any]:
    _run(
        [
            "gcloud",
            "storage",
            "cp",
            uri,
            str(destination),
            f"--impersonate-service-account={identity}",
            f"--project={project_id}",
            "--quiet",
        ]
    )
    value = json.loads(destination.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("scenario evidence object is malformed")
    return value


def _snapshot(*, api_uri: str, oracle_identity: str, project_id: str) -> dict[str, Any]:
    return _request(
        method="GET",
        base_url=api_uri,
        path="/api/console/snapshot",
        identity=oracle_identity,
        project_id=project_id,
    )


def _tick(*, coordinator_uri: str, injector_identity: str, project_id: str) -> None:
    _request(
        method="POST",
        base_url=coordinator_uri,
        path="/internal/wakeups/tick",
        identity=injector_identity,
        project_id=project_id,
        body={"schema_version": 1},
        timeout=330,
    )


def _await_snapshot(
    *,
    api_uri: str,
    coordinator_uri: str,
    oracle_identity: str,
    injector_identity: str,
    project_id: str,
    predicate: Any,
    timeout_seconds: int = 900,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        _tick(
            coordinator_uri=coordinator_uri,
            injector_identity=injector_identity,
            project_id=project_id,
        )
        last = _snapshot(
            api_uri=api_uri,
            oracle_identity=oracle_identity,
            project_id=project_id,
        )
        if predicate(last):
            return last
        time.sleep(10)
    states = [item.get("state") for item in last.get("incidents", []) if isinstance(item, dict)]
    raise TimeoutError(f"S1 did not reach the required state; last incident states: {states}")


def _awaiting_approval(snapshot: dict[str, Any]) -> bool:
    incidents = snapshot.get("incidents")
    if not isinstance(incidents, list) or len(incidents) != 1:
        return False
    incident = incidents[0]
    return isinstance(incident, dict) and any(
        isinstance(action, dict)
        and action.get("status") == "AWAITING_APPROVAL"
        and action.get("digest")
        for action in incident.get("actions", [])
    )


def _mitigated_with_case(snapshot: dict[str, Any]) -> bool:
    incidents = snapshot.get("incidents")
    cases = snapshot.get("cases")
    return bool(
        isinstance(incidents, list)
        and len(incidents) == 1
        and isinstance(incidents[0], dict)
        and incidents[0].get("state") == "MITIGATED"
        and isinstance(cases, list)
        and len(cases) >= 1
    )


def _approve(
    *,
    snapshot: dict[str, Any],
    api_uri: str,
    injector_identity: str,
    human_token: str,
    project_id: str,
) -> str:
    incident = snapshot["incidents"][0]
    action = next(
        item
        for item in incident["actions"]
        if item.get("status") == "AWAITING_APPROVAL" and item.get("digest")
    )
    action_id = str(action["id"])
    _request(
        method="POST",
        base_url=api_uri,
        path=f"/api/v1/actions/{action_id}:approve",
        identity=injector_identity,
        project_id=project_id,
        extra_headers={
            "x-solvan-approval-token": f"Bearer {human_token}",
            "idempotency-key": f"s1-{action_id}",
        },
        body={
            "schema_version": 1,
            "action_digest": action["digest"],
            "reason": "Release S1 operator approved the exact rollback material.",
        },
    )
    return action_id


def _verify_schedulers(value: dict[str, Any], *, project_id: str) -> None:
    jobs = _output(value, "scheduler_jobs")
    if not isinstance(jobs, dict) or len(jobs) != 4:
        raise ValueError("Terraform output has no exact scheduler set")
    for name in jobs.values():
        raw = _run(
            [
                "gcloud",
                "scheduler",
                "jobs",
                "describe",
                str(name),
                f"--project={project_id}",
                "--location=europe-west1",
                "--format=value(state)",
                "--quiet",
            ]
        ).strip()
        if raw != "ENABLED":
            raise RuntimeError("release scenarios require promoted ENABLED schedulers")


def run_s1(
    *,
    plan: CloudScenarioPlan,
    terraform_value: dict[str, Any],
    bucket: str,
    human_token: str,
    output_dir: Path,
) -> ScenarioReceipt:
    services = _output(terraform_value, "service_uris")
    identities = _output(terraform_value, "scenario_identities")
    jobs = _output(terraform_value, "release_jobs")
    if not all(isinstance(item, dict) for item in (services, identities, jobs)):
        raise ValueError("Terraform scenario topology is malformed")
    injector = identities.get("injector")
    oracle = identities.get("oracle")
    injector_job = jobs.get("scenario_injector")
    oracle_job = jobs.get("scenario_oracle")
    scenario_material = (injector, oracle, injector_job, oracle_job)
    if not all(isinstance(item, str) and item for item in scenario_material):
        raise ValueError("release was not seeded with scenario jobs and identities")
    started_at = datetime.now(UTC)
    run_suffix = started_at.strftime("%Y%m%dT%H%M%S%fZ")
    fault_object = f"scenarios/{plan.deployment_id}/S1/{run_suffix}-fault.json"
    oracle_object = f"scenarios/{plan.deployment_id}/S1/{run_suffix}-oracle.json"
    _execute_job(
        job_name=injector_job,
        project_id=plan.project_id,
        release_commit=plan.release_commit,
        deployment_id=plan.deployment_id,
        object_name=fault_object,
    )
    fault_uri = f"gs://{bucket}/{fault_object}"
    _request(
        method="POST",
        base_url=services["detector"],
        path="/internal/detection/burst",
        identity=injector,
        project_id=plan.project_id,
        body={
            "schema_version": 1,
            "offsets_seconds": [0, 25, 50],
            "rule_ids": ["payments-http-5xx-v1"],
        },
        timeout=180,
    )
    approval_snapshot = _await_snapshot(
        api_uri=services["api"],
        coordinator_uri=services["coordinator"],
        oracle_identity=oracle,
        injector_identity=injector,
        project_id=plan.project_id,
        predicate=_awaiting_approval,
    )
    _approve(
        snapshot=approval_snapshot,
        api_uri=services["api"],
        injector_identity=injector,
        human_token=human_token,
        project_id=plan.project_id,
    )
    _await_snapshot(
        api_uri=services["api"],
        coordinator_uri=services["coordinator"],
        oracle_identity=oracle,
        injector_identity=injector,
        project_id=plan.project_id,
        predicate=_mitigated_with_case,
    )
    oracle_job_passed = _execute_job(
        job_name=oracle_job,
        project_id=plan.project_id,
        release_commit=plan.release_commit,
        deployment_id=plan.deployment_id,
        object_name=oracle_object,
        allow_failed_exit=True,
    )
    oracle_uri = f"gs://{bucket}/{oracle_object}"
    oracle_value = _download_gcs(
        uri=oracle_uri,
        destination=output_dir / "S1-oracle.json",
        identity=oracle,
        project_id=plan.project_id,
    )
    if (
        oracle_value.get("project_id"),
        oracle_value.get("release_commit"),
        oracle_value.get("deployment_id"),
    ) != (plan.project_id, plan.release_commit, plan.deployment_id):
        raise ValueError("S1 oracle result belongs to another release")
    raw_assertions = oracle_value.get("assertions")
    if not isinstance(raw_assertions, dict) or set(raw_assertions) != set(S1_ASSERTIONS):
        raise ValueError("S1 oracle assertion set is incomplete")
    assertions = {
        str(name): bool(passed) and oracle_job_passed
        for name, passed in raw_assertions.items()
        if isinstance(name, str) and isinstance(passed, bool)
    }
    extra_refs = oracle_value.get("evidence_refs")
    references = [fault_uri, oracle_uri]
    if isinstance(extra_refs, list):
        references.extend(
            item
            for item in extra_refs
            if isinstance(item, str) and item.startswith(("gs://", "db://"))
        )
    return ScenarioReceipt.create(
        scenario_id="S1",
        mode=EvidenceMode.LIVE_GCP,
        status=EvidenceStatus.PASS if all(assertions.values()) else EvidenceStatus.FAIL,
        release_commit=plan.release_commit,
        project_id=plan.project_id,
        region="europe-west1",
        deployment_id=plan.deployment_id,
        started_at=started_at,
        completed_at=datetime.now(UTC),
        assertions=assertions,
        evidence_refs=tuple(dict.fromkeys(references)),
    )


def run_scripted_scenario(
    *,
    scenario_id: str,
    plan: CloudScenarioPlan,
    terraform_value: dict[str, Any],
    bucket: str,
    output_dir: Path,
) -> ScenarioReceipt:
    if scenario_id not in {"S2", "S3", "S4", "S5", "S6"}:
        raise ValueError("scripted fixture runner supports S2 through S6")
    identities = _output(terraform_value, "scenario_identities")
    jobs = _output(terraform_value, "release_jobs")
    if not isinstance(identities, dict) or not isinstance(jobs, dict):
        raise ValueError("Terraform scenario topology is malformed")
    injector = identities.get("injector")
    oracle = identities.get("oracle")
    injector_job = jobs.get("scenario_injector")
    oracle_job = jobs.get("scenario_oracle")
    if not all(
        isinstance(item, str) and item for item in (injector, oracle, injector_job, oracle_job)
    ):
        raise ValueError("release has no complete scripted scenario topology")
    assert isinstance(oracle, str)
    assert isinstance(injector_job, str)
    assert isinstance(oracle_job, str)
    started_at = datetime.now(UTC)
    suffix = started_at.strftime("%Y%m%dT%H%M%S%fZ").lower()
    run_id = _scenario_run_id(
        deployment_id=plan.deployment_id,
        scenario_id=scenario_id,
        started_at=started_at,
    )
    fixture_object = f"scenarios/{plan.deployment_id}/{scenario_id}/{suffix}-fixture.json"
    oracle_object = f"scenarios/{plan.deployment_id}/{scenario_id}/{suffix}-oracle.json"
    _execute_job(
        job_name=injector_job,
        project_id=plan.project_id,
        release_commit=plan.release_commit,
        deployment_id=plan.deployment_id,
        object_name=fixture_object,
        args_override=f"scenario-inject-{scenario_id.lower()}",
        scenario_run_id=run_id,
    )
    oracle_passed = _execute_job(
        job_name=oracle_job,
        project_id=plan.project_id,
        release_commit=plan.release_commit,
        deployment_id=plan.deployment_id,
        object_name=oracle_object,
        args_override=f"scenario-oracle-{scenario_id.lower()}",
        scenario_run_id=run_id,
        allow_failed_exit=True,
    )
    fixture_uri = f"gs://{bucket}/{fixture_object}"
    oracle_uri = f"gs://{bucket}/{oracle_object}"
    fixture = _download_gcs(
        uri=fixture_uri,
        destination=output_dir / f"{scenario_id}-fixture.json",
        identity=oracle,
        project_id=plan.project_id,
    )
    oracle_value = _download_gcs(
        uri=oracle_uri,
        destination=output_dir / f"{scenario_id}-oracle.json",
        identity=oracle,
        project_id=plan.project_id,
    )
    expected_binding = (plan.project_id, plan.release_commit, plan.deployment_id, run_id)
    for label, value in (("fixture", fixture), ("oracle", oracle_value)):
        binding = (
            value.get("project_id"),
            value.get("release_commit"),
            value.get("deployment_id"),
            value.get("scenario_run_id"),
        )
        if binding != expected_binding:
            raise ValueError(f"{scenario_id} {label} belongs to another release run")
    raw_assertions = oracle_value.get("assertions")
    expected_names = set(SCRIPTED_ASSERTIONS[scenario_id])
    if not isinstance(raw_assertions, dict) or set(raw_assertions) != expected_names:
        raise ValueError(f"{scenario_id} oracle assertion set is incomplete")
    assertions = {
        str(name): bool(passed) and oracle_passed
        for name, passed in raw_assertions.items()
        if isinstance(name, str) and isinstance(passed, bool)
    }
    return ScenarioReceipt.create(
        scenario_id=scenario_id,
        mode=EvidenceMode.SCRIPTED_GCP,
        status=EvidenceStatus.PASS if all(assertions.values()) else EvidenceStatus.FAIL,
        release_commit=plan.release_commit,
        project_id=plan.project_id,
        region="europe-west1",
        deployment_id=plan.deployment_id,
        started_at=started_at,
        completed_at=datetime.now(UTC),
        assertions=assertions,
        evidence_refs=(fixture_uri, oracle_uri),
    )


def apply(plan: CloudScenarioPlan, *, acknowledgement: str | None, remote: str) -> int:
    if acknowledgement != plan.deployment_id:
        raise ValueError("--ack-scenarios must exactly equal --deployment-id")
    commit, _remote_url = verify_release_source(remote=remote)
    if commit != plan.release_commit:
        raise ValueError("checked-out commit differs from the scenario release commit")
    terraform_value = json.loads(Path(plan.terraform_output).read_text(encoding="utf-8"))
    preflight_value = json.loads(Path(plan.preflight_receipt).read_text(encoding="utf-8"))
    if not isinstance(terraform_value, dict):
        raise ValueError("Terraform output is malformed")
    topology = topology_from_terraform_output(terraform_value)
    bucket = validate_preflight(
        preflight_value,
        project_id=plan.project_id,
        release_commit=plan.release_commit,
        deployment_id=plan.deployment_id,
    )
    if topology.canonical_dict() != preflight_value.get("topology"):
        raise ValueError("Terraform topology changed after platform preflight")
    _verify_schedulers(terraform_value, project_id=plan.project_id)
    output_dir = Path(plan.output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    receipts: list[ScenarioReceipt] = []
    if "S1" in plan.scenarios:
        audience = _output(terraform_value, "approval_token_audience")
        if not isinstance(audience, str):
            raise ValueError("Terraform output has no approval token audience")
        if plan.human_identity_token_file is None:
            raise ValueError("S1 human identity token is missing")
        human_token = _human_token(Path(plan.human_identity_token_file), expected_audience=audience)
        receipts.append(
            run_s1(
                plan=plan,
                terraform_value=terraform_value,
                bucket=bucket,
                human_token=human_token,
                output_dir=output_dir,
            )
        )
    for scenario_id in ("S2", "S3", "S4", "S5", "S6"):
        if scenario_id in plan.scenarios:
            receipts.append(
                run_scripted_scenario(
                    scenario_id=scenario_id,
                    plan=plan,
                    terraform_value=terraform_value,
                    bucket=bucket,
                    output_dir=output_dir,
                )
            )
    oracle_identity = _output(terraform_value, "scenario_identities")["oracle"]
    for receipt in receipts:
        local = output_dir / f"{receipt.scenario_id}.json"
        local.write_text(
            json.dumps(receipt.canonical_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        digest = receipt.content_hash.removeprefix("sha256:")
        uri = (
            f"gs://{bucket}/scenarios/{plan.deployment_id}/{receipt.scenario_id}/"
            f"receipts/{digest}.json"
        )
        _run(
            [
                "gcloud",
                "storage",
                "cp",
                str(local),
                uri,
                f"--impersonate-service-account={oracle_identity}",
                f"--project={plan.project_id}",
                "--quiet",
            ]
        )
    return 0 if all(receipt.status is EvidenceStatus.PASS for receipt in receipts) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--terraform-output", required=True, type=Path)
    parser.add_argument("--preflight-receipt", required=True, type=Path)
    parser.add_argument("--human-identity-token-file", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--scenario", action="append", choices=[f"S{i}" for i in range(1, 7)])
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--ack-scenarios")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    output = args.output_dir or (
        ROOT
        / ".solvan"
        / "releases"
        / args.deployment_id
        / "scenario-evidence"
        / datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    )
    try:
        plan = build_plan(
            project_id=args.project,
            release_commit=args.release_commit,
            deployment_id=args.deployment_id,
            terraform_output=args.terraform_output,
            preflight_receipt=args.preflight_receipt,
            human_identity_token_file=args.human_identity_token_file,
            output_dir=output,
            scenarios=tuple(args.scenario or ("S1",)),
            apply=args.apply,
        )
        if not args.apply:
            print(json.dumps(asdict(plan), indent=2, sort_keys=True))
            return 0
        return apply(plan, acknowledgement=args.ack_scenarios, remote=args.remote)
    except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as error:
        print(f"GCP scenario error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
