"""Collect live GCP preflight proofs and upload raw evidence to Cloud Storage.

The default is plan-only. Applied probes never infer success from configuration
alone: every required result is derived from a live observation or a dedicated
one-shot oracle job, and every result receives a durable GCS evidence object.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from solvan.agents import SupervisorPlanOutput
from solvan.platform import (
    VertexAgentPlatformClient,
    structured_query_output,
    topology_from_terraform_output,
)
from solvan.platform.antigravity_preflight import ANTIGRAVITY_PROOFS
from solvan.platform.google_rest import authorized_session
from solvan.platform.preflight import _REQUIRED_PROOFS, ReleaseTopology
from tools.antigravity_platform_probes import (
    QUALIFICATION_PROOFS,
    provider_preflight,
    qualification_preflight,
    registry_preflight,
    subprocess_run,
)

ROOT = Path(__file__).resolve().parents[1]
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
DEPLOYMENT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
TRACE_PATTERN = re.compile(r"projects/[^/]+/traces/([0-9a-f]{32})")
AGENT_KEYS = (
    "workspace_agent",
    "evidence_agent",
    "execution_agent",
    "incident_supervisor",
    "infrastructure_agent",
    "verification_agent",
)


@dataclass(frozen=True, slots=True)
class ProbePlan:
    schema_version: int
    mutation_mode: str
    project_id: str
    release_commit: str
    deployment_id: str
    terraform_output: str
    output: str
    required_proofs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProbeResult:
    passed: bool
    evidence_ref: str


def build_plan(
    *,
    project_id: str,
    release_commit: str,
    deployment_id: str,
    terraform_output: Path,
    output: Path,
    apply: bool,
) -> ProbePlan:
    if re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", project_id) is None:
        raise ValueError("project ID is not canonical")
    if COMMIT_PATTERN.fullmatch(release_commit) is None:
        raise ValueError("release commit must be a full lowercase Git SHA")
    if DEPLOYMENT_PATTERN.fullmatch(deployment_id) is None:
        raise ValueError("deployment ID is not canonical")
    if apply and not terraform_output.is_file():
        raise ValueError("Terraform output does not exist")
    required_proofs = _REQUIRED_PROOFS
    if terraform_output.is_file():
        raw = json.loads(terraform_output.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Terraform output must be a JSON object")
        if topology_from_terraform_output(raw).antigravity is not None:
            required_proofs = frozenset(set(required_proofs) | set(ANTIGRAVITY_PROOFS))
    return ProbePlan(
        schema_version=1,
        mutation_mode="APPLY" if apply else "PLAN_ONLY",
        project_id=project_id,
        release_commit=release_commit,
        deployment_id=deployment_id,
        terraform_output=str(terraform_output.resolve()),
        output=str(output.resolve()),
        required_proofs=tuple(sorted(required_proofs)),
    )


def _run(arguments: list[str], *, timeout: int = 600) -> str:
    completed = subprocess.run(
        arguments,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "no output").strip()
        raise RuntimeError(f"{arguments[0]} failed: {detail[-1000:]}")
    return completed.stdout


def _gcloud_json(arguments: list[str], *, timeout: int = 600) -> Any:
    return json.loads(_run(["gcloud", *arguments, "--format=json", "--quiet"], timeout=timeout))


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(path)


def _output(value: dict[str, Any], name: str) -> Any:
    item = value.get(name)
    if not isinstance(item, dict) or "value" not in item:
        raise ValueError(f"Terraform output is missing {name}")
    return item["value"]


def _upload_document(
    *,
    bucket: str,
    deployment_id: str,
    proof_name: str,
    document: dict[str, Any],
    work_dir: Path,
) -> str:
    local = work_dir / f"{proof_name}.json"
    _atomic_json(local, document)
    uri = f"gs://{bucket}/preflight/{deployment_id}/proofs/{proof_name}.json"
    _run(["gcloud", "storage", "cp", str(local), uri, "--quiet"])
    return uri


def _safe_probe(
    proof_name: str,
    probe: Callable[[], tuple[bool, dict[str, Any]]],
    *,
    bucket: str,
    deployment_id: str,
    release_commit: str,
    project_id: str,
    work_dir: Path,
) -> ProbeResult:
    observed_at = datetime.now(UTC)
    try:
        passed, observations = probe()
        error_class = None
    except Exception as exception:
        passed = False
        observations = {}
        error_class = type(exception).__name__
    document = {
        "schema_version": 1,
        "kind": "SOLVAN_PLATFORM_PROOF",
        "proof_name": proof_name,
        "passed": passed,
        "project_id": project_id,
        "release_commit": release_commit,
        "deployment_id": deployment_id,
        "observed_at": observed_at.isoformat(),
        "observations": observations,
        "error_class": error_class,
    }
    uri = _upload_document(
        bucket=bucket,
        deployment_id=deployment_id,
        proof_name=proof_name,
        document=document,
        work_dir=work_dir,
    )
    return ProbeResult(passed, uri)


def _observed_result(
    passed: bool, detail: dict[str, Any]
) -> Callable[[], tuple[bool, dict[str, Any]]]:
    def probe() -> tuple[bool, dict[str, Any]]:
        return passed, detail

    return probe


def _job_probe(
    *,
    job_name: str,
    object_name: str,
    bucket: str,
    project_id: str,
    release_commit: str,
    deployment_id: str,
    work_dir: Path,
) -> dict[str, bool]:
    command = [
        "gcloud",
        "run",
        "jobs",
        "execute",
        job_name,
        f"--project={project_id}",
        "--region=europe-west1",
        "--update-env-vars="
        f"SOLVAN_PROOF_OBJECT_NAME={object_name},"
        f"SOLVAN_RELEASE_COMMIT={release_commit},"
        f"SOLVAN_DEPLOYMENT_ID={deployment_id}",
        "--wait",
        "--format=json",
        "--quiet",
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=600,
    )
    uri = f"gs://{bucket}/{object_name}"
    local = work_dir / f"job-{job_name}.json"
    _run(["gcloud", "storage", "cp", uri, str(local), "--quiet"])
    value = json.loads(local.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or (
        value.get("project_id"),
        value.get("release_commit"),
        value.get("deployment_id"),
    ) != (project_id, release_commit, deployment_id):
        raise RuntimeError("release oracle evidence is not bound to this exact deployment")
    results = value.get("results") if isinstance(value, dict) else None
    if not isinstance(results, dict):
        raise RuntimeError("release oracle job wrote a malformed proof")
    return {
        str(name): bool(passed) and completed.returncode == 0
        for name, passed in results.items()
        if isinstance(name, str) and isinstance(passed, bool)
    }


def _cloud_run_health(topology: ReleaseTopology, project_id: str) -> tuple[bool, dict[str, Any]]:
    listed = _gcloud_json(
        ["run", "services", "list", f"--project={project_id}", "--region=europe-west1"]
    )
    if not isinstance(listed, list):
        raise RuntimeError("Cloud Run service list is malformed")

    def service_value(item: dict[str, Any], key: str) -> Any:
        status = item.get("status")
        return (
            item.get(key) if key in item else status.get(key) if isinstance(status, dict) else None
        )

    by_name = {
        item.get("metadata", {}).get("name"): item
        for item in listed
        if isinstance(item, dict)
        and isinstance(item.get("metadata"), dict)
        and isinstance(item["metadata"].get("name"), str)
    }
    services: dict[str, dict[str, Any]] = {}
    for key, expected_uri in topology.service_uris:
        expected = re.fullmatch(
            r"https://(?P<service>[a-z0-9-]+)-[0-9]+\.europe-west1\.run\.app",
            expected_uri,
        )
        value = by_name.get(expected.group("service")) if expected is not None else None
        if not isinstance(value, dict):
            services[key] = {
                "ready": False,
                "uri_matches": False,
                "latest_revision_ready": False,
            }
            continue
        status = value.get("status")
        conditions = status.get("conditions", []) if isinstance(status, dict) else []
        ready = any(
            isinstance(item, dict)
            and item.get("type") == "Ready"
            and (
                item.get("state") in {"CONDITION_SUCCEEDED", "True"}
                or item.get("status") in {"CONDITION_SUCCEEDED", "True", True}
            )
            for item in conditions
        )
        observed_uri = service_value(value, "url") or service_value(value, "uri")
        latest_ready = service_value(value, "latestReadyRevision") or service_value(
            value, "latestReadyRevisionName"
        )
        latest_created = service_value(value, "latestCreatedRevision") or service_value(
            value, "latestCreatedRevisionName"
        )
        services[key] = {
            "ready": ready,
            # Google may report the stable generated alias here. Match the
            # service by its authoritative resource name and require that the
            # observed endpoint remains a default Cloud Run HTTPS URL.
            "uri_matches": (
                isinstance(observed_uri, str)
                and re.fullmatch(r"https://[a-z0-9-]+(?:\.[a-z0-9-]+)*\.run\.app", observed_uri)
                is not None
            ),
            "latest_revision_ready": bool(latest_ready) and latest_ready == latest_created,
        }
    return all(all(item.values()) for item in services.values()), {"services": services}


def _workspace_sandbox_launcher(
    topology: ReleaseTopology, project_id: str
) -> tuple[bool, dict[str, Any]]:
    uri = dict(topology.service_uris).get("workspace_sandbox")
    if uri is None:
        raise RuntimeError("workspace sandbox is absent from the release topology")
    match = re.fullmatch(r"https://(?P<service>.+)-[0-9]+\.europe-west1\.run\.app", uri)
    if match is None:
        raise RuntimeError("workspace sandbox URI is malformed")
    value = _gcloud_json(
        [
            "beta",
            "run",
            "services",
            "describe",
            match.group("service"),
            f"--project={project_id}",
            "--region=europe-west1",
        ]
    )

    def enabled(item: object) -> bool:
        if isinstance(item, dict):
            return item.get("sandboxLauncher") is True or any(
                enabled(value) for value in item.values()
            )
        if isinstance(item, list):
            return any(enabled(value) for value in item)
        return False

    observed = enabled(value)
    return observed, {"service": match.group("service"), "sandbox_launcher": observed}


def _registry_probe(topology: ReleaseTopology, project_id: str) -> tuple[bool, dict[str, Any]]:
    expected = dict(topology.agent_resources)
    url = f"https://agentregistry.googleapis.com/v1/projects/{project_id}/locations/europe-west1/agents"
    last_value: object = None
    for _attempt in range(18):
        response = authorized_session().get(url, timeout=30)
        response.raise_for_status()
        last_value = response.json()
        serialized = json.dumps(last_value, sort_keys=True)
        discovered = {key: resource in serialized for key, resource in expected.items()}
        if all(discovered.values()):
            return True, {"agents": discovered, "agent_count_expected": 6}
        time.sleep(10)
    serialized = json.dumps(last_value, sort_keys=True)
    discovered = {key: resource in serialized for key, resource in expected.items()}
    return False, {"agents": discovered, "agent_count_expected": 6}


def _runtime_probe(
    *, topology: ReleaseTopology, scope: dict[str, str], deployment_id: str
) -> tuple[bool, dict[str, Any]]:
    agents = dict(topology.agent_resources)
    supervisor = agents["incident_supervisor"]
    runtime_bucket = topology.runtime_bucket
    now = datetime.now(UTC)
    invocation: dict[str, Any] = {
        "schema_version": 1,
        "invocation_id": f"preflight-{deployment_id}",
        "logical_step_key": f"preflight:{deployment_id}:supervisor",
        **scope,
        "incident_id": "inc_00000000000000000000000000",
        "reliability_case_id": None,
        "workflow_version": 1,
        "deadline": (now + timedelta(minutes=5)).isoformat(),
        "budget": {
            "max_runtime_seconds": 300,
            "max_model_calls": 1,
            "max_tool_calls": 0,
            "max_output_bytes": 16384,
            "max_replans": 0,
        },
        "evidence_refs": [],
        "allowed_tool_names": [],
        "input_payload": {
            "objective": "Propose one bounded read-only investigation plan for preflight.",
            "agent_options": ["evidence-agent"],
            "scope_options": ["payments-service"],
        },
        "trace_context": {
            "trace_id": f"{int(now.timestamp() * 1000000):032x}"[-32:],
            "span_id": f"{int(now.timestamp() * 1000):016x}"[-16:],
            "trace_flags": "01",
        },
    }
    query = json.dumps(
        {
            "input": {
                "user_id": scope["environment_id"],
                "message": json.dumps(invocation, sort_keys=True, separators=(",", ":")),
            }
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    client = VertexAgentPlatformClient(
        project=topology.cloud_sql_connection_name.split(":")[0], location="europe-west1"
    )
    output_uri = f"gs://{runtime_bucket}/preflight/{deployment_id}/runtime-query.json"
    started = client.run_query_job(
        name=supervisor, config={"query": query, "output_gcs_uri": output_uri}
    )
    if not started.job_name or not started.output_gcs_uri:
        raise RuntimeError("Agent Runtime returned an incomplete preflight job receipt")
    status = "RUNNING"
    structured = False
    for _attempt in range(36):
        checked = client.check_query_job(name=started.job_name, config={"retrieve_result": True})
        status = checked.status
        if status == "SUCCESS" and checked.result:
            SupervisorPlanOutput.model_validate_json(structured_query_output(checked.result))
            structured = True
            break
        if status == "FAILED":
            break
        time.sleep(10)
    return status == "SUCCESS" and structured, {
        "runtime_resource": supervisor,
        "operation_name": started.job_name,
        "output_ref": started.output_gcs_uri,
        "status": status,
        "typed_output_valid": structured,
        "started_at": now.isoformat(),
    }


def _members(policy: object) -> set[str]:
    if not isinstance(policy, dict):
        return set()
    candidate = policy.get("policy", policy)
    bindings = candidate.get("bindings") if isinstance(candidate, dict) else None
    if not isinstance(bindings, list):
        return set()
    return {
        member
        for binding in bindings
        if isinstance(binding, dict) and binding.get("role") == "roles/iap.egressor"
        for member in binding.get("members", [])
        if isinstance(member, str)
    }


def _iap_matrix(*, topology: ReleaseTopology, project_number: str) -> tuple[bool, dict[str, Any]]:
    principals = dict(topology.agent_principals)
    all_members = set(principals.values())
    expected = {
        "solvan-staging-evidence-broker": {
            principals["evidence_agent"],
            principals["infrastructure_agent"],
        },
        "solvan-staging-actuator": {principals["execution_agent"]},
        "solvan-staging-verifier": {principals["verification_agent"]},
        "solvan-staging-aiplatform": all_members,
        "solvan-staging-aiplatform-mtls": all_members,
        "solvan-staging-aiplatform-rep": all_members,
        "solvan-staging-resource-manager": all_members,
        "solvan-staging-resource-manager-mtls": all_members,
        "solvan-staging-logging": all_members,
        "solvan-staging-telemetry": all_members,
        "solvan-staging-telemetry-mtls": all_members,
    }
    observed: dict[str, list[str]] = {}
    session = authorized_session()
    for endpoint, wanted in expected.items():
        response = session.post(
            "https://iap.googleapis.com/v1/"
            f"projects/{project_number}/locations/europe-west1/iap_web/"
            f"agentRegistry/endpoints/{endpoint}:getIamPolicy",
            json={},
            timeout=30,
        )
        response.raise_for_status()
        observed[endpoint] = sorted(_members(response.json()))
        if set(observed[endpoint]) != wanted:
            return False, {"endpoint_members": observed, "distinct_principals": len(all_members)}
    return len(all_members) == 6, {
        "endpoint_members": observed,
        "distinct_principals": len(all_members),
    }


def _gateway_bypass(topology: ReleaseTopology) -> tuple[bool, dict[str, Any]]:
    service_uris = dict(topology.service_uris)
    targets = {"actuator": (service_uris["actuator"], "/live")}
    if "mcp_facade" in service_uris:
        targets["mcp_facade"] = (service_uris["mcp_facade"], "/mcp")
    statuses: dict[str, int] = {}
    for name, (base_url, path) in targets.items():
        response = httpx.get(f"{base_url}{path}", timeout=30, follow_redirects=False)
        statuses[name] = response.status_code
    return all(value in {401, 403} for value in statuses.values()), {
        "unauthenticated_statuses": statuses
    }


def _otel_trace(
    *, project_id: str, runtime_observations: dict[str, Any]
) -> tuple[bool, dict[str, Any]]:
    started_at = runtime_observations.get("started_at")
    runtime_resource = runtime_observations.get("runtime_resource")
    if not isinstance(started_at, str) or not isinstance(runtime_resource, str):
        raise ValueError("Runtime observations are unavailable for trace correlation")
    engine_id = runtime_resource.rsplit("/", 1)[-1]
    entries = _gcloud_json(
        [
            "logging",
            "read",
            f'timestamp>="{started_at}" AND "{engine_id}"',
            f"--project={project_id}",
            "--limit=200",
        ]
    )
    serialized = json.dumps(entries, sort_keys=True)
    trace_ids = sorted(set(TRACE_PATTERN.findall(serialized)))
    verified: list[str] = []
    session = authorized_session()
    for trace_id in trace_ids[:10]:
        response = session.get(
            f"https://cloudtrace.googleapis.com/v1/projects/{project_id}/traces/{trace_id}",
            timeout=30,
        )
        if response.status_code == 200:
            value = response.json()
            if isinstance(value, dict) and isinstance(value.get("spans"), list):
                verified.append(trace_id)
    return bool(verified), {
        "runtime_engine_id": engine_id,
        "logging_trace_ids": trace_ids,
        "cloud_trace_verified_ids": verified,
    }


def collect(plan: ProbePlan, *, acknowledgement: str | None) -> dict[str, Any]:
    if acknowledgement != plan.deployment_id:
        raise ValueError("--ack-deployment must exactly equal --deployment-id")
    terraform_value = json.loads(Path(plan.terraform_output).read_text(encoding="utf-8"))
    if not isinstance(terraform_value, dict):
        raise ValueError("Terraform output must be a JSON object")
    topology = topology_from_terraform_output(terraform_value)
    if topology.cloud_sql_connection_name.split(":", 1)[0] != plan.project_id:
        raise ValueError("Terraform output belongs to another GCP project")
    scope = _output(terraform_value, "solvan_scope")
    jobs = _output(terraform_value, "release_jobs")
    if not isinstance(scope, dict) or not isinstance(jobs, dict):
        raise ValueError("Terraform scope or release jobs output is malformed")
    work_dir = Path(plan.output).parent / f"{plan.deployment_id}-proofs"
    work_dir.mkdir(parents=True, exist_ok=True)
    bucket = topology.evidence_bucket
    results: dict[str, ProbeResult] = {}

    def capture(name: str, probe: Callable[[], tuple[bool, dict[str, Any]]]) -> None:
        results[name] = _safe_probe(
            name,
            probe,
            bucket=bucket,
            deployment_id=plan.deployment_id,
            release_commit=plan.release_commit,
            project_id=plan.project_id,
            work_dir=work_dir,
        )

    capture("cloud_run_health", lambda: _cloud_run_health(topology, plan.project_id))
    capture(
        "workspace_sandbox_launcher_enabled",
        lambda: _workspace_sandbox_launcher(topology, plan.project_id),
    )
    capture("registry_six_agents_discovered", lambda: _registry_probe(topology, plan.project_id))

    runtime_detail: dict[str, Any] = {}

    def runtime() -> tuple[bool, dict[str, Any]]:
        passed, detail = _runtime_probe(
            topology=topology,
            scope={str(k): str(v) for k, v in scope.items()},
            deployment_id=plan.deployment_id,
        )
        runtime_detail.update(detail)
        return passed, detail

    capture("runtime_query_job_completed", runtime)

    project = _gcloud_json(["projects", "describe", plan.project_id])
    project_number = project.get("projectNumber") if isinstance(project, dict) else None
    if not isinstance(project_number, str):
        raise RuntimeError("GCP project number is unavailable")
    matrix_detail: dict[str, Any] = {}

    def matrix() -> tuple[bool, dict[str, Any]]:
        passed, detail = _iap_matrix(topology=topology, project_number=project_number)
        matrix_detail.update(detail)
        return passed, detail

    capture("identity_matrix_denied_excess_authority", matrix)
    capture(
        "gateway_registered_route_allowed",
        lambda: (
            results["runtime_query_job_completed"].passed
            and results["identity_matrix_denied_excess_authority"].passed,
            {
                "runtime_query_completed": results["runtime_query_job_completed"].passed,
                **matrix_detail,
            },
        ),
    )
    capture("gateway_bypass_denied", lambda: _gateway_bypass(topology))
    capture(
        "otel_trace_correlated",
        lambda: _otel_trace(project_id=plan.project_id, runtime_observations=runtime_detail),
    )

    job_groups = (
        (
            "database_probe",
            ("cloud_sql_61_tables", "cross_scope_database_read_denied"),
        ),
        (
            "memory_probe",
            ("memory_exact_scope_recall", "memory_cross_scope_denied"),
        ),
        (
            "model_armor_probe",
            (
                "model_armor_benign_allowed",
                "model_armor_injection_denied",
                "model_armor_pii_denied",
            ),
        ),
    )
    for job_key, proof_names in job_groups:
        job_name = jobs.get(job_key)
        if not isinstance(job_name, str):
            raise ValueError(f"Terraform output is missing release job {job_key}")
        object_name = f"preflight/{plan.deployment_id}/oracles/{job_key}.json"
        try:
            observed = _job_probe(
                job_name=job_name,
                object_name=object_name,
                bucket=bucket,
                project_id=plan.project_id,
                release_commit=plan.release_commit,
                deployment_id=plan.deployment_id,
                work_dir=work_dir,
            )
        except Exception as exception:
            observed = {}
            failure = {
                "schema_version": 1,
                "kind": "SOLVAN_RELEASE_ORACLE_FAILURE",
                "project_id": plan.project_id,
                "release_commit": plan.release_commit,
                "deployment_id": plan.deployment_id,
                "job_key": job_key,
                "error_class": type(exception).__name__,
                "results": {proof_name: False for proof_name in proof_names},
            }
            failure_path = work_dir / f"{job_key}-failure.json"
            _atomic_json(failure_path, failure)
            _run(
                [
                    "gcloud",
                    "storage",
                    "cp",
                    str(failure_path),
                    f"gs://{bucket}/{object_name}",
                    "--quiet",
                ]
            )
        evidence_ref = f"gs://{bucket}/{object_name}"
        for proof_name in proof_names:
            results[proof_name] = ProbeResult(observed.get(proof_name, False), evidence_ref)

    if topology.antigravity is not None:
        antigravity = topology.antigravity
        try:
            provider_results = provider_preflight(antigravity, run=subprocess_run)
        except Exception as exception:
            provider_results = {
                name: (False, {"error_class": type(exception).__name__})
                for name in ANTIGRAVITY_PROOFS
                if name not in QUALIFICATION_PROOFS | {"antigravity_registry_discovered"}
            }
        for proof_name, (passed, detail) in provider_results.items():
            capture(proof_name, _observed_result(passed, detail))
        capture("antigravity_registry_discovered", lambda: registry_preflight(antigravity))
        try:
            qualification_results = qualification_preflight(
                antigravity,
                bucket=bucket,
                project_id=plan.project_id,
                release_commit=plan.release_commit,
                deployment_id=plan.deployment_id,
                work_dir=work_dir,
                run=subprocess_run,
            )
        except Exception as exception:
            qualification_results = {
                name: (False, {"error_class": type(exception).__name__})
                for name in QUALIFICATION_PROOFS
            }
        for proof_name, (passed, detail) in qualification_results.items():
            capture(proof_name, _observed_result(passed, detail))

    expected_proofs = set(plan.required_proofs)
    if set(results) != expected_proofs:
        raise RuntimeError("probe implementation did not produce the exact required proof set")
    manifest = {
        "schema_version": 1,
        "project_id": plan.project_id,
        "release_commit": plan.release_commit,
        "deployment_id": plan.deployment_id,
        "proofs": {
            name: {"passed": result.passed, "evidence_ref": result.evidence_ref}
            for name, result in sorted(results.items())
        },
    }
    _atomic_json(Path(plan.output), manifest)
    return manifest


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
            project_id=args.project,
            release_commit=args.release_commit,
            deployment_id=args.deployment_id,
            terraform_output=args.terraform_output,
            output=args.output,
            apply=args.apply,
        )
        if not args.apply:
            print(json.dumps(asdict(plan), indent=2, sort_keys=True))
            return 0
        manifest = collect(plan, acknowledgement=args.ack_deployment)
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0 if all(item["passed"] for item in manifest["proofs"].values()) else 1
    except (OSError, RuntimeError, TypeError, ValueError) as exception:
        print(f"platform probe error: {exception}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
