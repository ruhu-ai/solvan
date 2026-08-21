"""Plan or execute the reproducible Solvan Google Cloud release sequence.

Planning is the default and performs no cloud mutation. Applying requires an
exact dedicated-project acknowledgement, a clean published commit, remote
Terraform state, and a static release tfvars file. The workflow deliberately
stops with schedulers paused and labels all outputs unverified; platform probes
and preflight own promotion to a release candidate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TF_ROOT = ROOT / "infra" / "terraform" / "environments" / "gcp"
PROJECT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
DEPLOYMENT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
RELEASE_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")

IMAGE_NAMES = {
    "api": "api",
    "alert_ingress": "alert-ingress",
    "direct_gcp_reader": "direct-gcp-reader",
    "pilot_qualification_verifier": "pilot-qualification-verifier",
    "coordinator": "coordinator",
    "detector": "detector",
    "actuator": "actuator",
    "evidence_broker": "evidence-broker",
    "verifier": "verifier",
    "payments_good": "payments-good",
    "payments_bad": "payments-bad",
    "console": "console",
    "outbox_publisher": "publisher",
    "memory_promoter": "memory-promoter",
    "antigravity_workspace": "antigravity-workspace",
    "workspace_sandbox": "workspace-sandbox",
    "workspace_adapter": "workspace-adapter",
    "fixture_attester": "fixture-attester",
    "release_admin": "release-admin",
    "github_provider": "github-provider",
    "github_identity_broker": "github-identity-broker",
    "deployment_controller": "deployment-controller",
    "release_verifier": "release-verifier",
    "slack_liaison": "slack-liaison",
    "liaison_maintenance": "liaison-maintenance",
    "trigger_scheduler": "trigger-scheduler",
    "mcp_facade": "mcp-facade",
    "discord_liaison": "discord-liaison",
    "email_liaison": "email-liaison",
    "relay_control": "relay-control",
}
AGENT_KEYS = {
    "incident-supervisor": "incident_supervisor",
    "evidence-agent": "evidence_agent",
    "execution-agent": "execution_agent",
    "infrastructure-agent": "infrastructure_agent",
    "verification-agent": "verification_agent",
    "workspace-agent": "workspace_agent",
}
BOOTSTRAP_TARGETS = (
    'google_project_service.required["artifactregistry.googleapis.com"]',
    'google_project_service.required["binaryauthorization.googleapis.com"]',
    'google_project_service.required["cloudbuild.googleapis.com"]',
    'google_project_service.required["clouddeploy.googleapis.com"]',
    'google_project_service.required["cloudresourcemanager.googleapis.com"]',
    'google_project_service.required["containeranalysis.googleapis.com"]',
    'google_project_service.required["iam.googleapis.com"]',
    'google_project_service.required["serviceusage.googleapis.com"]',
    'google_service_account.workload["build"]',
    "google_artifact_registry_repository.containers",
)
BUILD_IAM_TARGETS = (
    "google_artifact_registry_repository_iam_member.build_writer",
    "google_project_iam_member.build_logs",
    "google_service_account_iam_member.cloud_build_service_agent_token",
    "google_storage_bucket.build_source",
    "google_storage_bucket_iam_member.build_source_reader",
)
BINARY_AUTH_TARGETS = ("google_binary_authorization_policy.release",)


@dataclass(frozen=True, slots=True)
class ReleasePlan:
    schema_version: int
    mutation_mode: str
    project_id: str
    region: str
    environment: str
    deployment_id: str
    release_version: str
    backend_config: str
    base_tfvars: str
    work_dir: str
    remote: str
    calibration_receipt_uri: str | None
    calibration_receipt_hash: str | None
    phases: tuple[str, ...]


class CommandFailure(RuntimeError):
    pass


def validate_staging_configuration(
    *, backend_config: Path, base_tfvars: Path, project_id: str
) -> None:
    """Reject release inputs that could attach staging to dev state or config."""

    backend = backend_config.read_text(encoding="utf-8")
    variables = base_tfvars.read_text(encoding="utf-8")
    staging_prefix = r'^\s*prefix\s*=\s*"solvan/staging(?:/[^"\n]+)?"\s*$'
    if re.search(staging_prefix, backend, re.MULTILINE) is None:
        raise ValueError("release backend prefix must be solvan/staging")
    if re.search(r'^\s*environment\s*=\s*"staging"\s*$', variables, re.MULTILINE) is None:
        raise ValueError("release tfvars environment must be staging")
    project_match = re.search(r'^\s*project_id\s*=\s*"([^"\n]+)"\s*$', variables, re.MULTILINE)
    if project_match is None or project_match.group(1) != project_id:
        raise ValueError("release tfvars project_id must exactly equal --project")
    required_catalog_inputs = {
        "catalog_network_policy_hash": re.compile(r"^sha256:[0-9a-f]{64}$"),
    }
    for name, pattern in required_catalog_inputs.items():
        match = re.search(rf'^\s*{name}\s*=\s*"([^"\n]+)"\s*$', variables, re.MULTILINE)
        if match is None or pattern.fullmatch(match.group(1)) is None:
            raise ValueError(
                f"release tfvars {name} must contain the exact checked-in policy digest"
            )
    expected_policy_hash = (
        "sha256:"
        + hashlib.sha256(
            (ROOT / "specs" / "artifacts" / "catalog-network-policy.v1.json").read_bytes()
        ).hexdigest()
    )
    if expected_policy_hash not in variables:
        raise ValueError("release tfvars catalog_network_policy_hash does not match the repository")
    approvers = re.search(r"approver_principals\s*=\s*\[(.*?)\]", variables, re.DOTALL)
    if approvers is None or re.search(r'"user:[^"\s]+"', approvers.group(1)) is None:
        raise ValueError("release tfvars require at least one individual catalog approver")


def build_plan(
    *,
    project_id: str,
    deployment_id: str,
    release_version: str,
    backend_config: Path,
    base_tfvars: Path,
    work_dir: Path,
    remote: str,
    calibration_receipt_uri: str | None,
    calibration_receipt_hash: str | None,
    apply: bool,
) -> ReleasePlan:
    if PROJECT_PATTERN.fullmatch(project_id) is None:
        raise ValueError("project ID is not canonical")
    if DEPLOYMENT_PATTERN.fullmatch(deployment_id) is None:
        raise ValueError("deployment ID is not canonical")
    if RELEASE_PATTERN.fullmatch(release_version) is None:
        raise ValueError("release version must be semver")
    if not remote or any(character.isspace() for character in remote):
        raise ValueError("git remote name is invalid")
    if (calibration_receipt_uri is None) != (calibration_receipt_hash is None):
        raise ValueError("calibration receipt URI and hash must be supplied together")
    if calibration_receipt_uri is not None and not calibration_receipt_uri.startswith("gs://"):
        raise ValueError("calibration receipt must be a GCS object URI")
    if (
        calibration_receipt_hash is not None
        and re.fullmatch(r"sha256:[0-9a-f]{64}", calibration_receipt_hash) is None
    ):
        raise ValueError("calibration receipt hash must be a lowercase sha256 digest")
    if apply:
        for label, path in (("backend config", backend_config), ("base tfvars", base_tfvars)):
            if not path.is_file():
                raise ValueError(f"{label} does not exist: {path}")
        validate_staging_configuration(
            backend_config=backend_config,
            base_tfvars=base_tfvars,
            project_id=project_id,
        )
    return ReleasePlan(
        schema_version=1,
        mutation_mode="APPLY" if apply else "PLAN_ONLY",
        project_id=project_id,
        region="europe-west1",
        environment="staging",
        deployment_id=deployment_id,
        release_version=release_version,
        backend_config=str(backend_config.resolve()),
        base_tfvars=str(base_tfvars.resolve()),
        work_dir=str(work_dir.resolve()),
        remote=remote,
        calibration_receipt_uri=calibration_receipt_uri,
        calibration_receipt_hash=calibration_receipt_hash,
        phases=(
            "verify_clean_published_commit",
            "initialize_remote_terraform_state",
            "enable_build_services_and_create_repository",
            "create_cloud_build_service_identity_and_exact_iam",
            "build_release_images",
            "resolve_all_images_to_immutable_digests",
            "verify_cloud_build_provenance_and_attestor",
            "enforce_cloud_build_attestations_with_binary_authorization",
            "pause_automated_work_before_any_image_rolls",
            "apply_platform_with_schedulers_paused",
            "deploy_six_agent_runtime_resources",
            "apply_agent_identity_gateway_policies",
            "bind_runtime_resources_revisions_and_principals",
            "execute_private_database_migration",
            "evaluate_catalog_with_cloud_deploy",
            "request_human_catalog_publication_approval",
            "execute_approved_calibration_seed_if_configured",
            "emit_deployed_unverified_receipt",
        ),
    )


def _run(
    arguments: Sequence[str],
    *,
    cwd: Path = ROOT,
    capture: bool = True,
    timeout: int = 3600,
) -> str:
    completed = subprocess.run(
        list(arguments),
        cwd=cwd,
        check=False,
        capture_output=capture,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "no command output").strip()
        raise CommandFailure(f"{arguments[0]} failed ({completed.returncode}): {detail[-2000:]}")
    return completed.stdout if capture else ""


def _run_allowing(arguments: Sequence[str], *, absent_markers: Sequence[str]) -> str | None:
    """Run a command, returning None only when the resource has never existed.

    A missing API on a first deploy is not a failure. A permission error, a
    wrong project, or an unreachable endpoint is, and must not be mistaken for
    an empty result.
    """

    try:
        return _run(arguments)
    except CommandFailure as error:
        detail = str(error).lower()
        if any(marker.lower() in detail for marker in absent_markers):
            return None
        raise


#: A first deploy has no tick to pause, because Cloud Scheduler has never been
#: enabled in the project. Every other listing failure is a real one and must
#: stop the release rather than roll images under schedulers of unknown state.
_SCHEDULER_ABSENT_MARKERS = (
    "cloudscheduler.googleapis.com",
    "has not been used in project",
    "service is not enabled",
    "was not found",
)


def scheduler_pause_targets(listing: object) -> tuple[str, ...]:
    """Name the scheduler jobs that must be paused, newest listing wins.

    A job already `PAUSED` is skipped; anything else — including a job whose
    state the API would not state — is paused, because "not observably stopped"
    is the condition this phase exists to remove.
    """

    if not isinstance(listing, list):
        raise CommandFailure("Cloud Scheduler job listing is not a list")
    targets: list[str] = []
    for entry in listing:
        if not isinstance(entry, dict):
            raise CommandFailure("Cloud Scheduler job listing holds a non-object entry")
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            raise CommandFailure("Cloud Scheduler job listing holds an unnamed job")
        if entry.get("state") == "PAUSED":
            continue
        targets.append(name.rsplit("/", 1)[-1])
    return tuple(dict.fromkeys(targets))


def quiesce_schedulers(*, project_id: str, region: str) -> tuple[str, ...]:
    """Stop every automated tick before the first service image is replaced.

    Terraform pauses the schedulers in the same apply that rolls the new images,
    and a scheduler job reads the URI of the service it calls, so the dependency
    graph necessarily updates the service before the job. On an in-place upgrade
    that leaves a window in which a live tick drives one service revision
    against another across a strict private contract — today, the workspace
    sandbox response, whose `run_kind` both sides require and neither side
    tolerates missing. Such a tick fails closed and parks a case for human
    review, so the hazard is recoverable rather than silent, but it is still
    self-inflicted.

    Pausing first narrows that window by ordering rather than by relaxing the
    contract. It does not close it completely: a pause stops new triggers, and
    a tick already executing runs to its own attempt deadline. What remains is
    bounded by that deadline — at most a few minutes for the longest job —
    rather than by however long the whole platform apply takes, and it is not
    removed until the release observes the coordinator idle rather than assuming
    it. Making either side tolerate an absent `run_kind` would accept a receipt
    that does not state whether it came from an exploratory or an adjudication
    run, which is the exact fence specification 12 §8.2 relies on.
    """

    listed = _run_allowing(
        [
            "gcloud",
            "scheduler",
            "jobs",
            "list",
            f"--project={project_id}",
            f"--location={region}",
            "--format=json",
        ],
        absent_markers=_SCHEDULER_ABSENT_MARKERS,
    )
    if listed is None:
        return ()
    try:
        listing = json.loads(listed or "[]")
    except json.JSONDecodeError as error:
        raise CommandFailure("Cloud Scheduler job listing was not readable JSON") from error
    paused = scheduler_pause_targets(listing)
    for job in paused:
        _run(
            [
                "gcloud",
                "scheduler",
                "jobs",
                "pause",
                job,
                f"--project={project_id}",
                f"--location={region}",
                "--quiet",
            ]
        )
    return paused


def verify_release_source(*, remote: str) -> tuple[str, str]:
    commit = _run(["git", "rev-parse", "HEAD"]).strip()
    if SHA_PATTERN.fullmatch(commit) is None:
        raise CommandFailure("git returned no full release commit")
    if _run(["git", "status", "--porcelain"]).strip():
        raise CommandFailure("release apply requires a clean working tree")
    remotes = set(_run(["git", "remote"]).split())
    if remote not in remotes:
        raise CommandFailure(f"required judging remote is not configured: {remote}")
    remote_url = _run(["git", "remote", "get-url", remote]).strip()
    if not (remote_url.startswith(("https://", "ssh://", "git@")) or remote_url.endswith(".git")):
        raise CommandFailure("judging remote URL is not a publishable Git remote")
    published = {
        line.split()[0] for line in _run(["git", "ls-remote", remote]).splitlines() if line.split()
    }
    if commit not in published:
        raise CommandFailure("exact release commit is not published at the judging remote")
    return commit, remote_url


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(path)


def _dummy_images(project_id: str) -> dict[str, str]:
    digest = "0" * 64
    return {
        key: f"europe-west1-docker.pkg.dev/{project_id}/solvan/{name}@sha256:{digest}"
        for key, name in IMAGE_NAMES.items()
    }


def _terraform(
    operation: str,
    *,
    base_tfvars: Path,
    generated_tfvars: Path,
    extra: Sequence[str] = (),
) -> str:
    return _run(
        [
            "terraform",
            f"-chdir={TF_ROOT}",
            operation,
            "-input=false",
            f"-var-file={base_tfvars}",
            f"-var-file={generated_tfvars}",
            *extra,
        ],
        timeout=3600,
    )


def _build(project_id: str, *, environment: str) -> str:
    # Stage the source in the bucket Terraform granted solvan-build read on.
    # Cloud Build's default bucket is created on first submit and carries no
    # such grant, so the build would upload successfully and then fail to read
    # its own source back.
    staging = f"gs://{project_id}-{environment}-solvan-build-source/source"
    raw = _run(
        [
            "gcloud",
            "builds",
            "submit",
            str(ROOT),
            "--config=cloudbuild.yaml",
            f"--project={project_id}",
            "--region=europe-west1",
            f"--gcs-source-staging-dir={staging}",
            "--substitutions=_REGION=europe-west1,_REPOSITORY=solvan",
            "--format=json",
            "--quiet",
        ],
        timeout=3600,
    )
    value = json.loads(raw)
    build_id = value.get("id") if isinstance(value, dict) else None
    if not isinstance(build_id, str) or not build_id:
        raise CommandFailure("Cloud Build returned no immutable build ID")
    return build_id


def parse_fully_qualified_digest(value: Any, *, expected_repository: str) -> str:
    if not isinstance(value, dict):
        raise ValueError("Artifact Registry response must be an object")
    summary = value.get("image_summary", value.get("imageSummary"))
    if not isinstance(summary, dict):
        summary = value
    digest = summary.get("fully_qualified_digest", summary.get("fullyQualifiedDigest"))
    if not isinstance(digest, str):
        short_digest = summary.get("digest")
        if isinstance(short_digest, str):
            digest = f"{expected_repository}@{short_digest}"
    if (
        not isinstance(digest, str)
        or re.fullmatch(re.escape(expected_repository) + r"@sha256:[0-9a-f]{64}", digest) is None
    ):
        raise ValueError("Artifact Registry returned no matching immutable image digest")
    return digest


def resolve_images(*, project_id: str, build_id: str) -> dict[str, str]:
    images: dict[str, str] = {}
    for key, name in IMAGE_NAMES.items():
        repository = f"europe-west1-docker.pkg.dev/{project_id}/solvan/{name}"
        raw = _run(
            [
                "gcloud",
                "artifacts",
                "docker",
                "images",
                "describe",
                f"{repository}:{build_id}",
                f"--project={project_id}",
                "--format=json",
                "--quiet",
            ]
        )
        images[key] = parse_fully_qualified_digest(json.loads(raw), expected_repository=repository)
    return images


def verify_build_supply_chain(*, project_id: str, build_id: str, images: dict[str, str]) -> None:
    """Refuse unless Google emitted verified provenance and its project attestor."""

    raw = _run(
        [
            "gcloud",
            "builds",
            "describe",
            build_id,
            f"--project={project_id}",
            "--region=europe-west1",
            "--format=json",
        ]
    )
    value = json.loads(raw)
    options = value.get("options") if isinstance(value, dict) else None
    results = value.get("results") if isinstance(value, dict) else None
    built = results.get("images") if isinstance(results, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("status") != "SUCCESS"
        or not isinstance(options, dict)
        or options.get("requestedVerifyOption") != "VERIFIED"
        or not isinstance(built, list)
    ):
        raise CommandFailure("Cloud Build did not return a successful verified-provenance build")
    observed: set[str] = set()
    for item in built:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or not isinstance(item.get("digest"), str)
        ):
            continue
        parent, separator, leaf = item["name"].rpartition("/")
        if not separator:
            continue
        repository = f"{parent}/{leaf.split(':', 1)[0]}"
        observed.add(f"{repository}@{item['digest']}")
    if not set(images.values()).issubset(observed):
        raise CommandFailure("Cloud Build provenance does not cover every release image digest")
    _run(
        [
            "gcloud",
            "container",
            "binauthz",
            "attestors",
            "describe",
            "built-by-cloud-build",
            f"--project={project_id}",
            "--format=json",
        ]
    )


def _terraform_output(path: Path) -> dict[str, Any]:
    raw = _run(["terraform", f"-chdir={TF_ROOT}", "output", "-json"])
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise CommandFailure("Terraform output is malformed")
    _atomic_json(path, value)
    return value


def _output_value(outputs: dict[str, Any], name: str) -> Any:
    item = outputs.get(name)
    if not isinstance(item, dict) or "value" not in item:
        raise CommandFailure(f"Terraform output is missing {name}")
    return item["value"]


def runtime_bindings(receipt: dict[str, Any], *, release_version: str) -> dict[str, Any]:
    if receipt.get("status") != "DEPLOYED_UNVERIFIED":
        raise ValueError("successful Runtime deployment receipt is required")
    plan = receipt.get("plan")
    if not isinstance(plan, dict):
        raise ValueError("Runtime deployment receipt plan is malformed")
    if (
        plan.get("location") != "europe-west1"
        or plan.get("model_location") != "eu"
        or plan.get("model_endpoint") != "https://aiplatform.eu.rep.googleapis.com"
        or plan.get("release_version") != release_version
    ):
        raise ValueError("Runtime deployment receipt has drifted region or model routing")
    targets = plan.get("targets")
    if not isinstance(targets, list):
        raise ValueError("Runtime deployment receipt has an unqualified model")
    target_keys = {
        target.get("agent_key")
        for target in targets
        if isinstance(target, dict) and isinstance(target.get("agent_key"), str)
    }
    if target_keys != set(AGENT_KEYS) or any(
        not isinstance(target, dict) or target.get("model_resource") != "gemini-3.6-flash"
        for target in targets
    ):
        raise ValueError("Runtime deployment receipt has an unqualified model")
    resources = receipt.get("resources")
    if not isinstance(resources, list):
        raise ValueError("Runtime deployment receipt resources are malformed")
    by_key = {
        item.get("agent_key"): item
        for item in resources
        if isinstance(item, dict) and isinstance(item.get("agent_key"), str)
    }
    if set(by_key) != set(AGENT_KEYS):
        raise ValueError("Runtime deployment receipt must contain exactly six agents")
    runtime_resources: dict[str, str] = {}
    principals: dict[str, str] = {}
    for external, internal in AGENT_KEYS.items():
        item = by_key[external]
        resource = item.get("immutable_resource_name")
        principal = item.get("iam_principal")
        if not isinstance(resource, str) or not isinstance(principal, str):
            raise ValueError(f"Runtime receipt is incomplete for {external}")
        runtime_resources[internal] = resource
        principals[external] = principal
    return {
        "agent_runtime_resources": runtime_resources,
        "agent_runtime_revisions": {internal: release_version for internal in AGENT_KEYS.values()},
        "execution_agent_principal": principals["execution-agent"],
        "evidence_agent_principal": principals["evidence-agent"],
        "infrastructure_agent_principal": principals["infrastructure-agent"],
        "verification_agent_principal": principals["verification-agent"],
        "incident_supervisor_agent_principal": principals["incident-supervisor"],
        "workspace_agent_principal": principals["workspace-agent"],
    }


def _deploy_agents(
    *, plan: ReleasePlan, outputs: dict[str, Any], receipt_path: Path
) -> dict[str, Any]:
    gateways = _output_value(outputs, "agent_gateway_resources")
    services = _output_value(outputs, "service_uris")
    runtime_bucket = _output_value(outputs, "runtime_bucket")
    if not isinstance(gateways, dict) or not isinstance(services, dict):
        raise CommandFailure("Terraform gateway or service outputs are malformed")
    _run(
        [
            sys.executable,
            str(ROOT / "tools" / "deploy_agent_platform.py"),
            f"--project={plan.project_id}",
            f"--staging-bucket=gs://{runtime_bucket}",
            f"--release-version={plan.release_version}",
            f"--egress-agent-gateway={gateways['egress']}",
            f"--ingress-agent-gateway={gateways['ingress']}",
            f"--evidence-broker-url={services['evidence']}",
            f"--actuator-url={services['actuator']}",
            f"--verifier-url={services['verifier']}",
            f"--workspace-tool-broker-url={services['coordinator']}",
            f"--environment={plan.environment}",
            f"--receipt={receipt_path}",
            "--apply",
        ],
        timeout=3600,
    )
    value = json.loads(receipt_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise CommandFailure("Runtime deployment receipt is malformed")
    return value


def _configure_iap(*, plan: ReleasePlan, runtime_receipt: Path, receipt_path: Path) -> None:
    _run(
        [
            sys.executable,
            str(ROOT / "tools" / "configure_agent_iap.py"),
            f"--deployment-receipt={runtime_receipt}",
            f"--terraform-output={receipt_path.parent / 'terraform-output-initial.json'}",
            f"--project={plan.project_id}",
            "--region=europe-west1",
            f"--environment={plan.environment}",
            f"--receipt={receipt_path}",
            "--apply",
        ]
    )


def initial_release_variables(plan: ReleasePlan, *, commit: str) -> dict[str, Any]:
    """Build the immutable generated bindings used by every Terraform phase."""

    if SHA_PATTERN.fullmatch(commit) is None:
        raise ValueError("release variables require a full lowercase git commit")
    return {
        "project_id": plan.project_id,
        "environment": plan.environment,
        "release_commit": commit,
        "deployment_id": plan.deployment_id,
        "scheduler_paused": True,
        # This command deploys the isolated fault drill only. Normal
        # dev, staging, and production Terraform applies leave it disabled.
        "fault_drill_enabled": True,
        # Google currently returns server-side code 13 when creating only the
        # inline Model Armor AuthzPolicy. IAP remains enabled, and the release
        # still probes fail-closed in-process sanitizeUserPrompt and
        # sanitizeModelResponse calls before qualification.
        "gateway_model_armor_enabled": False,
        "images": _dummy_images(plan.project_id),
        "calibration_receipt_uri": plan.calibration_receipt_uri,
        "calibration_receipt_hash": plan.calibration_receipt_hash,
    }


def _catalog_rollouts(
    *, project_id: str, region: str, pipeline: str, release: str
) -> list[dict[str, Any]]:
    raw = _run(
        [
            "gcloud",
            "deploy",
            "rollouts",
            "list",
            f"--project={project_id}",
            f"--region={region}",
            f"--delivery-pipeline={pipeline}",
            f"--release={release}",
            "--format=json",
        ]
    )
    value = json.loads(raw)
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise CommandFailure("Cloud Deploy rollout listing is malformed")
    return value


def _wait_catalog_evaluation(
    *, project_id: str, region: str, pipeline: str, release: str, target: str
) -> dict[str, Any]:
    for _attempt in range(120):
        matches = [
            item
            for item in _catalog_rollouts(
                project_id=project_id, region=region, pipeline=pipeline, release=release
            )
            if item.get("targetId") == target
        ]
        if len(matches) != 1:
            raise CommandFailure("Cloud Deploy did not create exactly one evaluation rollout")
        state = matches[0].get("state")
        if state == "SUCCEEDED":
            return matches[0]
        if state in {
            "FAILED",
            "HALTED",
            "CANCELLED",
            "APPROVAL_REJECTED",
            "ROLLOUT_STATE_UNSPECIFIED",
        }:
            raise CommandFailure(f"Cloud Deploy catalog evaluation ended in {state}")
        time.sleep(5)
    raise CommandFailure("Cloud Deploy catalog evaluation timed out")


def start_catalog_delivery(
    *, plan: ReleasePlan, commit: str, outputs: dict[str, Any]
) -> dict[str, Any]:
    delivery = _output_value(outputs, "catalog_delivery")
    if not isinstance(delivery, dict):
        raise CommandFailure("Terraform catalog delivery output is malformed")
    required = (
        "delivery_pipeline",
        "evaluation_target",
        "publication_target",
        "catalog_subject_hash",
        "network_policy_hash",
    )
    if any(not isinstance(delivery.get(key), str) for key in required):
        raise CommandFailure("Terraform catalog delivery output is incomplete")
    pipeline = delivery["delivery_pipeline"]
    evaluation_target = delivery["evaluation_target"]
    publication_target = delivery["publication_target"]
    release = f"catalog-{commit[:12]}-{hashlib.sha256(plan.deployment_id.encode()).hexdigest()[:8]}"
    annotations = {
        "solvan-catalog-subject": delivery["catalog_subject_hash"],
        "solvan-deployment-id": plan.deployment_id,
        "solvan-network-policy": delivery["network_policy_hash"],
        "solvan-release-commit": commit,
    }
    existing = _run_allowing(
        [
            "gcloud",
            "deploy",
            "releases",
            "describe",
            release,
            f"--project={plan.project_id}",
            f"--region={plan.region}",
            f"--delivery-pipeline={pipeline}",
            "--format=json",
        ],
        absent_markers=("not found", "does not exist"),
    )
    if existing is None:
        with tempfile.TemporaryDirectory(prefix="solvan-catalog-release-") as directory:
            source = Path(directory)
            _atomic_json(
                source / "release.json",
                {
                    "schema_version": 1,
                    "catalog_subject_hash": delivery["catalog_subject_hash"],
                },
            )
            _run(
                [
                    "gcloud",
                    "deploy",
                    "releases",
                    "create",
                    release,
                    f"--project={plan.project_id}",
                    f"--region={plan.region}",
                    f"--delivery-pipeline={pipeline}",
                    f"--source={source}",
                    "--annotations="
                    + ",".join(f"{key}={value}" for key, value in sorted(annotations.items())),
                    "--quiet",
                ],
                timeout=1200,
            )
    else:
        value = json.loads(existing)
        if not isinstance(value, dict) or value.get("annotations") != annotations:
            raise CommandFailure("existing Cloud Deploy release has different annotations")

    evaluation = _wait_catalog_evaluation(
        project_id=plan.project_id,
        region=plan.region,
        pipeline=pipeline,
        release=release,
        target=evaluation_target,
    )
    publications = [
        item
        for item in _catalog_rollouts(
            project_id=plan.project_id,
            region=plan.region,
            pipeline=pipeline,
            release=release,
        )
        if item.get("targetId") == publication_target
    ]
    if not publications:
        _run(
            [
                "gcloud",
                "deploy",
                "releases",
                "promote",
                f"--release={release}",
                f"--project={plan.project_id}",
                f"--region={plan.region}",
                f"--delivery-pipeline={pipeline}",
                f"--to-target={publication_target}",
                "--quiet",
            ]
        )
        publications = [
            item
            for item in _catalog_rollouts(
                project_id=plan.project_id,
                region=plan.region,
                pipeline=pipeline,
                release=release,
            )
            if item.get("targetId") == publication_target
        ]
    if len(publications) != 1:
        raise CommandFailure("Cloud Deploy did not create exactly one publication rollout")
    publication = publications[0]
    if publication.get("approvalState") not in {"NEEDS_APPROVAL", "APPROVED"}:
        raise CommandFailure("Cloud Deploy publication rollout is not awaiting valid approval")
    rollout_name = publication.get("name")
    if not isinstance(rollout_name, str):
        raise CommandFailure("Cloud Deploy publication rollout has no name")
    return {
        "delivery_pipeline": pipeline,
        "release": release,
        "evaluation_rollout": evaluation.get("name"),
        "publication_rollout": rollout_name,
        "publication_approval_state": publication.get("approvalState"),
        "catalog_subject_hash": delivery["catalog_subject_hash"],
        "approve_command": (
            f"gcloud deploy rollouts approve {rollout_name.rsplit('/', 1)[-1]} "
            f"--project={plan.project_id} --region={plan.region} "
            f"--delivery-pipeline={pipeline} --release={release}"
        ),
    }


def apply_release(plan: ReleasePlan, *, acknowledgement: str | None) -> dict[str, Any]:
    if acknowledgement != plan.project_id:
        raise ValueError("--ack-dedicated-project must exactly equal --project")
    work_dir = Path(plan.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = work_dir / "deployment-receipt.json"
    started_at = datetime.now(UTC)
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "kind": "SOLVAN_GCP_DEPLOYMENT",
        "status": "FAILED",
        "warning": "Deployment evidence is not a platform-preflight or release pass.",
        "plan": asdict(plan),
        "started_at": started_at.isoformat(),
        "phases_completed": [],
    }
    try:
        commit, remote_url = verify_release_source(remote=plan.remote)
        receipt.update({"release_commit": commit, "remote_url": remote_url})
        receipt["phases_completed"].append("verify_clean_published_commit")

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
        receipt["phases_completed"].append("initialize_remote_terraform_state")

        generated = work_dir / "release.auto.tfvars.json"
        release_vars = initial_release_variables(plan, commit=commit)
        _atomic_json(generated, release_vars)
        _terraform(
            "apply",
            base_tfvars=Path(plan.base_tfvars),
            generated_tfvars=generated,
            extra=("-auto-approve", *(f"-target={item}" for item in BOOTSTRAP_TARGETS)),
        )
        receipt["phases_completed"].append("enable_build_services_and_create_repository")

        _run(
            [
                "gcloud",
                "beta",
                "services",
                "identity",
                "create",
                "--service=cloudbuild.googleapis.com",
                f"--project={plan.project_id}",
                "--quiet",
            ]
        )
        _terraform(
            "apply",
            base_tfvars=Path(plan.base_tfvars),
            generated_tfvars=generated,
            extra=("-auto-approve", *(f"-target={item}" for item in BUILD_IAM_TARGETS)),
        )
        receipt["phases_completed"].append("create_cloud_build_service_identity_and_exact_iam")

        build_id = _build(plan.project_id, environment=plan.environment)
        receipt["build_id"] = build_id
        receipt["phases_completed"].append("build_release_images")
        release_vars["images"] = resolve_images(project_id=plan.project_id, build_id=build_id)
        _atomic_json(generated, release_vars)
        receipt["image_digests"] = release_vars["images"]
        receipt["phases_completed"].append("resolve_all_images_to_immutable_digests")

        verify_build_supply_chain(
            project_id=plan.project_id,
            build_id=build_id,
            images=release_vars["images"],
        )
        receipt["phases_completed"].append("verify_cloud_build_provenance_and_attestor")

        _terraform(
            "apply",
            base_tfvars=Path(plan.base_tfvars),
            generated_tfvars=generated,
            extra=("-auto-approve", *(f"-target={item}" for item in BINARY_AUTH_TARGETS)),
        )
        receipt["phases_completed"].append(
            "enforce_cloud_build_attestations_with_binary_authorization"
        )

        receipt["paused_scheduler_jobs"] = list(
            quiesce_schedulers(project_id=plan.project_id, region=plan.region)
        )
        receipt["phases_completed"].append("pause_automated_work_before_any_image_rolls")

        # The platform apply binds the Vertex AI Reasoning Engine service agent
        # to Model Armor and the runtime bucket. Google creates that agent
        # lazily, and IAM rejects a binding naming a principal that does not
        # exist yet, so the apply fails on an identity the deployment never asks
        # for. Provisioning the aiplatform identity materializes it, the same
        # way the build identity is provisioned above.
        _run(
            [
                "gcloud",
                "beta",
                "services",
                "identity",
                "create",
                "--service=aiplatform.googleapis.com",
                f"--project={plan.project_id}",
                "--quiet",
            ]
        )

        _terraform(
            "apply",
            base_tfvars=Path(plan.base_tfvars),
            generated_tfvars=generated,
            extra=("-auto-approve",),
        )
        first_outputs = _terraform_output(work_dir / "terraform-output-initial.json")
        receipt["phases_completed"].append("apply_platform_with_schedulers_paused")

        runtime_path = work_dir / "agent-runtime-deployment.json"
        runtime_receipt = _deploy_agents(
            plan=plan, outputs=first_outputs, receipt_path=runtime_path
        )
        receipt["phases_completed"].append("deploy_six_agent_runtime_resources")
        _configure_iap(
            plan=plan,
            runtime_receipt=runtime_path,
            receipt_path=work_dir / "agent-iap-policies.json",
        )
        receipt["phases_completed"].append("apply_agent_identity_gateway_policies")

        release_vars.update(runtime_bindings(runtime_receipt, release_version=plan.release_version))
        _atomic_json(generated, release_vars)
        _terraform(
            "apply",
            base_tfvars=Path(plan.base_tfvars),
            generated_tfvars=generated,
            extra=("-auto-approve",),
        )
        final_outputs = _terraform_output(work_dir / "terraform-output.json")
        receipt["phases_completed"].append("bind_runtime_resources_revisions_and_principals")

        jobs = _output_value(final_outputs, "release_jobs")
        if (
            not isinstance(jobs, dict)
            or not isinstance(jobs.get("migration"), str)
            or not isinstance(jobs.get("catalog"), str)
        ):
            raise CommandFailure("Terraform release job output is malformed")
        _run(
            [
                "gcloud",
                "run",
                "jobs",
                "execute",
                jobs["migration"],
                f"--project={plan.project_id}",
                "--region=europe-west1",
                "--wait",
                "--quiet",
            ],
            timeout=1200,
        )
        receipt["phases_completed"].append("execute_private_database_migration")
        catalog_delivery = start_catalog_delivery(plan=plan, commit=commit, outputs=final_outputs)
        receipt["catalog_delivery"] = catalog_delivery
        receipt["phases_completed"].append("evaluate_catalog_with_cloud_deploy")
        receipt["phases_completed"].append("request_human_catalog_publication_approval")
        receipt.update(
            {
                "status": "AWAITING_HUMAN_CATALOG_PUBLICATION_APPROVAL",
                "terraform_output": str(work_dir / "terraform-output.json"),
                "runtime_receipt": str(runtime_path),
                "next_required_gate": catalog_delivery["approve_command"],
            }
        )
    except Exception as exception:
        receipt["error"] = f"{type(exception).__name__}: {exception}"
        raise
    finally:
        receipt["completed_at"] = datetime.now(UTC).isoformat()
        receipt["receipt_sha256"] = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        )
        _atomic_json(receipt_path, receipt)
    return receipt


def resume_after_catalog_approval(
    plan: ReleasePlan, *, acknowledgement: str | None
) -> dict[str, Any]:
    """Finish the same deployment only after Cloud Deploy records approval."""

    if acknowledgement != plan.project_id:
        raise ValueError("--ack-dedicated-project must exactly equal --project")
    receipt_path = Path(plan.work_dir) / "deployment-receipt.json"
    if not receipt_path.is_file():
        raise CommandFailure("the deployment receipt to resume does not exist")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if not isinstance(receipt, dict) or receipt.get("status") != (
        "AWAITING_HUMAN_CATALOG_PUBLICATION_APPROVAL"
    ):
        raise CommandFailure("deployment receipt is not awaiting catalog approval")
    source_commit, _remote_url = verify_release_source(remote=plan.remote)
    if source_commit != receipt.get("release_commit"):
        raise CommandFailure("current commit differs from the deployment awaiting approval")
    delivery = receipt.get("catalog_delivery")
    if not isinstance(delivery, dict):
        raise CommandFailure("deployment receipt has no Cloud Deploy catalog binding")
    pipeline = delivery.get("delivery_pipeline")
    release = delivery.get("release")
    publication_name = delivery.get("publication_rollout")
    if (
        not isinstance(pipeline, str)
        or not isinstance(release, str)
        or not isinstance(publication_name, str)
    ):
        raise CommandFailure("deployment receipt Cloud Deploy binding is malformed")
    publication_id = publication_name.rsplit("/", 1)[-1]
    publication: dict[str, Any] | None = None
    for _attempt in range(240):
        matches = [
            item
            for item in _catalog_rollouts(
                project_id=plan.project_id,
                region=plan.region,
                pipeline=pipeline,
                release=release,
            )
            if isinstance(item.get("name"), str)
            and item["name"].rsplit("/", 1)[-1] == publication_id
        ]
        if len(matches) != 1:
            raise CommandFailure("approved publication rollout is no longer unique")
        publication = matches[0]
        if publication.get("approvalState") != "APPROVED":
            raise CommandFailure("catalog publication has not been approved by Cloud Deploy")
        if publication.get("state") == "SUCCEEDED":
            break
        if publication.get("state") in {
            "FAILED",
            "HALTED",
            "CANCELLED",
            "APPROVAL_REJECTED",
        }:
            raise CommandFailure(
                f"approved catalog publication ended in {publication.get('state')}"
            )
        time.sleep(5)
    else:
        raise CommandFailure("approved catalog publication timed out")
    outputs_path = Path(plan.work_dir) / "terraform-output.json"
    outputs = json.loads(outputs_path.read_text(encoding="utf-8"))
    jobs = _output_value(outputs, "release_jobs")
    if not isinstance(jobs, dict):
        raise CommandFailure("Terraform release job output is malformed")
    receipt.setdefault("phases_completed", []).append("publish_governed_tool_catalog")
    if isinstance(jobs.get("seed"), str):
        _run(
            [
                "gcloud",
                "run",
                "jobs",
                "execute",
                jobs["seed"],
                f"--project={plan.project_id}",
                f"--region={plan.region}",
                "--wait",
                "--quiet",
            ],
            timeout=1200,
        )
        receipt.setdefault("phases_completed", []).append(
            "execute_approved_calibration_seed_if_configured"
        )
    receipt.update(
        {
            "status": "DEPLOYED_UNVERIFIED_SCHEDULERS_PAUSED",
            "next_required_gate": "run platform probes and preflight before unpausing",
            "completed_at": datetime.now(UTC).isoformat(),
        }
    )
    receipt.pop("receipt_sha256", None)
    receipt["receipt_sha256"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    _atomic_json(receipt_path, receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--release-version", default="0.1.0")
    parser.add_argument("--backend-config", required=True, type=Path)
    parser.add_argument("--base-tfvars", required=True, type=Path)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--calibration-receipt-uri")
    parser.add_argument("--calibration-receipt-hash")
    parser.add_argument("--ack-dedicated-project")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--resume-after-catalog-approval", action="store_true")
    args = parser.parse_args()
    work_dir = args.work_dir or ROOT / ".solvan" / "releases" / args.deployment_id
    try:
        plan = build_plan(
            project_id=args.project,
            deployment_id=args.deployment_id,
            release_version=args.release_version,
            backend_config=args.backend_config,
            base_tfvars=args.base_tfvars,
            work_dir=work_dir,
            remote=args.remote,
            calibration_receipt_uri=args.calibration_receipt_uri,
            calibration_receipt_hash=args.calibration_receipt_hash,
            apply=args.apply or args.resume_after_catalog_approval,
        )
        if not args.apply and not args.resume_after_catalog_approval:
            print(json.dumps(asdict(plan), indent=2, sort_keys=True))
            return 0
        receipt = (
            resume_after_catalog_approval(plan, acknowledgement=args.ack_dedicated_project)
            if args.resume_after_catalog_approval
            else apply_release(plan, acknowledgement=args.ack_dedicated_project)
        )
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    except (CommandFailure, OSError, TypeError, ValueError) as exception:
        print(f"release error: {exception}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
