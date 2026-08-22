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
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
TF_ROOT = ROOT / "infra" / "terraform" / "environments" / "gcp"
PROJECT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
DEPLOYMENT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
RELEASE_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
BUILD_ID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

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
    "google_project_iam_member.release_build_approver",
    "google_cloudbuild_trigger.release_images",
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
            "create_managed_cloud_build_trigger_identity_and_exact_iam",
            "accept_managed_cloud_build",
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
            "publish_governed_tool_catalog",
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


def _canonical_sha256(value: object) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )


def _write_release_receipt(path: Path, receipt: dict[str, Any]) -> None:
    """Atomically persist one self-hashed release checkpoint."""

    receipt.pop("receipt_sha256", None)
    receipt["receipt_sha256"] = _canonical_sha256(receipt)
    _atomic_json(path, receipt)


def _complete_release_phase(
    *,
    receipt: dict[str, Any],
    receipt_path: Path,
    phase: str,
    updates: dict[str, Any] | None = None,
) -> None:
    """Commit a durable, ordered checkpoint immediately after one phase."""

    plan = receipt.get("plan")
    declared = plan.get("phases") if isinstance(plan, dict) else None
    completed = receipt.get("phases_completed")
    if not isinstance(declared, list) or phase not in declared:
        raise CommandFailure(f"release phase is not declared by the bound plan: {phase}")
    if not isinstance(completed, list) or any(not isinstance(item, str) for item in completed):
        raise CommandFailure("deployment receipt phase history is malformed")
    phase_index = declared.index(phase)
    if phase_index > 0 and declared[phase_index - 1] not in completed:
        raise CommandFailure(f"release phase completed out of order: {phase}")
    if phase not in completed:
        completed.append(phase)
    if updates:
        receipt.update(updates)
    receipt.update(
        {
            "status": "IN_PROGRESS",
            "updated_at": datetime.now(UTC).isoformat(),
        }
    )
    receipt.pop("error", None)
    _write_release_receipt(receipt_path, receipt)


def _read_json_object(path: Path, *, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise CommandFailure(f"resume requires the persisted {label}: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise CommandFailure(f"persisted {label} is not readable JSON") from error
    if not isinstance(value, dict):
        raise CommandFailure(f"persisted {label} is not an object")
    return value


def _new_release_receipt(plan: ReleasePlan) -> dict[str, Any]:
    plan_value = json.loads(json.dumps(asdict(plan)))
    return {
        "schema_version": 2,
        "kind": "SOLVAN_GCP_DEPLOYMENT",
        "status": "IN_PROGRESS",
        "warning": "Deployment evidence is not a platform-preflight or release pass.",
        "plan": plan_value,
        "plan_sha256": _canonical_sha256(plan_value),
        "started_at": datetime.now(UTC).isoformat(),
        "updated_at": datetime.now(UTC).isoformat(),
        "attempts": 1,
        "phases_completed": [],
    }


def _resume_release_receipt(path: Path, *, plan: ReleasePlan) -> dict[str, Any]:
    receipt = _read_json_object(path, label="deployment receipt")
    if receipt.get("schema_version") != 2 or receipt.get("kind") != "SOLVAN_GCP_DEPLOYMENT":
        raise CommandFailure("deployment receipt is not resumable schema version 2")
    plan_value = json.loads(json.dumps(asdict(plan)))
    if receipt.get("plan") != plan_value or receipt.get("plan_sha256") != _canonical_sha256(
        plan_value
    ):
        raise CommandFailure("current release plan differs from the interrupted deployment")
    if receipt.get("status") not in {"FAILED", "INTERRUPTED", "AWAITING_MANAGED_BUILD"}:
        raise CommandFailure("deployment receipt is not at a resumable boundary")
    completed = receipt.get("phases_completed")
    if not isinstance(completed, list) or any(not isinstance(item, str) for item in completed):
        raise CommandFailure("deployment receipt phase history is malformed")
    declared = list(plan.phases)
    if completed != declared[: len(completed)]:
        raise CommandFailure("deployment receipt phase history is not an exact ordered prefix")
    if "request_human_catalog_publication_approval" in completed:
        raise CommandFailure("catalog-gated deployment must use --resume-after-catalog-approval")
    stored_digest = receipt.pop("receipt_sha256", None)
    if stored_digest != _canonical_sha256(receipt):
        raise CommandFailure("deployment receipt digest does not match its contents")
    receipt["receipt_sha256"] = stored_digest
    receipt.update(
        {
            "status": "IN_PROGRESS",
            "updated_at": datetime.now(UTC).isoformat(),
            "attempts": int(receipt.get("attempts", 0)) + 1,
        }
    )
    receipt.pop("error", None)
    return receipt


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


def describe_managed_build_trigger(
    *, project_id: str, region: str, expected_repository_uri: str
) -> dict[str, str]:
    """Return the exact approval-gated trigger only after its controls match."""

    trigger_name = "solvan-staging-release-images"
    raw = _run(
        [
            "gcloud",
            "builds",
            "triggers",
            "describe",
            trigger_name,
            f"--project={project_id}",
            f"--region={region}",
            "--format=json",
            "--quiet",
        ]
    )
    value = json.loads(raw)
    approval = value.get("approvalConfig") if isinstance(value, dict) else None
    source = value.get("sourceToBuild") if isinstance(value, dict) else None
    build_file = value.get("gitFileSource") if isinstance(value, dict) else None
    substitutions = value.get("substitutions") if isinstance(value, dict) else None
    trigger_id = value.get("id") if isinstance(value, dict) else None
    expected_service_account = (
        f"projects/{project_id}/serviceAccounts/solvan-build@{project_id}.iam.gserviceaccount.com"
    )
    if (
        not isinstance(trigger_id, str)
        or BUILD_ID_PATTERN.fullmatch(trigger_id) is None
        or value.get("name") != trigger_name
        or value.get("serviceAccount") != expected_service_account
        or not isinstance(approval, dict)
        or approval.get("approvalRequired") is not True
        or not isinstance(source, dict)
        or source.get("uri") != expected_repository_uri
        or source.get("ref") != "refs/heads/main"
        or source.get("repoType") != "GITHUB"
        or not isinstance(build_file, dict)
        or build_file.get("path") != "cloudbuild.yaml"
        or build_file.get("uri") != expected_repository_uri
        or build_file.get("revision") != "refs/heads/main"
        or build_file.get("repoType") != "GITHUB"
        or not isinstance(substitutions, dict)
        or substitutions.get("_REGION") != region
        or substitutions.get("_REPOSITORY") != "solvan"
        or substitutions.get("_RELEASE_COMMIT") != "UNCONFIGURED"
    ):
        raise CommandFailure("managed Cloud Build trigger does not match the release contract")
    return {
        "trigger_id": trigger_id,
        "trigger_name": trigger_name,
        "repository_uri": expected_repository_uri,
        "service_account": expected_service_account,
    }


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


def verify_build_supply_chain(
    *,
    project_id: str,
    build_id: str,
    expected_commit: str,
    expected_trigger_id: str,
    expected_service_account: str,
    images: dict[str, str],
) -> None:
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
    substitutions = value.get("substitutions") if isinstance(value, dict) else None
    approval = value.get("approval") if isinstance(value, dict) else None
    approval_result = approval.get("result") if isinstance(approval, dict) else None
    provenance = value.get("sourceProvenance") if isinstance(value, dict) else None
    repo_source = provenance.get("resolvedRepoSource") if isinstance(provenance, dict) else None
    git_source = provenance.get("resolvedGitSource") if isinstance(provenance, dict) else None
    connected_source = (
        provenance.get("resolvedConnectedRepository") if isinstance(provenance, dict) else None
    )
    resolved_commits = {
        item
        for item in (
            repo_source.get("commitSha") if isinstance(repo_source, dict) else None,
            git_source.get("revision") if isinstance(git_source, dict) else None,
            connected_source.get("revision") if isinstance(connected_source, dict) else None,
        )
        if isinstance(item, str)
    }
    results = value.get("results") if isinstance(value, dict) else None
    built = results.get("images") if isinstance(results, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("status") != "SUCCESS"
        or not isinstance(options, dict)
        or options.get("requestedVerifyOption") != "VERIFIED"
        or not isinstance(substitutions, dict)
        or substitutions.get("_RELEASE_COMMIT") != expected_commit
        or value.get("buildTriggerId") != expected_trigger_id
        or value.get("serviceAccount") != expected_service_account
        or not isinstance(approval, dict)
        or approval.get("state") != "APPROVED"
        or not isinstance(approval_result, dict)
        or approval_result.get("decision") != "APPROVED"
        or resolved_commits != {expected_commit}
        or not isinstance(built, list)
    ):
        raise CommandFailure(
            "Cloud Build did not return a successful commit-bound verified-provenance build"
        )
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
    *,
    plan: ReleasePlan,
    commit: str,
    outputs: dict[str, Any],
    receipt_path: Path,
    resume: bool = False,
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
            f"--deployment-id={plan.deployment_id}",
            f"--release-commit={commit}",
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
            *(["--resume"] if resume else []),
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
    # Cloud Deploy's automatic rollout IDs have the form
    # ``<release>-to-<target>-0001`` and resource IDs are limited to 63
    # characters. Keep the immutable release ID concise enough for both
    # ordered targets, and refuse before mutation if a configured target ever
    # exceeds that bound.
    release = f"cat-{commit[:10]}-{hashlib.sha256(plan.deployment_id.encode()).hexdigest()[:5]}"
    for target in (evaluation_target, publication_target):
        automatic_rollout_id = f"{release}-to-{target}-0001"
        if len(automatic_rollout_id) > 63:
            raise CommandFailure(
                "Cloud Deploy automatic rollout ID would exceed the 63-character limit: "
                f"{automatic_rollout_id}"
            )
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
            # Cloud Deploy requires a Skaffold configuration for every release,
            # including custom targets whose tasks live in the CustomTargetType.
            # Google's custom-target quickstart specifies this minimal file.
            (source / "skaffold.yaml").write_text(
                "apiVersion: skaffold/v4beta7\nkind: Config\n",
                encoding="utf-8",
            )
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
                    "--enable-initial-rollout",
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


def apply_release(
    plan: ReleasePlan,
    *,
    acknowledgement: str | None,
    managed_build_id: str | None,
    resume: bool,
) -> dict[str, Any]:
    """Advance an exact release from its last durable phase checkpoint.

    Image construction is intentionally outside this mutation runner. A new
    release first provisions the dedicated managed-build boundary and returns
    ``AWAITING_MANAGED_BUILD``. Only a later exact resume may accept the Cloud
    Build ID, verify its commit binding and provenance, and begin deployment.
    """

    if plan.mutation_mode != "APPLY":
        raise ValueError("release mutation requires an APPLY plan")
    if acknowledgement != plan.project_id:
        raise ValueError("--ack-dedicated-project must exactly equal --project")
    if managed_build_id is not None and BUILD_ID_PATTERN.fullmatch(managed_build_id) is None:
        raise ValueError("--managed-build-id must be a canonical Cloud Build UUID")
    work_dir = Path(plan.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = work_dir / "deployment-receipt.json"
    if resume:
        receipt = _resume_release_receipt(receipt_path, plan=plan)
    else:
        if receipt_path.exists():
            raise CommandFailure(
                "deployment receipt already exists; use --resume or a new deployment ID"
            )
        receipt = _new_release_receipt(plan)
    _write_release_receipt(receipt_path, receipt)
    completed = set(cast(list[str], receipt["phases_completed"]))
    generated = work_dir / "release.auto.tfvars.json"
    initial_outputs_path = work_dir / "terraform-output-initial.json"
    final_outputs_path = work_dir / "terraform-output.json"
    runtime_path = work_dir / "agent-runtime-deployment.json"

    try:
        commit, remote_url = verify_release_source(remote=plan.remote)
        if "verify_clean_published_commit" in completed:
            if commit != receipt.get("release_commit") or remote_url != receipt.get("remote_url"):
                raise CommandFailure("published release source differs from the checkpoint")
        else:
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="verify_clean_published_commit",
                updates={"release_commit": commit, "remote_url": remote_url},
            )
            completed.add("verify_clean_published_commit")

        # Init is safe to repeat and re-establishes the exact remote backend
        # before any mutable cloud state is inspected or advanced.
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
        if "initialize_remote_terraform_state" not in completed:
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="initialize_remote_terraform_state",
            )
            completed.add("initialize_remote_terraform_state")

        if resume:
            release_vars = _read_json_object(generated, label="generated Terraform variables")
            if release_vars.get("release_commit") != commit:
                raise CommandFailure("generated Terraform variables differ from the release commit")
        else:
            release_vars = initial_release_variables(plan, commit=commit)
            _atomic_json(generated, release_vars)

        if "enable_build_services_and_create_repository" not in completed:
            _terraform(
                "apply",
                base_tfvars=Path(plan.base_tfvars),
                generated_tfvars=generated,
                extra=("-auto-approve", *(f"-target={item}" for item in BOOTSTRAP_TARGETS)),
            )
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="enable_build_services_and_create_repository",
            )
            completed.add("enable_build_services_and_create_repository")

        if "create_managed_cloud_build_trigger_identity_and_exact_iam" not in completed:
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
            managed_trigger = describe_managed_build_trigger(
                project_id=plan.project_id,
                region=plan.region,
                expected_repository_uri=remote_url,
            )
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="create_managed_cloud_build_trigger_identity_and_exact_iam",
                updates={"managed_build_trigger": managed_trigger},
            )
            completed.add("create_managed_cloud_build_trigger_identity_and_exact_iam")
        else:
            managed_trigger = describe_managed_build_trigger(
                project_id=plan.project_id,
                region=plan.region,
                expected_repository_uri=remote_url,
            )
            if managed_trigger != receipt.get("managed_build_trigger"):
                raise CommandFailure("managed Cloud Build trigger differs from its checkpoint")

        if "accept_managed_cloud_build" in completed:
            build_id = receipt.get("build_id")
            if not isinstance(build_id, str):
                raise CommandFailure("managed build checkpoint has no immutable build ID")
            if managed_build_id is not None and managed_build_id != build_id:
                raise CommandFailure("resume supplied a different managed Cloud Build ID")
        else:
            if managed_build_id is None:
                receipt.update(
                    {
                        "status": "AWAITING_MANAGED_BUILD",
                        "updated_at": datetime.now(UTC).isoformat(),
                        "next_required_gate": (
                            "gcloud builds triggers run "
                            + managed_trigger["trigger_name"]
                            + f" --project={plan.project_id} --region={plan.region}"
                            + f" --sha={commit} --substitutions=_RELEASE_COMMIT={commit}; "
                            + "then approve that exact pending build"
                        ),
                    }
                )
                _write_release_receipt(receipt_path, receipt)
                return receipt
            build_id = managed_build_id
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="accept_managed_cloud_build",
                updates={"build_id": build_id},
            )
            completed.add("accept_managed_cloud_build")

        if "resolve_all_images_to_immutable_digests" in completed:
            images = receipt.get("image_digests")
            if not isinstance(images, dict) or set(images) != set(IMAGE_NAMES):
                raise CommandFailure("image digest checkpoint is incomplete")
            release_vars["images"] = images
        else:
            images = resolve_images(project_id=plan.project_id, build_id=build_id)
            release_vars["images"] = images
            _atomic_json(generated, release_vars)
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="resolve_all_images_to_immutable_digests",
                updates={"image_digests": images},
            )
            completed.add("resolve_all_images_to_immutable_digests")

        # Provenance is mutable provider observation, so every resume rechecks
        # it even after the immutable result was checkpointed.
        verify_build_supply_chain(
            project_id=plan.project_id,
            build_id=build_id,
            expected_commit=commit,
            expected_trigger_id=managed_trigger["trigger_id"],
            expected_service_account=managed_trigger["service_account"],
            images=cast(dict[str, str], release_vars["images"]),
        )
        if "verify_cloud_build_provenance_and_attestor" not in completed:
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="verify_cloud_build_provenance_and_attestor",
            )
            completed.add("verify_cloud_build_provenance_and_attestor")

        if "enforce_cloud_build_attestations_with_binary_authorization" not in completed:
            _terraform(
                "apply",
                base_tfvars=Path(plan.base_tfvars),
                generated_tfvars=generated,
                extra=("-auto-approve", *(f"-target={item}" for item in BINARY_AUTH_TARGETS)),
            )
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="enforce_cloud_build_attestations_with_binary_authorization",
            )
            completed.add("enforce_cloud_build_attestations_with_binary_authorization")

        # Always re-observe and quiesce before any resume advances deployment.
        paused = list(quiesce_schedulers(project_id=plan.project_id, region=plan.region))
        if "pause_automated_work_before_any_image_rolls" not in completed:
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="pause_automated_work_before_any_image_rolls",
                updates={"paused_scheduler_jobs": paused},
            )
            completed.add("pause_automated_work_before_any_image_rolls")

        if "apply_platform_with_schedulers_paused" in completed:
            first_outputs = _read_json_object(
                initial_outputs_path, label="initial Terraform output"
            )
        else:
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
            first_outputs = _terraform_output(initial_outputs_path)
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="apply_platform_with_schedulers_paused",
                updates={"initial_terraform_output_sha256": _canonical_sha256(first_outputs)},
            )
            completed.add("apply_platform_with_schedulers_paused")
        if receipt.get("initial_terraform_output_sha256") != _canonical_sha256(first_outputs):
            raise CommandFailure("initial Terraform output differs from its checkpoint")

        if "deploy_six_agent_runtime_resources" in completed:
            runtime_receipt = _read_json_object(runtime_path, label="Agent Runtime receipt")
        else:
            runtime_receipt = _deploy_agents(
                plan=plan,
                commit=commit,
                outputs=first_outputs,
                receipt_path=runtime_path,
                resume=resume and runtime_path.exists(),
            )
            runtime_bindings(runtime_receipt, release_version=plan.release_version)
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="deploy_six_agent_runtime_resources",
                updates={"runtime_receipt_sha256": _canonical_sha256(runtime_receipt)},
            )
            completed.add("deploy_six_agent_runtime_resources")
        if receipt.get("runtime_receipt_sha256") != _canonical_sha256(runtime_receipt):
            raise CommandFailure("Agent Runtime receipt differs from its checkpoint")

        if "apply_agent_identity_gateway_policies" not in completed:
            _configure_iap(
                plan=plan,
                runtime_receipt=runtime_path,
                receipt_path=work_dir / "agent-iap-policies.json",
            )
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="apply_agent_identity_gateway_policies",
            )
            completed.add("apply_agent_identity_gateway_policies")

        release_vars.update(runtime_bindings(runtime_receipt, release_version=plan.release_version))
        _atomic_json(generated, release_vars)
        if "bind_runtime_resources_revisions_and_principals" in completed:
            final_outputs = _read_json_object(final_outputs_path, label="final Terraform output")
        else:
            _terraform(
                "apply",
                base_tfvars=Path(plan.base_tfvars),
                generated_tfvars=generated,
                extra=("-auto-approve",),
            )
            final_outputs = _terraform_output(final_outputs_path)
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="bind_runtime_resources_revisions_and_principals",
                updates={"terraform_output_sha256": _canonical_sha256(final_outputs)},
            )
            completed.add("bind_runtime_resources_revisions_and_principals")
        if receipt.get("terraform_output_sha256") != _canonical_sha256(final_outputs):
            raise CommandFailure("final Terraform output differs from its checkpoint")

        jobs = _output_value(final_outputs, "release_jobs")
        if (
            not isinstance(jobs, dict)
            or not isinstance(jobs.get("migration"), str)
            or not isinstance(jobs.get("catalog"), str)
        ):
            raise CommandFailure("Terraform release job output is malformed")
        if "execute_private_database_migration" not in completed:
            _run(
                [
                    "gcloud",
                    "run",
                    "jobs",
                    "execute",
                    jobs["migration"],
                    f"--project={plan.project_id}",
                    f"--region={plan.region}",
                    "--wait",
                    "--quiet",
                ],
                timeout=1200,
            )
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="execute_private_database_migration",
            )
            completed.add("execute_private_database_migration")

        if "evaluate_catalog_with_cloud_deploy" in completed:
            catalog_delivery = receipt.get("catalog_delivery")
            if not isinstance(catalog_delivery, dict):
                raise CommandFailure("catalog delivery checkpoint is malformed")
        else:
            catalog_delivery = start_catalog_delivery(
                plan=plan, commit=commit, outputs=final_outputs
            )
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="evaluate_catalog_with_cloud_deploy",
                updates={"catalog_delivery": catalog_delivery},
            )
            completed.add("evaluate_catalog_with_cloud_deploy")
        if "request_human_catalog_publication_approval" not in completed:
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="request_human_catalog_publication_approval",
            )
        receipt.update(
            {
                "status": "AWAITING_HUMAN_CATALOG_PUBLICATION_APPROVAL",
                "terraform_output": str(final_outputs_path),
                "runtime_receipt": str(runtime_path),
                "next_required_gate": catalog_delivery["approve_command"],
                "updated_at": datetime.now(UTC).isoformat(),
            }
        )
        _write_release_receipt(receipt_path, receipt)
        return receipt
    except KeyboardInterrupt as exception:
        receipt.update(
            {
                "status": "INTERRUPTED",
                "error": f"{type(exception).__name__}: operator interrupted release",
                "updated_at": datetime.now(UTC).isoformat(),
            }
        )
        _write_release_receipt(receipt_path, receipt)
        raise
    except Exception as exception:
        receipt.update(
            {
                "status": "FAILED",
                "error": f"{type(exception).__name__}: {exception}",
                "updated_at": datetime.now(UTC).isoformat(),
            }
        )
        _write_release_receipt(receipt_path, receipt)
        raise


def resume_after_catalog_approval(
    plan: ReleasePlan, *, acknowledgement: str | None
) -> dict[str, Any]:
    """Finish the exact checkpointed deployment after Cloud Deploy approval."""

    if plan.mutation_mode != "APPLY":
        raise ValueError("release mutation requires an APPLY plan")
    if acknowledgement != plan.project_id:
        raise ValueError("--ack-dedicated-project must exactly equal --project")
    receipt_path = Path(plan.work_dir) / "deployment-receipt.json"
    receipt = _read_json_object(receipt_path, label="deployment receipt")
    stored_digest = receipt.pop("receipt_sha256", None)
    if stored_digest != _canonical_sha256(receipt):
        raise CommandFailure("deployment receipt digest does not match its contents")
    plan_value = json.loads(json.dumps(asdict(plan)))
    if (
        receipt.get("schema_version") != 2
        or receipt.get("kind") != "SOLVAN_GCP_DEPLOYMENT"
        or receipt.get("plan") != plan_value
        or receipt.get("plan_sha256") != _canonical_sha256(plan_value)
        or receipt.get("status")
        not in {
            "AWAITING_HUMAN_CATALOG_PUBLICATION_APPROVAL",
            "FAILED",
            "INTERRUPTED",
        }
    ):
        raise CommandFailure("deployment receipt is not an exact catalog-gated release")
    completed_value = receipt.get("phases_completed")
    if not isinstance(completed_value, list) or any(
        not isinstance(item, str) for item in completed_value
    ):
        raise CommandFailure("deployment receipt phase history is malformed")
    completed = cast(list[str], completed_value)
    declared = list(plan.phases)
    if completed != declared[: len(completed)] or (
        "request_human_catalog_publication_approval" not in completed
    ):
        raise CommandFailure("deployment is not at or beyond its catalog approval gate")
    receipt["receipt_sha256"] = stored_digest
    receipt.update(
        {
            "status": "IN_PROGRESS",
            "updated_at": datetime.now(UTC).isoformat(),
            "attempts": int(receipt.get("attempts", 0)) + 1,
        }
    )
    receipt.pop("error", None)
    _write_release_receipt(receipt_path, receipt)

    try:
        source_commit, remote_url = verify_release_source(remote=plan.remote)
        if source_commit != receipt.get("release_commit") or remote_url != receipt.get(
            "remote_url"
        ):
            raise CommandFailure("published source differs from the catalog-gated release")
        paused = list(quiesce_schedulers(project_id=plan.project_id, region=plan.region))
        receipt["paused_scheduler_jobs"] = paused

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
        if "publish_governed_tool_catalog" not in completed:
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="publish_governed_tool_catalog",
                updates={"catalog_publication": publication},
            )

        outputs_path = Path(plan.work_dir) / "terraform-output.json"
        outputs = _read_json_object(outputs_path, label="final Terraform output")
        if receipt.get("terraform_output_sha256") != _canonical_sha256(outputs):
            raise CommandFailure("final Terraform output differs from its checkpoint")
        jobs = _output_value(outputs, "release_jobs")
        if not isinstance(jobs, dict):
            raise CommandFailure("Terraform release job output is malformed")
        if "execute_approved_calibration_seed_if_configured" not in completed:
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
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="execute_approved_calibration_seed_if_configured",
            )
        if "emit_deployed_unverified_receipt" not in completed:
            _complete_release_phase(
                receipt=receipt,
                receipt_path=receipt_path,
                phase="emit_deployed_unverified_receipt",
            )
        receipt.update(
            {
                "status": "DEPLOYED_UNVERIFIED_SCHEDULERS_PAUSED",
                "next_required_gate": "run platform probes and preflight before unpausing",
                "completed_at": datetime.now(UTC).isoformat(),
                "updated_at": datetime.now(UTC).isoformat(),
            }
        )
        _write_release_receipt(receipt_path, receipt)
        return receipt
    except KeyboardInterrupt as exception:
        receipt.update(
            {
                "status": "INTERRUPTED",
                "error": f"{type(exception).__name__}: operator interrupted release",
                "updated_at": datetime.now(UTC).isoformat(),
            }
        )
        _write_release_receipt(receipt_path, receipt)
        raise
    except Exception as exception:
        receipt.update(
            {
                "status": "FAILED",
                "error": f"{type(exception).__name__}: {exception}",
                "updated_at": datetime.now(UTC).isoformat(),
            }
        )
        _write_release_receipt(receipt_path, receipt)
        raise


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
    parser.add_argument("--managed-build-id")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--resume-after-catalog-approval", action="store_true")
    args = parser.parse_args()
    work_dir = args.work_dir or ROOT / ".solvan" / "releases" / args.deployment_id
    try:
        if sum((args.apply, args.resume, args.resume_after_catalog_approval)) > 1:
            raise ValueError(
                "choose exactly one of --apply, --resume, or --resume-after-catalog-approval"
            )
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
            apply=args.apply or args.resume or args.resume_after_catalog_approval,
        )
        if not args.apply and not args.resume and not args.resume_after_catalog_approval:
            print(json.dumps(asdict(plan), indent=2, sort_keys=True))
            return 0
        receipt = (
            resume_after_catalog_approval(plan, acknowledgement=args.ack_dedicated_project)
            if args.resume_after_catalog_approval
            else apply_release(
                plan,
                acknowledgement=args.ack_dedicated_project,
                managed_build_id=args.managed_build_id,
                resume=args.resume,
            )
        )
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    except KeyboardInterrupt:
        print("release interrupted; durable checkpoint retained", file=sys.stderr)
        return 130
    except (CommandFailure, OSError, TypeError, ValueError) as exception:
        print(f"release error: {exception}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
