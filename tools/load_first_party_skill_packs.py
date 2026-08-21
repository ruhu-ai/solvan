"""Publish the repository's first-party skill packs as built-in product guidance.

The packs under `guidance/*/*/SKILL.md` are validated by
`scripts/validate_skill_packs.py` and ship with the application. Per
specification 18 §11 they are **built-in product guidance**: published at
deployment by the release identity through the standard specification 17
lifecycle machinery — create draft, ingestion receipt, submit, evaluation,
independent approval — with three distinct release principals and the pinned
release commit's merge-gate run as the evaluation evidence. No separate write
path exists and every ordinary digest, role, ingestion, predicate, and
separation check still executes.

Built-in guidance is not client-manageable: tenant principals cannot deprecate,
retire, or remove it. A subsequent application release supersedes it: when a
pack's approved head no longer matches the shipped material, the release
approver deprecates the head and publishes the next version with an exact
`supersedes` reference through the same lifecycle. Prior revisions, approvals,
evaluations, and ingestion receipts are immutable history and are never
rewritten or deleted; stale never-approved drafts are converged past, not
removed.

A pack published under the `SKILL` kind is additionally compiled from a real
specification 18 §6 import of the first-party repository source: the pack
directory is packaged into the profile's deterministic container, inspected by
the ordinary interchange canonicalizer, and recorded as a `skill_import_attempt`
and `skill_import` pinned to the release commit, whose licence evidence and
provenance attestation are then bound to the exact reviewable draft. Every hash
recorded there is computed from bytes this process actually read. The release
job performs no quarantine content scan, so the attempt carries no scanner
receipt and its recorded scanner state says exactly that.

Idempotent: re-running at the same release commit converges to a no-op.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any, Literal

import psycopg
import yaml
from psycopg.types.json import Jsonb

from solvan.application.operational_guidance import (
    BlockedBehavior,
    GuidanceError,
    GuidanceKind,
    GuidanceLifecycle,
    GuidanceRevision,
    GuidanceSourceKind,
    GuidanceStepKind,
    GuidanceStepRevision,
)
from solvan.application.skills_interchange import SkillImportError, inspect_skill_archive
from solvan.application.skills_interchange_service import SkillImportCommand, SkillImportService
from solvan.application.skills_security import normalize_license
from solvan.application.workspace_hashing import canonical_sha256, sha256_bytes
from solvan.domain import Scope, new_identifier
from solvan.persistence.operational_guidance_store import PostgresOperationalGuidanceStore
from solvan.persistence.skills_interchange_store import PostgresSkillImportRepository

ROOT = Path(__file__).resolve().parents[1]

#: Specification 18 §11 release principals. Three distinct identities so the
#: ordinary author/evaluator/approver separation checks hold for built-ins.
AUTHOR_PRINCIPAL = "product:solvan"
EVALUATOR_PRINCIPAL = "release:merge-gate"
APPROVER_PRINCIPAL = "release:manager"
GRANTED_BY = "release:bootstrap"

#: Mirrors the API's registered completion predicates (apps/api/main.py); the
#: approval path refuses a predicate outside this closed set, and every entry
#: must be implemented by the runtime evaluator
#: (solvan.persistence.operational_guidance_runtime). The ci-failure-triage
#: predicates are deliberately absent: its classification step has no durable
#: classification record to evaluate against, so approving the pack would mint
#: steps that can only ever verdict ERROR (specification 23 marks that skill
#: target until the record exists).
KNOWN_PREDICATES = frozenset(
    {
        "evidence-kind-present@1",
        "verification-profile-passed@1",
        "production-graph-binding-resolved@1",
        "action-effect-reconciled@1",
        "guidance-content-fetched@1",
        "repair-input-manifest-valid@1",
        "repair-evidence-cited@1",
        "exploratory-baseline-recorded@1",
        "candidate-generation-recorded@1",
        "exploratory-regression-recorded@1",
        "patch-proposal-complete@1",
    }
)

CODE_REPAIR_PACKS = frozenset({"code-repair"})
CODE_REPAIR_PROFILE = "workspace.code-repair.v1@1"

#: Specification 18 §6.1 source type for this repository at a pinned commit.
IMPORT_SOURCE_KIND: Literal["FIRST_PARTY"] = "FIRST_PARTY"
#: The canonicalization `inspect_skill_archive` implements (§8).
CANONICALIZATION_VERSION = "skill-canonicalization/1"
#: Recorded on the licence policy row this job creates for the repository's own
#: licence. The identifier itself comes from the pack, never from this constant.
LICENSE_POLICY_VERSION = "first-party-release/1"
#: What the release job did about §6.2 phase 3. It runs no quarantine content
#: scanner: there is no Model Armor gate, policy engine, or quarantine bucket in
#: the catalog-publication job, and first-party material is screened by the
#: merge gate instead (§11). Recording this labelled absence — rather than a
#: verdict, a receipt, or an empty object that could be read as "unrecorded" —
#: keeps the attempt's idempotency material honest and makes a future real scan
#: a different import rather than a silent upgrade.
IMPORT_SCANNER_STATE: dict[str, str] = {"QUARANTINE_SCAN": "not-performed"}

#: Owner-family metadata. A pack whose family binds no registered agent with an
#: approved profile is refused, never silently skipped or half-bound.
FAMILY_AGENT_KEYS: dict[str, tuple[str, ...]] = {
    "reliability": ("evidence-agent",),
    "payments": ("evidence-agent",),
    "platform": ("infrastructure-agent", "evidence-agent"),
    "reporting": ("workspace-agent",),
}
#: The SKILL kind is reserved for content compiled through the interchange
#: import path, whose approval requires a compile and license binding. Built-in
#: packs publish under the release trust root, so they use the other kinds.
FAMILY_KIND: dict[str, GuidanceKind] = {
    "reliability": GuidanceKind.DIAGNOSTIC_PROCEDURE,
    "payments": GuidanceKind.CHECKLIST,
    "platform": GuidanceKind.CHECKLIST,
    "reporting": GuidanceKind.RUNBOOK,
}
INCIDENT_CLASS_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("connection", "CONNECTION_EXHAUSTION"),
    ("error-rate", "SERVICE_ERROR_RATE"),
    ("deployment", "DEPLOYMENT_REGRESSION"),
    ("latency", "LATENCY_REGRESSION"),
)

_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_DISPLAY_ACRONYMS = frozenset({"api", "sli", "slo"})


class PackLoaderError(RuntimeError):
    """Pack material or publication input is invalid or unidentifiable."""


def _validated_commit(value: str) -> str:
    if _COMMIT_PATTERN.fullmatch(value) is None:
        raise PackLoaderError("release commit must be a full lowercase git commit SHA")
    return value


def release_commit(explicit: str | None = None) -> str:
    """Resolve the pinned commit this publication is attributed to.

    An explicit argument wins, then ``SOLVAN_RELEASE_COMMIT``, then the
    repository HEAD. A publication without an identifiable commit is refused:
    the commit is bound into decision request identifiers and evaluation
    evidence, and a placeholder there would poison idempotency and provenance.
    """

    if explicit is not None:
        return _validated_commit(explicit)
    from_environment = os.environ.get("SOLVAN_RELEASE_COMMIT")
    if from_environment:
        return _validated_commit(from_environment)
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PackLoaderError(
            "release commit is unidentifiable: pass --release-commit, set "
            "SOLVAN_RELEASE_COMMIT, or run inside the release git worktree"
        ) from error
    return _validated_commit(result.stdout.strip())


def _frontmatter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---\n"):
        raise PackLoaderError("a skill pack must begin with YAML frontmatter")
    parts = text.split("---\n", 2)
    if len(parts) != 3:
        raise PackLoaderError("skill pack frontmatter is unterminated")
    try:
        parsed = yaml.safe_load(parts[1])
    except yaml.YAMLError as error:
        raise PackLoaderError("skill pack frontmatter is invalid YAML") from error
    if not isinstance(parsed, dict):
        raise PackLoaderError("skill pack frontmatter must be a mapping")
    return parsed, parts[2]


def _display_name(name: str) -> str:
    """Sentence-case the pack name, uppercasing exact acronym tokens only."""

    words = [token.upper() if token in _DISPLAY_ACRONYMS else token for token in name.split("-")]
    text = " ".join(words)
    return text[:1].upper() + text[1:]


def _incident_classes(name: str) -> tuple[str, ...]:
    matched = tuple(cls for keyword, cls in INCIDENT_CLASS_KEYWORDS if keyword in name)
    return matched or ("GENERAL_INVESTIGATION",)


def _provenance(pack: Path) -> dict[str, Any]:
    path = pack / "PROVENANCE.yaml"
    if not path.is_file():
        raise PackLoaderError(f"{pack.name}: provenance attestation is missing")
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise PackLoaderError(f"{pack.name}: provenance attestation is invalid YAML") from error
    if not isinstance(value, dict):
        raise PackLoaderError(f"{pack.name}: provenance attestation must be a mapping")
    return value


def provenance_attestation_hash(pack: Path) -> str:
    """Content digest of the pack's provenance attestation, bound into evidence."""

    path = pack / "PROVENANCE.yaml"
    if not path.is_file():
        raise PackLoaderError(f"{pack.name}: provenance attestation is missing")
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def revision_for(
    pack: Path,
    *,
    commit: str,
    agent_keys: tuple[str, ...],
    profile_revisions: tuple[str, ...],
    version: str = "1",
    supersedes: str | None = None,
) -> GuidanceRevision:
    """Build one draft revision from a validated pack directory."""

    skill_path = pack / "SKILL.md"
    if not skill_path.is_file():
        raise PackLoaderError(f"{pack.name}: SKILL.md is missing")
    front, body = _frontmatter(skill_path.read_text(encoding="utf-8"))
    name = front.get("name")
    if not isinstance(name, str) or name != pack.name:
        raise PackLoaderError(
            f"{pack.name}: frontmatter name {name!r} must equal the pack directory name"
        )
    description = front.get("description")
    if not isinstance(description, str) or not description.strip():
        raise PackLoaderError(f"{pack.name}: frontmatter description is required")
    stripped_body = body.strip()
    if not stripped_body:
        raise PackLoaderError(f"{pack.name}: skill pack body is empty")
    provenance = _provenance(pack)
    metadata = front.get("metadata") or {}
    family = pack.parent.name
    key = f"{family}.{name}"
    code_repair = family == "reliability" and name in CODE_REPAIR_PACKS
    content_hash = (
        sha256_bytes(skill_path.read_bytes())
        if code_repair
        else f"sha256:{canonical_sha256({'body': body}).removeprefix('sha256:')}"
    )
    return GuidanceRevision(
        guidance_key=key,
        version=version,
        display_name=_display_name(name),
        description=description,
        owner_department=str(metadata.get("solvan-owner", family)),
        discoverable_departments=(str(metadata.get("solvan-owner", family)),),
        guidance_kind=(
            GuidanceKind.SKILL if code_repair else FAMILY_KIND.get(family, GuidanceKind.CHECKLIST)
        ),
        lifecycle=GuidanceLifecycle.DRAFT,
        applicable_service_kinds=("payments-api",),
        applicable_incident_classes=(
            ("CI_FAILURE_EVIDENCE",) if name == "ci-failure-triage" else _incident_classes(name)
        ),
        symptom_tags=(family,),
        purpose="INCIDENT_INVESTIGATION",
        classification="INTERNAL",
        eligible_regions=("europe-west1",),
        allowed_agent_keys=agent_keys,
        required_profile_revisions=profile_revisions,
        steps=(
            _code_repair_steps(name)
            if code_repair
            else (
                GuidanceStepRevision(
                    step_key="read-pack",
                    ordinal=1,
                    title="Read the packaged checklist",
                    objective=stripped_body.splitlines()[0][:900],
                    step_kind=GuidanceStepKind.CHECKPOINT,
                    allowed_tool_revisions=(),
                    prerequisite_step_keys=(),
                    completion_predicate_key="guidance-content-fetched",
                    completion_predicate_version="1",
                    required_evidence_kinds=("GUIDANCE_FETCH_RECEIPT",),
                    maximum_tool_requests=0,
                    on_blocked=BlockedBehavior.CONTINUE,
                ),
            )
        ),
        content_ref=str(pack.resolve().relative_to(ROOT)),
        content_hash=content_hash,
        source_kind=GuidanceSourceKind.SOLVAN_AUTHORED,
        # The release commit must not be digested material: approval_digest
        # covers source_ref, so embedding the SHA made every commit invalidate
        # every pack's digest-equality no-op and superseded all seventeen
        # packs on the next load. Release provenance already lives in the
        # commit-qualified decision IDs and the release-gate receipt.
        source_ref=f"{pack.resolve().relative_to(ROOT)} · first-party release pack",
        source_license=str(front.get("license") or provenance.get("license") or "Apache-2.0"),
        author_principal=AUTHOR_PRINCIPAL,
        supersedes=supersedes,
    )


def _repair_step(
    *,
    key: str,
    ordinal: int,
    title: str,
    objective: str,
    kind: GuidanceStepKind,
    tools: tuple[str, ...],
    predecessor: str | None,
    predicate: str,
    requests: int,
) -> GuidanceStepRevision:
    return GuidanceStepRevision(
        step_key=key,
        ordinal=ordinal,
        title=title,
        objective=objective,
        step_kind=kind,
        allowed_tool_revisions=tools,
        prerequisite_step_keys=() if predecessor is None else (predecessor,),
        completion_predicate_key=predicate,
        completion_predicate_version="1",
        required_evidence_kinds=("ARTIFACT",),
        maximum_tool_requests=requests,
        on_blocked=BlockedBehavior.STOP_INCONCLUSIVE,
    )


def _code_repair_steps(name: str) -> tuple[GuidanceStepRevision, ...]:
    read = "workspace.code-repair.read-artifact@1"
    write = "workspace.code-repair.write-candidate-artifact@1"
    sandbox = "workspace.code-repair.run-in-sandbox@1"
    if name == "ci-failure-triage":
        return (
            _repair_step(
                key="validate-ci-evidence",
                ordinal=1,
                title="Validate the bounded CI failure evidence",
                objective=(
                    "Read only the successor plan's frozen CI failure artifact and identities."
                ),
                kind=GuidanceStepKind.OBSERVE,
                tools=(read,),
                predecessor=None,
                predicate="ci-failure-evidence-valid",
                requests=8,
            ),
            _repair_step(
                key="classify-ci-failure",
                ordinal=2,
                title="Classify the bounded CI failure",
                objective=(
                    "Classify the cited failure without rerunning CI or changing the pull request."
                ),
                kind=GuidanceStepKind.COMPUTE,
                tools=(read,),
                predecessor="validate-ci-evidence",
                predicate="ci-failure-classified",
                requests=8,
            ),
            _repair_step(
                key="prepare-successor-candidate",
                ordinal=3,
                title="Prepare a successor candidate or stop inconclusive",
                objective=(
                    "Create only an allowlisted candidate and record an "
                    "experimental sandbox receipt."
                ),
                kind=GuidanceStepKind.PROPOSE,
                tools=(read, write, sandbox),
                predecessor="classify-ci-failure",
                predicate="patch-proposal-complete",
                requests=16,
            ),
        )
    return (
        _repair_step(
            key="establish-inputs",
            ordinal=1,
            title="Establish bounded repair inputs",
            objective=(
                "Validate the exact plan, snapshot, profile, catalog, guidance, "
                "and budget bindings."
            ),
            kind=GuidanceStepKind.OBSERVE,
            tools=(read,),
            predecessor=None,
            predicate="repair-input-manifest-valid",
            requests=16,
        ),
        _repair_step(
            key="inspect-mechanism",
            ordinal=2,
            title="Inspect the cited mechanism",
            objective="Read only cited source and evidence handles and preserve uncertainty.",
            kind=GuidanceStepKind.OBSERVE,
            tools=(read,),
            predecessor="establish-inputs",
            predicate="repair-evidence-cited",
            requests=32,
        ),
        _repair_step(
            key="reproduce-baseline",
            ordinal=3,
            title="Record an experimental baseline",
            objective=(
                "Run the frozen reproduction catalog command without treating "
                "its result as adjudication."
            ),
            kind=GuidanceStepKind.COMPUTE,
            tools=(sandbox,),
            predecessor="inspect-mechanism",
            predicate="exploratory-baseline-recorded",
            requests=2,
        ),
        _repair_step(
            key="build-candidate",
            ordinal=4,
            title="Build a minimal candidate",
            objective=(
                "Append only allowlisted regular-file candidate generations "
                "with exact prior hashes."
            ),
            kind=GuidanceStepKind.PROPOSE,
            tools=(read, write),
            predecessor="reproduce-baseline",
            predicate="candidate-generation-recorded",
            requests=40,
        ),
        _repair_step(
            key="regression-exploration",
            ordinal=5,
            title="Record an experimental regression run",
            objective=(
                "Run the frozen regression catalog command without claiming "
                "that the candidate passed."
            ),
            kind=GuidanceStepKind.COMPUTE,
            tools=(sandbox,),
            predecessor="build-candidate",
            predicate="exploratory-regression-recorded",
            requests=6,
        ),
        _repair_step(
            key="submit-proposal",
            ordinal=6,
            title="Submit a bounded proposal or insufficiency",
            objective=(
                "Return the complete cited proposal contract or stop with insufficient evidence."
            ),
            kind=GuidanceStepKind.CHECKPOINT,
            tools=(),
            predecessor="regression-exploration",
            predicate="patch-proposal-complete",
            requests=0,
        ),
    )


class _UnusedObjectWriter:
    """Refuse rather than fall back: this publication writes no quarantine object.

    `PostgresSkillImportRepository` needs an object writer for the uploaded-archive
    path. Built-in packs ship inside the release image, so nothing is written to a
    bucket here; any call is a defect and must surface as one.
    """

    def put_bytes(self, *, object_name: str, content: bytes, content_type: str) -> Any:
        raise PackLoaderError(
            "built-in pack publication writes no quarantine object; "
            f"an object write to {object_name!r} is a defect"
        )


def _repository_ref(pack: Path, commit: str, *, suffix: str = "") -> str:
    """A commit-pinned, resolvable reference to material inside this repository."""

    return f"git:{commit}:{pack.resolve().relative_to(ROOT).as_posix()}{suffix}"


def _package_bytes(pack: Path) -> bytes:
    """Package the pack directory into the profile's deterministic container.

    The merge gate (`scripts/validate_skill_packs.py`) inspects the same
    whole-directory package, so the import canonicalizes exactly the material the
    gate validated — including `PROVENANCE.yaml`, which specification 18 §11
    requires the reviewable-material digest to cover. Entry order, timestamps,
    permissions, and storage mode are fixed, so identical pack bytes always
    produce identical package bytes and therefore an identical
    `source_bundle_hash`; nothing here depends on the filesystem's clock or mode
    bits. A link or special file is refused rather than packaged.
    """

    members: list[tuple[str, bytes]] = []
    for path in sorted(pack.rglob("*"), key=lambda item: str(item).encode("utf-8")):
        if path.is_symlink():
            raise PackLoaderError(f"{pack.name}: pack contains a symbolic link")
        if path.is_dir():
            continue
        if not path.is_file():
            raise PackLoaderError(f"{pack.name}: pack contains a special file")
        members.append((f"{pack.name}/{path.relative_to(pack).as_posix()}", path.read_bytes()))
    if not members:
        raise PackLoaderError(f"{pack.name}: pack directory contains no files")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in sorted(members, key=lambda item: item[0].encode("utf-8")):
            info = zipfile.ZipInfo(name)
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, content)
    return output.getvalue()


def _require_first_party_attestation(pack: Path) -> None:
    """Specification 18 §11: repository location alone does not establish authorship."""

    provenance = _provenance(pack)
    if provenance.get("source_kind") != IMPORT_SOURCE_KIND:
        raise PackLoaderError(
            f"{pack.name}: provenance attestation does not declare FIRST_PARTY authorship; "
            "a pack carrying third-party material compiles as IMPORTED under the full "
            "third-party licence rules, not as a built-in"
        )


def _ensure_license_policy(
    connection: psycopg.Connection[Any], *, scope: Scope, identifier: str
) -> None:
    """Register the repository's own licence as an enabled, import-allowed policy.

    Created once and never rewritten. An existing row is a governance decision
    this job does not own, so a disabled or import-denied policy is a typed
    refusal rather than a silent re-enable.
    """

    params = {
        **scope.canonical_dict(),
        "identifier": identifier,
        "policy_version": LICENSE_POLICY_VERSION,
        "principal": APPROVER_PRINCIPAL,
    }
    connection.execute(
        """INSERT INTO solvan_operability.skill_license_policies
             (organization_id,project_id,environment_id,normalized_identifier,
              policy_version,import_allowed,redistribution_allowed,enabled,
              reviewed_by_principal)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(identifier)s,
                   %(policy_version)s,true,true,true,%(principal)s)
           ON CONFLICT DO NOTHING""",
        params,
    )
    row = connection.execute(
        """SELECT enabled,import_allowed FROM solvan_operability.skill_license_policies
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s
              AND normalized_identifier=%(identifier)s""",
        params,
    ).fetchone()
    if row is None or not row[0] or not row[1]:
        raise PackLoaderError(
            f"licence {identifier!r} is not an enabled, import-allowed policy in this scope"
        )


def _ensure_owner_slug(
    connection: psycopg.Connection[Any], *, scope: Scope, slug: str, department: str
) -> None:
    """Register the pack's owner-slug segment as its department's stable identity.

    Specification 18 §11 makes the `guidance/<owner-slug>/` segment the owner
    slug, so the registration records a repository fact rather than inventing an
    identity. It is written once; a row that maps the slug elsewhere, or retires
    it, is a typed refusal rather than a rewrite.
    """

    params = {
        **scope.canonical_dict(),
        "slug": slug,
        "department": department,
        "principal": AUTHOR_PRINCIPAL,
    }
    connection.execute(
        """INSERT INTO solvan_operability.skill_owner_department_slugs
             (organization_id,project_id,environment_id,owner_slug,owner_department,
              owner_principal)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(slug)s,
                   %(department)s,%(principal)s)
           ON CONFLICT DO NOTHING""",
        params,
    )
    row = connection.execute(
        """SELECT owner_department,retired_at
             FROM solvan_operability.skill_owner_department_slugs
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s AND owner_slug=%(slug)s""",
        params,
    ).fetchone()
    if row is None or str(row[0]) != department or row[1] is not None:
        raise PackLoaderError(
            f"owner slug {slug!r} is not registered to department {department!r} in this scope"
        )


def _record_first_party_import(
    connection: psycopg.Connection[Any],
    *,
    scope: Scope,
    pack: Path,
    revision: GuidanceRevision,
    commit: str,
) -> str:
    """Record the §6 import this publication actually performs; return its attempt.

    Everything persisted is derived from bytes read out of the release image at
    the pinned commit: the source, package, and guidance digests come from the
    ordinary interchange canonicalizer, and the licence evidence is the pack's
    own frontmatter declaration. No fetch, scanner verdict, or object-store
    receipt is claimed. Idempotent on the import request hash, so re-running at
    the same commit over the same bytes reuses the one attempt.
    """

    _require_first_party_attestation(pack)
    package = _package_bytes(pack)
    try:
        inspection = inspect_skill_archive(package)
    except SkillImportError as error:
        raise PackLoaderError(
            f"{pack.name}: pack material is not importable: {', '.join(sorted(error.codes))}"
        ) from error
    license_value = normalize_license(inspection.frontmatter)
    if license_value is None or license_value[0] != revision.source_license:
        raise PackLoaderError(
            f"{pack.name}: pack licence evidence does not match the revision licence"
        )
    subdirectory = pack.resolve().relative_to(ROOT).as_posix()
    command = SkillImportCommand(
        command_id=f"builtin-import:{revision.guidance_key}",
        scope=scope,
        purpose=revision.purpose,
        classification=revision.classification,
        region=revision.eligible_regions[0],
        source_kind=IMPORT_SOURCE_KIND,
        source_ref=_repository_ref(pack, commit),
        upstream_subdirectory=subdirectory,
        upstream_commit_sha=commit,
        principal=AUTHOR_PRINCIPAL,
        # The release job's authorization is the release itself: the same pinned
        # merge-gate run the evaluation cites. It is not caller-provided.
        authorization_ref=f"release-gate://{commit}",
        idempotency_key=(
            f"builtin:{commit[:12]}:{revision.guidance_key}:"
            f"{inspection.source_bundle_hash.removeprefix('sha256:')[:12]}"
        ),
    )
    request_hash = SkillImportService.request_hash(
        command,
        source_bundle_hash=inspection.source_bundle_hash,
        scanner_versions=dict(IMPORT_SCANNER_STATE),
    )
    lookup = {**scope.canonical_dict(), "request_hash": request_hash}
    existing = connection.execute(
        """SELECT id FROM solvan_operability.skill_import_attempts
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s
              AND import_request_hash=%(request_hash)s""",
        lookup,
    ).fetchone()
    if existing is not None:
        return str(existing[0])
    attempt_id = new_identifier("sia")
    connection.execute(
        """INSERT INTO solvan_operability.skill_import_attempts
             (organization_id,project_id,environment_id,id,import_request_hash,
              idempotency_key,source_kind,source_ref,purpose,requested_classification,
              requested_region,decision,reason_codes_json,scanner_receipts_json,
              importer_principal,authorization_ref)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                   %(request_hash)s,%(idempotency_key)s,%(source_kind)s,%(source_ref)s,
                   %(purpose)s,%(classification)s,%(region)s,'QUARANTINED',
                   %(reasons)s,'[]',%(principal)s,%(authorization_ref)s)
           ON CONFLICT (organization_id,project_id,environment_id,import_request_hash)
           DO NOTHING""",
        {
            **lookup,
            "id": attempt_id,
            "idempotency_key": command.idempotency_key,
            "source_kind": command.source_kind,
            "source_ref": command.source_ref,
            "purpose": command.purpose,
            "classification": command.classification,
            "region": command.region,
            # Real findings from the inspection that ran, plus the marker naming
            # what this attempt is. No scanner receipt is recorded because no
            # quarantine scanner ran.
            "reasons": Jsonb(sorted({"FIRST_PARTY_RELEASE_PACK", *inspection.warnings})),
            "principal": command.principal,
            "authorization_ref": command.authorization_ref,
        },
    )
    stored = connection.execute(
        """SELECT id FROM solvan_operability.skill_import_attempts
            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
              AND environment_id=%(environment_id)s
              AND import_request_hash=%(request_hash)s""",
        lookup,
    ).fetchone()
    if stored is None:
        raise PackLoaderError(f"{pack.name}: the first-party import attempt was not persisted")
    if str(stored[0]) != attempt_id:
        # A concurrent release job recorded the identical import first; its
        # attempt is the one this publication compiles from.
        return str(stored[0])
    connection.execute(
        """INSERT INTO solvan_operability.skill_imports
             (organization_id,project_id,environment_id,id,attempt_id,source_skill_name,
              source_bundle_hash,normalized_package_hash,guidance_content_hash,
              canonicalization_version,package_object_ref,package_object_hash,
              content_manifest_ref,license_state,normalized_license_identifier,
              license_evidence_ref,license_evidence_hash,upstream_ref,
              upstream_subdirectory,upstream_commit_sha,upstream_subtree_hash,
              scanner_versions_json)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                   %(attempt_id)s,%(name)s,%(source_hash)s,%(normalized_hash)s,
                   %(content_hash)s,%(canonicalization)s,%(package_ref)s,%(package_hash)s,
                   %(manifest_ref)s,'PRESENT',%(license_identifier)s,%(license_ref)s,
                   %(license_hash)s,NULL,%(subdirectory)s,%(commit)s,NULL,%(scanners)s)""",
        {
            **scope.canonical_dict(),
            "id": new_identifier("si"),
            "attempt_id": attempt_id,
            "name": str(inspection.frontmatter["name"]),
            "source_hash": inspection.source_bundle_hash,
            "normalized_hash": inspection.normalized_package_hash,
            "content_hash": inspection.guidance_content_hash,
            "canonicalization": CANONICALIZATION_VERSION,
            # There is no quarantine bucket in the release job. The package and
            # its manifest are addressed where the bytes actually are: this
            # repository at the pinned commit. The hash is of the exact package
            # bytes canonicalized above, and `upstream_ref`/`upstream_subtree_hash`
            # stay NULL because no branch was resolved and git's tree hash is not
            # the sha256 the column requires.
            "package_ref": _repository_ref(pack, commit),
            "package_hash": "sha256:" + hashlib.sha256(package).hexdigest(),
            "manifest_ref": _repository_ref(
                pack, commit, suffix=f"#content-manifest/{CANONICALIZATION_VERSION}"
            ),
            "license_identifier": license_value[0],
            "license_ref": _repository_ref(pack, commit, suffix="/SKILL.md#frontmatter.license"),
            "license_hash": "sha256:" + hashlib.sha256(license_value[1]).hexdigest(),
            "subdirectory": subdirectory,
            "commit": commit,
            "scanners": Jsonb(dict(IMPORT_SCANNER_STATE)),
        },
    )
    return attempt_id


def _bind_compile(
    connection: psycopg.Connection[Any],
    *,
    scope: Scope,
    pack: Path,
    revision: GuidanceRevision,
    commit: str,
    attempt_id: str,
    provenance_hash: str,
) -> None:
    """Bind the recorded import's licence evidence to the exact reviewable draft.

    The licence evidence hash is read back out of the import through the store's
    own compile gate, so the binding cites what the import recorded rather than
    what this job would like it to say.
    """

    repository = PostgresSkillImportRepository(connection, object_writer=_UnusedObjectWriter())
    attestation_ref = _repository_ref(pack, commit, suffix="/PROVENANCE.yaml")
    try:
        license_evidence_hash = repository.require_compile_context(
            scope=scope,
            import_id=attempt_id,
            guidance_key=revision.guidance_key,
            owner_department=revision.owner_department,
            normalized_license_identifier=str(revision.source_license),
            source_classification=revision.source_kind,
            provenance_attestation_ref=attestation_ref,
            provenance_attestation_hash=provenance_hash,
            contains_third_party_material=False,
        )
        repository.persist_compile_binding(
            scope=scope,
            import_id=attempt_id,
            revision=revision,
            license_evidence_hash=license_evidence_hash,
            provenance_attestation_ref=attestation_ref,
            provenance_attestation_hash=provenance_hash,
            contains_third_party_material=False,
        )
    except ValueError as error:
        raise PackLoaderError(
            f"{revision.revision_ref}: skill compile binding refused: {error}"
        ) from error


def _compile_from_first_party_import(
    connection: psycopg.Connection[Any],
    *,
    scope: Scope,
    pack: Path,
    revision: GuidanceRevision,
    commit: str,
) -> str:
    """Run the §6 import and the §7 compile prerequisites for one SKILL revision."""

    license_identifier = revision.source_license
    if not license_identifier:
        raise PackLoaderError(
            f"{revision.revision_ref}: a SKILL revision requires reviewed licence evidence"
        )
    _ensure_license_policy(connection, scope=scope, identifier=license_identifier)
    _ensure_owner_slug(
        connection,
        scope=scope,
        slug=revision.guidance_key.partition(".")[0],
        department=revision.owner_department,
    )
    return _record_first_party_import(
        connection, scope=scope, pack=pack, revision=revision, commit=commit
    )


def _ensure_release_role_bindings(
    connection: psycopg.Connection[Any], *, scope: Scope, departments: tuple[str, ...]
) -> None:
    """Bind the three release principals to their single lifecycle role each."""

    grants = (
        (AUTHOR_PRINCIPAL, "GUIDANCE_AUTHOR"),
        (EVALUATOR_PRINCIPAL, "GUIDANCE_EVALUATOR"),
        (APPROVER_PRINCIPAL, "GUIDANCE_APPROVER"),
    )
    for department in departments:
        for principal, role in grants:
            connection.execute(
                """INSERT INTO solvan_operability.operability_role_bindings
                     (organization_id,project_id,environment_id,principal,role,
                      department,granted_by)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(principal)s,%(role)s,%(department)s,%(granted_by)s)
                   ON CONFLICT DO NOTHING""",
                {
                    **scope.canonical_dict(),
                    "principal": principal,
                    "role": role,
                    "department": department,
                    "granted_by": GRANTED_BY,
                },
            )


def _decision_id(commit: str, revision_ref: str, stage: str) -> str:
    return f"builtin:{commit[:12]}:{revision_ref}:{stage}"


def _publish(
    store: PostgresOperationalGuidanceStore,
    *,
    connection: psycopg.Connection[Any],
    scope: Scope,
    pack: Path,
    revision: GuidanceRevision,
    commit: str,
    provenance_hash: str,
) -> None:
    """Walk one pack through the ordinary lifecycle with release identities.

    A `SKILL` revision is compiled from a real §6 import first, in specification
    order: the import is recorded, the draft is created from it, and the import's
    licence evidence and provenance attestation are bound to that exact draft
    before any ingestion, evaluation, or approval runs.
    """

    key = revision.guidance_key
    ref = revision.revision_ref
    commit_pin = commit[:12]
    attempt_id = (
        _compile_from_first_party_import(
            connection, scope=scope, pack=pack, revision=revision, commit=commit
        )
        if revision.guidance_kind is GuidanceKind.SKILL
        else None
    )
    draft = store.create_draft(
        scope=scope, revision=revision, decision_request_id=_decision_id(commit, ref, "draft")
    )
    digest = draft.digest
    if attempt_id is not None:
        _bind_compile(
            connection,
            scope=scope,
            pack=pack,
            revision=revision,
            commit=commit,
            attempt_id=attempt_id,
            provenance_hash=provenance_hash,
        )
    # Ingestion is an author-side acceptance record: the store requires the
    # recording principal to hold GUIDANCE_AUTHOR in the owning department.
    # Evaluation and approval below remain with the two other identities.
    store.record_ingestion(
        scope=scope,
        guidance_key=key,
        version=revision.version,
        content_hash=revision.content_hash,
        accepted=True,
        reason_codes=("FIRST_PARTY_RELEASE_PACK",),
        armor_verdict_ref=None,
        principal=AUTHOR_PRINCIPAL,
        decision_request_id=_decision_id(commit, ref, "ingest"),
    )
    store.submit(
        scope=scope,
        guidance_key=key,
        version=revision.version,
        principal=AUTHOR_PRINCIPAL,
        expected_digest=digest,
        decision_request_id=_decision_id(commit, ref, "submit"),
    )
    evaluation_id = store.record_evaluation(
        scope=scope,
        guidance_key=key,
        version=revision.version,
        expected_digest=digest,
        principal=EVALUATOR_PRINCIPAL,
        suite_version="release-merge-gate@v1",
        passed_cases=1,
        failed_cases=0,
        receipt_ref=f"release-gate://{commit}",
        receipt_hash=canonical_sha256({"release_gate": commit, "pack": key}),
        receipt_generation="1",
        corpus_digest=revision.content_hash,
        case_set_digest=canonical_sha256(
            {"registry": "specs/artifacts/skills-acceptance-registry.yaml", "release": commit}
        ),
        scorer_name="scripts/check",
        scorer_version="ten-stage-gate",
        model_config_pins={
            "release_commit": commit_pin,
            "provenance_attestation": provenance_hash,
        },
        repetitions=1,
        pass_thresholds={"stages": 1.0},
        reason_codes=("RELEASE_GATE_PASSED",),
        decision_request_id=_decision_id(commit, ref, "evaluation"),
    )
    store.approve(
        scope=scope,
        guidance_key=key,
        version=revision.version,
        principal=APPROVER_PRINCIPAL,
        expected_digest=digest,
        evaluation_ref=evaluation_id,
        decision_request_id=_decision_id(commit, ref, "approval"),
        reason=f"Built-in product guidance published at release {commit_pin}.",
        known_predicates=KNOWN_PREDICATES,
    )


def _version_numbers(key: str, versions: tuple[str, ...]) -> tuple[int, ...]:
    numbers: list[int] = []
    for value in versions:
        if not value.isdigit():
            raise PackLoaderError(
                f"{key}: existing guidance version {value!r} is not release-numbered; "
                "refusing to converge a foreign lineage"
            )
        numbers.append(int(value))
    return tuple(numbers)


def load(connection: psycopg.Connection[Any], *, scope: Scope, commit: str) -> list[str]:
    """Converge the guidance store to the shipped packs; return published refs.

    Each pack whose lineage is absent is published as version 1. A pack whose
    approved head matches the shipped material digest-for-digest is left alone.
    Any other lineage — a changed pack, or stale artifacts left by an earlier
    loader run — is converged by supersession: the approved head (if any)
    is deprecated by the release approver and the next version is published
    with an exact ``supersedes`` reference through the full lifecycle. Nothing
    is deleted; approvals, evaluations, and receipts remain immutable history.
    """

    commit = _validated_commit(commit)
    store = PostgresOperationalGuidanceStore(connection)
    registered_agents = {
        str(row[0])
        for row in connection.execute(
            "SELECT principal_key FROM solvan_operability.catalog_principals"
        ).fetchall()
    }
    approved_profiles: dict[str, tuple[str, ...]] = {}
    for row in connection.execute(
        """SELECT allowed_agent_key, profile_key, version
             FROM solvan_operability.tool_profile_revisions
            WHERE lifecycle = 'APPROVED'
            ORDER BY profile_key, version"""
    ).fetchall():
        agent = str(row[0])
        approved_profiles.setdefault(agent, ())
        approved_profiles[agent] = (*approved_profiles[agent], f"{row[1]}@{row[2]}")
    packs = sorted(ROOT.glob("guidance/*/*/SKILL.md"))
    if not packs:
        raise PackLoaderError(f"no first-party skill packs found under {ROOT / 'guidance'}")
    # ci-failure-triage is excluded from publication, not silently published
    # broken: its classification step names a predicate with no durable
    # classification record, so the runtime could only verdict ERROR. It
    # returns when that record exists (specification 23 §5).
    packs = [path for path in packs if path.parent.name != "ci-failure-triage"]
    prepared: list[tuple[Path, tuple[str, ...], tuple[str, ...], GuidanceRevision]] = []
    seen_keys: set[str] = set()
    for skill in packs:
        pack = skill.parent
        family = pack.parent.name
        declared = (
            ("workspace-agent",)
            if family == "reliability" and pack.name in CODE_REPAIR_PACKS
            else FAMILY_AGENT_KEYS.get(family)
        )
        if declared is None:
            raise PackLoaderError(
                f"{pack.name}: guidance family {family!r} is not in the owner-agent registry"
            )
        agent_keys = tuple(key for key in declared if key in registered_agents)
        profile_revisions = tuple(
            revision for key in agent_keys for revision in approved_profiles.get(key, ())
        )
        if family == "reliability" and pack.name in CODE_REPAIR_PACKS:
            profile_revisions = tuple(
                revision for revision in profile_revisions if revision == CODE_REPAIR_PROFILE
            )
        if not agent_keys or not profile_revisions:
            raise PackLoaderError(
                f"{pack.name}: family {family!r} has no registered agents with approved "
                "profiles; publish the governed catalog before built-in guidance"
            )
        baseline = revision_for(
            pack, commit=commit, agent_keys=agent_keys, profile_revisions=profile_revisions
        )
        if baseline.guidance_key in seen_keys:
            raise PackLoaderError(f"{pack.name}: duplicate guidance key {baseline.guidance_key}")
        seen_keys.add(baseline.guidance_key)
        prepared.append((pack, agent_keys, profile_revisions, baseline))
    departments = tuple(sorted({item[3].owner_department for item in prepared}))
    _ensure_release_role_bindings(connection, scope=scope, departments=departments)
    # A previously published head of an excluded pack is deprecated rather
    # than left live: an approved skill whose steps cannot be evaluated must
    # not present as available.
    excluded_head = connection.execute(
        """SELECT h.approved_version, r.revision_hash
             FROM solvan_operability.guidance_current_heads h
             JOIN solvan_operability.guidance_revisions r ON
               (r.organization_id,r.project_id,r.environment_id,r.guidance_key,r.version)=
               (h.organization_id,h.project_id,h.environment_id,h.guidance_key,
                h.approved_version)
            WHERE h.organization_id=%(organization_id)s
              AND h.project_id=%(project_id)s AND h.environment_id=%(environment_id)s
              AND h.guidance_key='reliability.ci-failure-triage'
              AND h.approved_version IS NOT NULL""",
        scope.canonical_dict(),
    ).fetchone()
    if excluded_head is not None:
        excluded_version = str(excluded_head[0])
        with connection.transaction():
            store.deprecate(
                scope=scope,
                guidance_key="reliability.ci-failure-triage",
                version=excluded_version,
                principal=APPROVER_PRINCIPAL,
                expected_digest=str(excluded_head[1]),
                decision_request_id=_decision_id(
                    commit,
                    f"reliability.ci-failure-triage@{excluded_version}",
                    "exclusion-deprecate",
                ),
            )
    published: list[str] = []
    for pack, agent_keys, profile_revisions, baseline in prepared:
        key = baseline.guidance_key
        rows = connection.execute(
            """SELECT version, lifecycle, revision_hash, supersedes_version
                 FROM solvan_operability.guidance_revisions
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND guidance_key=%(key)s""",
            {**scope.canonical_dict(), "key": key},
        ).fetchall()
        if not rows:
            with connection.transaction():
                _publish(
                    store,
                    connection=connection,
                    scope=scope,
                    pack=pack,
                    revision=baseline,
                    commit=commit,
                    provenance_hash=provenance_attestation_hash(pack),
                )
            published.append(baseline.revision_ref)
            continue
        by_version = {str(row[0]): row for row in rows}
        numbers = _version_numbers(key, tuple(by_version))
        head = connection.execute(
            """SELECT approved_version FROM solvan_operability.guidance_current_heads
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND guidance_key=%(key)s""",
            {**scope.canonical_dict(), "key": key},
        ).fetchone()
        head_version = None if head is None or head[0] is None else str(head[0])
        deprecate_digest: str | None = None
        if head_version is not None:
            head_row = by_version.get(head_version)
            if head_row is None:
                raise PackLoaderError(f"{key}: lineage head {head_version} has no revision row")
            head_supersedes = head_row[3]
            candidate = revision_for(
                pack,
                commit=commit,
                agent_keys=agent_keys,
                profile_revisions=profile_revisions,
                version=head_version,
                supersedes=None if head_supersedes is None else f"{key}@{head_supersedes}",
            )
            if candidate.approval_digest == str(head_row[2]):
                continue
            predecessor_version = head_version
            deprecate_digest = str(head_row[2])
        else:
            predecessor_version = str(max(numbers))
        successor = revision_for(
            pack,
            commit=commit,
            agent_keys=agent_keys,
            profile_revisions=profile_revisions,
            version=str(max(numbers) + 1),
            supersedes=f"{key}@{predecessor_version}",
        )
        with connection.transaction():
            if deprecate_digest is not None:
                store.deprecate(
                    scope=scope,
                    guidance_key=key,
                    version=predecessor_version,
                    principal=APPROVER_PRINCIPAL,
                    expected_digest=deprecate_digest,
                    decision_request_id=_decision_id(
                        commit, f"{key}@{predecessor_version}", "deprecate"
                    ),
                )
            _publish(
                store,
                connection=connection,
                scope=scope,
                pack=pack,
                revision=successor,
                commit=commit,
                provenance_hash=provenance_attestation_hash(pack),
            )
        published.append(successor.revision_ref)
    return published


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--environment-id", required=True)
    parser.add_argument(
        "--release-commit",
        default=None,
        help="Pinned release commit; defaults to SOLVAN_RELEASE_COMMIT, then repository HEAD.",
    )
    args = parser.parse_args()
    scope = Scope(args.organization_id, args.project_id, args.environment_id)
    try:
        commit = release_commit(args.release_commit)
        with psycopg.connect(args.database_url) as connection:
            published = load(connection, scope=scope, commit=commit)
    except (GuidanceError, PackLoaderError, ValueError) as error:
        sys.stderr.write(f"first-party pack publication refused: {error}\n")
        return 1
    sys.stdout.write(
        f"Built-in skill packs published: {len(published)}"
        + (f" ({', '.join(published)})" if published else " (all already converged)")
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
