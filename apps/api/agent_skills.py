"""OIDC-bound Agent Skills interchange commands; unavailable dependencies refuse closed."""

from __future__ import annotations

import base64
import binascii
import os
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast

import requests
from fastapi import APIRouter, FastAPI, Header, HTTPException, Query, status
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from solvan.application.operational_guidance import (
    GuidanceIncompatibilityDeclaration,
    GuidanceSourceKind,
    GuidanceStepRevision,
)
from solvan.application.skills_governance import (
    RepositoryMetadataConnector,
    SkillCompileCommand,
    compile_import,
    export_approved_revision,
)
from solvan.application.skills_interchange import SkillFile
from solvan.application.skills_interchange_service import (
    SkillImportCommand,
    SkillImportService,
)
from solvan.application.skills_security import (
    GoogleModelArmorScanner,
    ModelArmorScanner,
    SecurityScanReceipt,
    UnavailableModelArmor,
    require_allowed,
    require_content_safe,
    scan_export_bytes,
    scan_skill_files,
)
from solvan.application.skills_selection import PostgresSkillSelector
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope
from solvan.persistence.operational_guidance_store import PostgresOperationalGuidanceStore
from solvan.persistence.skills_interchange_store import (
    ImmutableObjectReader,
    ImmutableObjectWriter,
    PostgresRefreshLedger,
    PostgresRevisionExportProvider,
    PostgresSkillImportRepository,
)
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.github import GitHubClient
from solvan.platform.github_skills import (
    ConfiguredGitHubTokenProvider,
    GitHubMetadataConnector,
)
from solvan.platform.gitlab_skills import (
    ConfiguredGitLabTokenProvider,
    GitLabMetadataConnector,
)
from solvan.platform.google_rest import authorized_session
from solvan.platform.model_armor import GoogleModelArmorTextGate


class SkillImportHttpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(ge=1, le=1)
    command_id: str = Field(min_length=3, max_length=80)
    purpose: str = Field(min_length=1, max_length=160)
    classification: str = Field(pattern=r"^(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)$")
    region: str = Field(pattern=r"^[a-z0-9-]+$")
    source_kind: str = Field(pattern=r"^(ARCHIVE|REPOSITORY|FIRST_PARTY)$")
    source_ref: str = Field(min_length=1, max_length=2_000)
    upstream_ref: str | None = Field(
        default=None, pattern=r"^refs/(?:heads|tags)/[A-Za-z0-9._/-]+$", max_length=512
    )
    pinned_commit_sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    subdirectory: str = Field(default="", max_length=512)
    archive_base64: str | None = Field(default=None, min_length=1, max_length=1_500_000)

    @model_validator(mode="after")
    def validate_source_shape(self) -> SkillImportHttpRequest:
        if self.source_kind == "REPOSITORY":
            if self.pinned_commit_sha is None or self.upstream_ref is None:
                raise ValueError(
                    "REPOSITORY imports require pinned_commit_sha and an explicit upstream_ref"
                )
            if self.archive_base64 is not None:
                raise ValueError("REPOSITORY imports cannot carry archive bytes")
        elif self.archive_base64 is None:
            raise ValueError("ARCHIVE and FIRST_PARTY imports require archive_base64")
        return self


class SkillCompileHttpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    guidance_key: str
    version: str
    display_name: str
    description: str
    owner_department: str
    discoverable_departments: tuple[str, ...]
    applicable_service_kinds: tuple[str, ...]
    applicable_incident_classes: tuple[str, ...]
    symptom_tags: tuple[str, ...]
    purpose: str
    classification: str
    eligible_regions: tuple[str, ...]
    allowed_agent_keys: tuple[str, ...]
    required_profile_revisions: tuple[str, ...]
    normalized_license_identifier: str = Field(min_length=1, max_length=160)
    source_classification: Literal["IMPORTED", "SOLVAN_AUTHORED"] = "IMPORTED"
    provenance_attestation_ref: str | None = Field(default=None, max_length=2_000)
    provenance_attestation_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    contains_third_party_material: bool = False
    incompatibilities: tuple[GuidanceIncompatibilityDeclaration, ...] = ()
    steps: tuple[GuidanceStepRevision, ...] | None = None
    supersedes: str | None = None


class SkillRefreshHttpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    command_id: str = Field(min_length=3, max_length=80)
    purpose: str = Field(min_length=1, max_length=160)
    expected_head_epoch: int = Field(ge=1)


class SkillExportHttpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(min_length=1, max_length=120)
    destination_id: str = Field(min_length=1, max_length=160)
    purpose: str = Field(min_length=1, max_length=160)
    stale_acknowledged: bool = False


class SkillOwnerRegistrationHttpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    owner_slug: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=80)
    owner_department: str = Field(min_length=1, max_length=160)
    purpose: str = Field(min_length=1, max_length=160)


class SkillLicensePolicyHttpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    normalized_identifier: str = Field(min_length=1, max_length=160)
    policy_version: str = Field(min_length=1, max_length=120)
    import_allowed: bool
    redistribution_allowed: bool
    enabled: bool
    purpose: str = Field(min_length=1, max_length=160)


class SkillReaderGrantHttpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    reader_principal: str = Field(min_length=3, max_length=255)
    owner_department: str = Field(min_length=1, max_length=160)
    reader_purpose: str = Field(min_length=1, max_length=160)
    region: str = Field(pattern=r"^[a-z0-9-]+$")
    classification_ceiling: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
    expires_at: AwareDatetime | None = None
    purpose: str = Field(min_length=1, max_length=160)


class SkillExportDestinationHttpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    destination_id: str = Field(pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$", max_length=160)
    destination_kind: Literal["GCS"]
    binding_ref: str = Field(pattern=r"^gs://[a-z0-9][a-z0-9._-]{1,221}/[^#]*$", max_length=2_000)
    region: str = Field(pattern=r"^[a-z0-9-]+$")
    classification_ceiling: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
    enabled: bool = True
    purpose: str = Field(min_length=1, max_length=160)


@dataclass(frozen=True, slots=True)
class RegisteredExportDestination:
    destination_id: str
    destination_kind: str
    binding_ref: str
    region: str
    classification_ceiling: str


class RevisionExportProvider(Protocol):
    def read(
        self, *, scope: Scope, guidance_key: str, version: str
    ) -> tuple[Any, tuple[SkillFile, ...]]: ...


def _decode_archive(value: str) -> bytes:
    try:
        archive = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "archive encoding is invalid"
        ) from error
    if len(archive) > 1 * 1024 * 1024:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "archive exceeds the profile bound"
        )
    return archive


def _require_role(
    connect: Callable[[], Any],
    *,
    scope: Scope,
    principal: str,
    role: str,
    department: str | None = None,
    purpose: str = "ROLE_CHECK",
    audience: str = "agent-skills",
    classification: str = "INTERNAL",
    region: str | None = None,
) -> str:
    """Require an active scope-bound role; missing bindings fail closed."""
    predicates = [
        "organization_id=%(organization_id)s",
        "project_id=%(project_id)s",
        "environment_id=%(environment_id)s",
        "principal=%(principal)s",
        "role=%(role)s",
        "(expires_at IS NULL OR expires_at > now())",
    ]
    params: dict[str, Any] = {
        **scope.canonical_dict(),
        "principal": principal,
        "role": role,
    }
    if department is not None:
        predicates.append("department=%(department)s")
        params["department"] = department
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT role,department,granted_by,granted_at,expires_at "
            "FROM solvan_operability.operability_role_bindings WHERE "
            + " AND ".join(predicates)
            + " ORDER BY department LIMIT 1",
            params,
        )
        binding = cursor.fetchone()
        if binding is None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "required role is inactive")
    authorization_hash = canonical_sha256(
        {
            "scope": scope.canonical_dict(),
            "principal": principal,
            "role": str(binding[0]),
            "department": str(binding[1]),
            "granted_by": str(binding[2]),
            "granted_at": str(binding[3]),
            "expires_at": str(binding[4]) if binding[4] is not None else None,
            "purpose": purpose,
            "audience": audience,
            "classification": classification,
            "region": region or os.environ.get("SOLVAN_REGION", "europe-west1"),
        }
    )
    return f"authz:{authorization_hash.removeprefix('sha256:')}"


def _require_skill_reader(connect: Callable[[], Any], *, scope: Scope, principal: str) -> None:
    """Projection access is a verified scope-bound grant, never mere omission."""
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            """SELECT 1
                 FROM solvan_operability.operability_role_bindings
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND principal=%(principal)s
                  AND role IN ('GUIDANCE_AUTHOR','GUIDANCE_APPROVER',
                               'GUIDANCE_EXPORTER','OPERABILITY_ADMIN')
                  AND (expires_at IS NULL OR expires_at > now())
                LIMIT 1""",
            {**scope.canonical_dict(), "principal": principal},
        )
        if cursor.fetchone() is None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "skill projection grant is inactive")


def _require_export_destination(
    connect: Callable[[], Any],
    *,
    scope: Scope,
    destination_id: str,
    classification: str,
) -> RegisteredExportDestination:
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            """SELECT enabled, destination_kind, binding_ref, region, classification_ceiling
                 FROM solvan_operability.guidance_export_destinations
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND destination_id=%(destination_id)s""",
            {**scope.canonical_dict(), "destination_id": destination_id},
        )
        row = cursor.fetchone()
    if row is None or not row[0]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "DESTINATION_NOT_ALLOWLISTED")
    configured_region = os.environ.get("SOLVAN_REGION", "europe-west1")
    if str(row[3]) != configured_region:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "REGION_DENIED")
    rank = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}
    if rank.get(classification, 99) > rank.get(str(row[4]), -1):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CLASSIFICATION_DENIED")
    if str(row[1]) != "GCS" or not str(row[2]).startswith("gs://"):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "DESTINATION_PROVIDER_UNAVAILABLE")
    return RegisteredExportDestination(
        destination_id=destination_id,
        destination_kind=str(row[1]),
        binding_ref=str(row[2]),
        region=str(row[3]),
        classification_ceiling=str(row[4]),
    )


def _governance_material(connect: Callable[[], Any], *, scope: Scope) -> dict[str, Any]:
    with connect() as connection, connection.cursor() as cursor:
        scope_params = scope.canonical_dict()
        cursor.execute(
            """SELECT owner_slug,owner_department,owner_principal,retired_at,created_at
                 FROM solvan_operability.skill_owner_department_slugs
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s ORDER BY owner_slug""",
            scope_params,
        )
        owners = [
            {
                "owner_slug": row[0],
                "owner_department": row[1],
                "owner_principal": row[2],
                "retired_at": row[3].isoformat() if row[3] else None,
                "created_at": row[4].isoformat(),
            }
            for row in cursor.fetchall()
        ]
        cursor.execute(
            """SELECT normalized_identifier,policy_version,import_allowed,
                      redistribution_allowed,enabled,reviewed_by_principal,reviewed_at
                 FROM solvan_operability.skill_license_policies
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s ORDER BY normalized_identifier""",
            scope_params,
        )
        licenses = [
            {
                "normalized_identifier": row[0],
                "policy_version": row[1],
                "import_allowed": row[2],
                "redistribution_allowed": row[3],
                "enabled": row[4],
                "reviewed_by_principal": row[5],
                "reviewed_at": row[6].isoformat(),
            }
            for row in cursor.fetchall()
        ]
        cursor.execute(
            """SELECT principal,owner_department,purpose,region,classification_ceiling,
                      granted_by_principal,expires_at,created_at
                 FROM solvan_operability.skill_reader_grants
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s
                ORDER BY principal,owner_department,purpose""",
            scope_params,
        )
        readers = [
            {
                "principal": row[0],
                "owner_department": row[1],
                "purpose": row[2],
                "region": row[3],
                "classification_ceiling": row[4],
                "granted_by_principal": row[5],
                "expires_at": row[6].isoformat() if row[6] else None,
                "created_at": row[7].isoformat(),
            }
            for row in cursor.fetchall()
        ]
        cursor.execute(
            """SELECT destination_id,destination_kind,binding_ref,region,
                      classification_ceiling,enabled
                 FROM solvan_operability.guidance_export_destinations
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s ORDER BY destination_id""",
            scope_params,
        )
        destinations = [
            {
                "destination_id": row[0],
                "destination_kind": row[1],
                "binding_ref": row[2],
                "region": row[3],
                "classification_ceiling": row[4],
                "enabled": row[5],
            }
            for row in cursor.fetchall()
        ]
    return {
        "owners": owners,
        "licenses": licenses,
        "readers": readers,
        "destinations": destinations,
    }


def _write_registered_export(
    *, destination: RegisteredExportDestination, scope: Scope, export_id: str, content: bytes
) -> Any:
    """Write only to the exact registered regional GCS destination."""

    remainder = destination.binding_ref.removeprefix("gs://")
    bucket, separator, prefix = remainder.partition("/")
    if not separator or not bucket or ".." in prefix.split("/"):
        raise ValueError("DESTINATION_BINDING_INVALID")
    session = authorized_session()
    metadata = session.get(
        f"https://storage.googleapis.com/storage/v1/b/{bucket}",
        params={"fields": "location"},
        timeout=30,
    )
    metadata.raise_for_status()
    payload = metadata.json()
    actual_location = str(payload.get("location", "")).lower()
    if actual_location != destination.region:
        raise ValueError("DESTINATION_REGION_MISMATCH")
    object_prefix = prefix.strip("/")
    object_name = "/".join(
        part
        for part in (
            object_prefix,
            scope.organization_id,
            scope.project_id,
            scope.environment_id,
            f"{export_id}.zip",
        )
        if part
    )
    return GcsEvidenceWriter(bucket=bucket, session=session).put_bytes(
        object_name=object_name, content=content, content_type="application/zip"
    )


def agent_skills_router(
    *,
    principal_provider: Callable[[str | None], str],
    reader_principal_provider: Callable[[str | None], str] | None = None,
    scope_provider: Callable[[], Scope],
    connect: Callable[[], Any],
    object_writer: ImmutableObjectWriter,
    object_reader: ImmutableObjectReader,
    armor: ModelArmorScanner,
    repository_connector: RepositoryMetadataConnector,
    revision_provider: RevisionExportProvider,
) -> APIRouter:
    router = APIRouter()

    @router.get("/api/v1/skills/governance")
    def get_skill_governance(
        human_identity_token: str | None = Header(default=None, alias="Authorization"),
    ) -> dict[str, Any]:
        principal = principal_provider(human_identity_token)
        scope = scope_provider()
        _require_role(
            connect,
            scope=scope,
            principal=principal,
            role="OPERABILITY_ADMIN",
            purpose="SKILL_GOVERNANCE_READ",
            audience="skills-governance",
        )
        return _governance_material(connect, scope=scope)

    @router.post("/api/v1/skills/governance/owners", status_code=status.HTTP_201_CREATED)
    def register_skill_owner(
        request: SkillOwnerRegistrationHttpRequest,
        human_identity_token: str | None = Header(default=None, alias="Authorization"),
    ) -> dict[str, Any]:
        principal = principal_provider(human_identity_token)
        scope = scope_provider()
        _require_role(
            connect,
            scope=scope,
            principal=principal,
            role="OPERABILITY_ADMIN",
            purpose=request.purpose,
            audience=f"skills-owner:{request.owner_slug}",
        )
        with connect() as connection, connection.transaction(), connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan_operability.skill_owner_department_slugs
                   (organization_id,project_id,environment_id,owner_slug,owner_department,
                    owner_principal)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(slug)s,
                           %(department)s,%(principal)s)
                   ON CONFLICT DO NOTHING""",
                {
                    **scope.canonical_dict(),
                    "slug": request.owner_slug,
                    "department": request.owner_department,
                    "principal": principal,
                },
            )
            cursor.execute(
                """SELECT owner_department,owner_principal,retired_at
                     FROM solvan_operability.skill_owner_department_slugs
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND owner_slug=%(slug)s""",
                {**scope.canonical_dict(), "slug": request.owner_slug},
            )
            row = cursor.fetchone()
        if row is None or str(row[0]) != request.owner_department or row[2] is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "OWNER_SLUG_CONFLICT")
        return {
            "owner_slug": request.owner_slug,
            "owner_department": request.owner_department,
            "owner_principal": str(row[1]),
        }

    @router.post("/api/v1/skills/governance/licenses", status_code=status.HTTP_201_CREATED)
    def register_skill_license_policy(
        request: SkillLicensePolicyHttpRequest,
        human_identity_token: str | None = Header(default=None, alias="Authorization"),
    ) -> dict[str, Any]:
        principal = principal_provider(human_identity_token)
        scope = scope_provider()
        _require_role(
            connect,
            scope=scope,
            principal=principal,
            role="OPERABILITY_ADMIN",
            purpose=request.purpose,
            audience=f"skills-license:{request.normalized_identifier}:{request.policy_version}",
        )
        params = {
            **scope.canonical_dict(),
            "identifier": request.normalized_identifier,
            "version": request.policy_version,
            "import_allowed": request.import_allowed,
            "redistribution_allowed": request.redistribution_allowed,
            "enabled": request.enabled,
            "principal": principal,
        }
        with connect() as connection, connection.transaction(), connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan_operability.skill_license_policies
                   (organization_id,project_id,environment_id,normalized_identifier,
                    policy_version,import_allowed,redistribution_allowed,enabled,
                    reviewed_by_principal)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(identifier)s,
                           %(version)s,%(import_allowed)s,%(redistribution_allowed)s,%(enabled)s,
                           %(principal)s) ON CONFLICT DO NOTHING""",
                params,
            )
            cursor.execute(
                """SELECT policy_version,import_allowed,redistribution_allowed,enabled
                     FROM solvan_operability.skill_license_policies
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND normalized_identifier=%(identifier)s""",
                params,
            )
            row = cursor.fetchone()
        expected = (
            request.policy_version,
            request.import_allowed,
            request.redistribution_allowed,
            request.enabled,
        )
        if row is None or tuple(row) != expected:
            raise HTTPException(status.HTTP_409_CONFLICT, "LICENSE_POLICY_CONFLICT")
        return {
            "normalized_identifier": request.normalized_identifier,
            "policy_version": request.policy_version,
            "status": "REGISTERED",
        }

    @router.post("/api/v1/skills/governance/readers", status_code=status.HTTP_201_CREATED)
    def register_skill_reader(
        request: SkillReaderGrantHttpRequest,
        human_identity_token: str | None = Header(default=None, alias="Authorization"),
    ) -> dict[str, Any]:
        principal = principal_provider(human_identity_token)
        scope = scope_provider()
        _require_role(
            connect,
            scope=scope,
            principal=principal,
            role="OPERABILITY_ADMIN",
            purpose=request.purpose,
            audience=f"skills-reader:{request.reader_principal}:{request.owner_department}",
        )
        params = {
            **scope.canonical_dict(),
            "reader": request.reader_principal,
            "department": request.owner_department,
            "reader_purpose": request.reader_purpose,
            "region": request.region,
            "ceiling": request.classification_ceiling,
            "principal": principal,
            "expires_at": request.expires_at,
        }
        with connect() as connection, connection.transaction(), connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan_operability.skill_reader_grants
                   (organization_id,project_id,environment_id,principal,owner_department,purpose,
                    region,classification_ceiling,granted_by_principal,expires_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(reader)s,
                           %(department)s,%(reader_purpose)s,%(region)s,%(ceiling)s,%(principal)s,
                           %(expires_at)s) ON CONFLICT DO NOTHING""",
                params,
            )
            cursor.execute(
                """SELECT classification_ceiling,expires_at
                     FROM solvan_operability.skill_reader_grants
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND principal=%(reader)s
                      AND owner_department=%(department)s AND purpose=%(reader_purpose)s
                      AND region=%(region)s""",
                params,
            )
            row = cursor.fetchone()
        if (
            row is None
            or str(row[0]) != request.classification_ceiling
            or row[1] != request.expires_at
        ):
            raise HTTPException(status.HTTP_409_CONFLICT, "READER_GRANT_CONFLICT")
        return {
            "reader_principal": request.reader_principal,
            "owner_department": request.owner_department,
            "reader_purpose": request.reader_purpose,
            "status": "ACTIVE",
        }

    @router.post("/api/v1/skills/governance/destinations", status_code=status.HTTP_201_CREATED)
    def register_skill_destination(
        request: SkillExportDestinationHttpRequest,
        human_identity_token: str | None = Header(default=None, alias="Authorization"),
    ) -> dict[str, Any]:
        principal = principal_provider(human_identity_token)
        scope = scope_provider()
        configured_region = os.environ.get("SOLVAN_REGION", "europe-west1")
        if request.region != configured_region:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "REGION_DENIED")
        _require_role(
            connect,
            scope=scope,
            principal=principal,
            role="OPERABILITY_ADMIN",
            purpose=request.purpose,
            audience=f"skills-destination:{request.destination_id}",
        )
        params = {
            **scope.canonical_dict(),
            "destination": request.destination_id,
            "kind": request.destination_kind,
            "binding": request.binding_ref,
            "region": request.region,
            "ceiling": request.classification_ceiling,
            "enabled": request.enabled,
        }
        with connect() as connection, connection.transaction(), connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan_operability.guidance_export_destinations
                   (organization_id,project_id,environment_id,destination_id,destination_kind,
                    binding_ref,region,classification_ceiling,enabled)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(destination)s,
                           %(kind)s,%(binding)s,%(region)s,%(ceiling)s,%(enabled)s)
                   ON CONFLICT DO NOTHING""",
                params,
            )
            cursor.execute(
                """SELECT destination_kind,binding_ref,region,classification_ceiling,enabled
                     FROM solvan_operability.guidance_export_destinations
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND destination_id=%(destination)s""",
                params,
            )
            row = cursor.fetchone()
        expected = (
            request.destination_kind,
            request.binding_ref,
            request.region,
            request.classification_ceiling,
            request.enabled,
        )
        if row is None or tuple(row) != expected:
            raise HTTPException(status.HTTP_409_CONFLICT, "DESTINATION_CONFLICT")
        return {"destination_id": request.destination_id, "status": "REGISTERED"}

    @router.get("/api/v1/skills/autocomplete")
    def autocomplete_skills(
        query: str = Query(default="", max_length=160),
        human_identity_token: str | None = Header(default=None, alias="Authorization"),
        reader_identity_token: str | None = Header(default=None, alias="X-Solvan-Approval-Token"),
    ) -> dict[str, Any]:
        reader_provider = reader_principal_provider or principal_provider
        principal = reader_provider(human_identity_token or reader_identity_token)
        scope = scope_provider()
        with connect() as connection:
            items = PostgresSkillSelector(connection).autocomplete_for_principal(
                scope=scope,
                principal=principal,
                runtime_region=os.environ.get("SOLVAN_REGION", "europe-west1"),
                query=query,
            )
        return {
            "items": [
                {
                    "selector": item.selector,
                    "guidance_key": item.guidance_key,
                    "version": item.version,
                    "display_name": item.display_name,
                    "description": item.description,
                }
                for item in items
            ]
        }

    @router.post("/api/v1/skills/import", status_code=status.HTTP_202_ACCEPTED)
    def import_skill(
        request: SkillImportHttpRequest,
        human_identity_token: str | None = Header(default=None, alias="Authorization"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        principal = principal_provider(human_identity_token)
        if idempotency_key is None or not 8 <= len(idempotency_key) <= 128:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Idempotency-Key is required")
        scope = scope_provider()
        authorization_ref = _require_role(
            connect,
            scope=scope,
            principal=principal,
            role="GUIDANCE_AUTHOR",
            purpose=request.purpose,
            audience=f"skills-import:{request.source_kind}:{request.source_ref}",
            classification=request.classification,
            region=request.region,
        )
        if request.source_kind == "REPOSITORY":
            fetch_archive = getattr(repository_connector, "fetch_archive", None)
            if not callable(fetch_archive):
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    "REGISTERED_CONNECTOR_REQUIRED",
                )
            try:
                observation = repository_connector.observe_ref(
                    repository_ref=request.source_ref,
                    upstream_ref=cast(str, request.upstream_ref),
                    subdirectory=request.subdirectory,
                )
                if observation.commit_sha != request.pinned_commit_sha:
                    raise ValueError("PINNED_COMMIT_MISMATCH")
                archive = fetch_archive(
                    repository_ref=request.source_ref,
                    commit_sha=request.pinned_commit_sha,
                    subdirectory=request.subdirectory,
                )
            except ValueError as error:
                raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
            except RuntimeError as error:
                raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error
            upstream_ref = request.upstream_ref
            upstream_subdirectory = request.subdirectory
            upstream_commit_sha = observation.commit_sha
            upstream_subtree_hash = observation.subtree_hash
        else:
            if request.archive_base64 is None:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "archive_base64 is required for ARCHIVE or FIRST_PARTY imports",
                )
            archive = _decode_archive(request.archive_base64)
            upstream_ref = None
            upstream_subdirectory = None
            upstream_commit_sha = None
            upstream_subtree_hash = None
        command = SkillImportCommand(
            schema_version=request.schema_version,
            command_id=request.command_id,
            scope=scope,
            purpose=request.purpose,
            classification=request.classification,
            region=request.region,
            source_kind=cast(Literal["ARCHIVE", "REPOSITORY", "FIRST_PARTY"], request.source_kind),
            source_ref=request.source_ref,
            upstream_ref=upstream_ref,
            upstream_subdirectory=upstream_subdirectory,
            upstream_commit_sha=upstream_commit_sha,
            upstream_subtree_hash=upstream_subtree_hash,
            principal=principal,
            authorization_ref=authorization_ref,
            idempotency_key=idempotency_key,
        )
        # The connection must own the outer transaction. The service reads before
        # it writes, so every repository `transaction()` is a savepoint; without
        # this block nothing is committed and the attempt is silently discarded.
        with connect() as connection:
            repository = PostgresSkillImportRepository(connection, object_writer=object_writer)
            try:
                outcome = SkillImportService(repository, armor=armor).import_archive(
                    command, archive
                )
            except ValueError as error:
                if str(error) == "IDEMPOTENCY_CONFLICT":
                    raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
                raise
        response = {
            "operation_id": outcome.attempt_id,
            "status": "ACCEPTED" if outcome.decision == "QUARANTINED" else "REFUSED",
            "attempt_id": outcome.attempt_id,
            "decision": outcome.decision,
            "reason_codes": list(outcome.reason_codes),
        }
        if outcome.decision == "REJECTED":
            response["status"] = "REFUSED"
        return response

    @router.get("/api/v1/skills/import-attempts/{attempt_id}")
    def import_attempt(
        attempt_id: str,
        human_identity_token: str | None = Header(default=None, alias="Authorization"),
    ) -> dict[str, Any]:
        principal = principal_provider(human_identity_token)
        scope = scope_provider()
        _require_skill_reader(connect, scope=scope, principal=principal)
        with connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT id, decision, reason_codes_json, scanner_receipts_json, created_at
                       FROM solvan_operability.skill_import_attempts
                      WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                        AND environment_id=%(environment_id)s AND id=%(id)s""",
                {**scope_provider().canonical_dict(), "id": attempt_id},
            )
            row = cursor.fetchone()
            if row is not None:
                cursor.execute(
                    """SELECT id, source_skill_name, source_bundle_hash,
                                      normalized_package_hash, guidance_content_hash,
                                      package_object_ref, content_manifest_ref,
                                      license_state, normalized_license_identifier,
                                      license_evidence_ref,
                                      license_evidence_hash, created_at
                         FROM solvan_operability.skill_imports
                        WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s AND attempt_id=%(id)s""",
                    {**scope.canonical_dict(), "id": attempt_id},
                )
                imported = cursor.fetchone()
                files: list[dict[str, Any]] = []
                validation: list[dict[str, Any]] = []
                retention: list[dict[str, Any]] = []
                if imported is not None:
                    cursor.execute(
                        """SELECT path,size_bytes,media_type,content_hash,disposition,
                                          object_ref
                             FROM solvan_operability.skill_import_files
                            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                              AND environment_id=%(environment_id)s AND import_id=%(import_id)s
                            ORDER BY path""",
                        {**scope.canonical_dict(), "import_id": str(imported[0])},
                    )
                    files = [
                        {
                            "path": file[0],
                            "size_bytes": file[1],
                            "media_type": file[2],
                            "content_hash": file[3],
                            "disposition": file[4],
                            "object_ref": file[5],
                        }
                        for file in cursor.fetchall()
                    ]
                    cursor.execute(
                        """SELECT sequence,reason_code,path,detail_json,object_ref,
                                          object_generation,created_at
                             FROM solvan_operability.skill_validation_receipts
                            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                              AND environment_id=%(environment_id)s AND import_id=%(import_id)s
                            ORDER BY sequence""",
                        {**scope.canonical_dict(), "import_id": str(imported[0])},
                    )
                    validation = [
                        {
                            "sequence": item[0],
                            "reason_code": item[1],
                            "path": item[2],
                            "detail": item[3],
                            "object_ref": item[4],
                            "object_generation": item[5],
                            "created_at": item[6].isoformat(),
                        }
                        for item in cursor.fetchall()
                    ]
                    cursor.execute(
                        """SELECT object_kind,object_id,storage_region,retention_until,
                                          legal_hold_ref,deletion_state,object_uri,
                                          object_generation,deleted_at
                             FROM solvan_operability.skill_retention_controls
                            WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                              AND environment_id=%(environment_id)s
                              AND (object_id=%(attempt_id)s OR object_id LIKE %(import_prefix)s)
                            ORDER BY object_kind,object_id""",
                        {
                            **scope.canonical_dict(),
                            "attempt_id": attempt_id,
                            "import_prefix": f"{imported[0]}:%",
                        },
                    )
                    retention = [
                        {
                            "object_kind": item[0],
                            "object_id": item[1],
                            "storage_region": item[2],
                            "retention_until": item[3].isoformat(),
                            "legal_hold_ref": item[4],
                            "deletion_state": item[5],
                            "object_uri": item[6],
                            "object_generation": item[7],
                            "deleted_at": None if item[8] is None else item[8].isoformat(),
                        }
                        for item in cursor.fetchall()
                    ]
                import_projection = (
                    None
                    if imported is None
                    else {
                        "id": str(imported[0]),
                        "source_skill_name": imported[1],
                        "source_bundle_hash": imported[2],
                        "normalized_package_hash": imported[3],
                        "guidance_content_hash": imported[4],
                        "package_object_ref": imported[5],
                        "content_manifest_ref": imported[6],
                        "license_state": imported[7],
                        "normalized_license_identifier": imported[8],
                        "license_evidence_ref": imported[9],
                        "license_evidence_hash": imported[10],
                        "created_at": imported[11].isoformat(),
                        "files": files,
                        "validation_receipts": validation,
                        "retention": retention,
                    }
                )
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "skill import attempt not found")
        return {
            "attempt_id": str(row[0]),
            "status": str(row[1]),
            "reason_codes": list(row[2]),
            "scanner_receipts": row[3],
            "created_at": row[4].isoformat(),
            "quarantine": import_projection,
        }

    @router.post("/api/v1/skills/{import_id}/compile", status_code=status.HTTP_202_ACCEPTED)
    def compile_skill(
        import_id: str,
        request: SkillCompileHttpRequest,
        human_identity_token: str | None = Header(default=None, alias="Authorization"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        principal = principal_provider(human_identity_token)
        if idempotency_key is None or not 8 <= len(idempotency_key) <= 128:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Idempotency-Key is required")
        scope = scope_provider()
        _require_role(
            connect,
            scope=scope,
            principal=principal,
            role="GUIDANCE_AUTHOR",
            department=request.owner_department,
        )
        try:
            command = SkillCompileCommand(
                **request.model_dump(),
                author_principal=principal,
            )
            with connect() as connection, connection.transaction():
                repository = PostgresSkillImportRepository(connection, object_writer=object_writer)
                inspection = repository.load_inspection(
                    scope=scope, import_id=import_id, reader=object_reader
                )
                require_content_safe(scan_skill_files(inspection.files, armor=armor))
                license_evidence_hash = repository.require_compile_context(
                    scope=scope,
                    import_id=import_id,
                    guidance_key=request.guidance_key,
                    owner_department=request.owner_department,
                    normalized_license_identifier=request.normalized_license_identifier,
                    source_classification=GuidanceSourceKind(request.source_classification),
                    provenance_attestation_ref=request.provenance_attestation_ref,
                    provenance_attestation_hash=request.provenance_attestation_hash,
                    contains_third_party_material=request.contains_third_party_material,
                )
                revision = compile_import(
                    command=command, attempt_id=import_id, inspection=inspection
                )
                guidance = PostgresOperationalGuidanceStore(connection)
                commit = guidance.create_draft(
                    scope=scope, revision=revision, decision_request_id=idempotency_key
                )
                # The approval gate requires an accepted ingestion receipt for
                # the exact content hash; the scan above is that acceptance, so
                # it is recorded in the same transaction as the draft. Without
                # it every API-compiled draft was permanent approval dead-end.
                guidance.record_ingestion(
                    scope=scope,
                    guidance_key=commit.guidance_key,
                    version=commit.version,
                    content_hash=revision.content_hash,
                    accepted=True,
                    reason_codes=("SKILL_COMPILE_CONTENT_SCAN_ACCEPTED",),
                    armor_verdict_ref=None,
                    principal=principal,
                    decision_request_id=f"{idempotency_key}:ingest",
                )
                repository.persist_compile_binding(
                    scope=scope,
                    import_id=import_id,
                    revision=revision,
                    license_evidence_hash=license_evidence_hash,
                    provenance_attestation_ref=request.provenance_attestation_ref,
                    provenance_attestation_hash=request.provenance_attestation_hash,
                    contains_third_party_material=request.contains_third_party_material,
                )
        except ValueError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        except RuntimeError as error:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error
        return {
            "operation_id": idempotency_key,
            "status": "COMPLETED",
            "guidance_key": commit.guidance_key,
            "version": commit.version,
            "decision": commit.lifecycle,
            "approval_digest": commit.digest,
        }

    @router.post("/api/v1/skills/{guidance_key}/refresh", status_code=status.HTTP_202_ACCEPTED)
    def refresh_skill(
        guidance_key: str,
        request: SkillRefreshHttpRequest,
        human_identity_token: str | None = Header(default=None, alias="Authorization"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        principal = principal_provider(human_identity_token)
        scope = scope_provider()
        if idempotency_key is None or not 8 <= len(idempotency_key) <= 128:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Idempotency-Key is required")
        # Authorization precedes every lineage read so an unauthorized caller
        # cannot probe lineage existence or head epochs through closed 409s.
        authorization_ref = _require_role(
            connect,
            scope=scope,
            principal=principal,
            role="GUIDANCE_AUTHOR",
            purpose=request.purpose,
            audience=f"skills-refresh:{guidance_key}",
        )
        request_hash = canonical_sha256(
            {
                "scope": scope.canonical_dict(),
                "command_id": request.command_id,
                "guidance_key": guidance_key,
                "expected_head_epoch": request.expected_head_epoch,
                "purpose": request.purpose,
            }
        )
        try:
            # Every ledger and attempt write must be durable before this
            # request can fail, so each store transaction commits on its own:
            # the lease claim commits before the network observation, and a
            # failure record survives the error the connector raises.
            with connect() as connection:
                connection.autocommit = True
                repository = PostgresSkillImportRepository(connection, object_writer=object_writer)
                replay = repository.find_refresh_attempt(
                    scope=scope,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                )
                if replay is not None:
                    if replay.decision == "REFUSED":
                        raise HTTPException(
                            status.HTTP_409_CONFLICT, str(replay.reason_code or "REFRESH_REFUSED")
                        )
                    return {
                        "operation_id": replay.attempt_id,
                        "status": replay.decision,
                        "outcome": replay.outcome,
                        "observed_commit_sha": replay.observed_commit_sha,
                        "observed_subtree_hash": replay.observed_tree_hash,
                    }
                try:
                    (
                        owner_department,
                        repository_ref,
                        upstream_ref,
                        subdirectory,
                        _imported_commit,
                        recorded_subtree_hash,
                        head_epoch,
                    ) = repository.load_refresh_binding(
                        scope=scope,
                        guidance_key=guidance_key,
                        expected_head_epoch=request.expected_head_epoch,
                    )
                except ValueError as error:
                    if str(error) in {"LINEAGE_CONFLICT", "REGISTERED_CONNECTOR_REQUIRED"}:
                        repository.persist_refresh_attempt(
                            scope=scope,
                            idempotency_key=idempotency_key,
                            request_hash=request_hash,
                            guidance_key=guidance_key,
                            expected_head_epoch=request.expected_head_epoch,
                            principal=principal,
                            authorization_ref=authorization_ref,
                            decision="REFUSED",
                            reason_code=str(error),
                        )
                    raise
                authorization_ref = _require_role(
                    connect,
                    scope=scope,
                    principal=principal,
                    role="GUIDANCE_AUTHOR",
                    department=owner_department,
                    purpose=request.purpose,
                    audience=f"skills-refresh:{guidance_key}:{head_epoch}",
                )
                ledger = PostgresRefreshLedger(connection, scope=scope)
                try:
                    lease = ledger.acquire(guidance_key)
                except ValueError as error:
                    repository.persist_refresh_attempt(
                        scope=scope,
                        idempotency_key=idempotency_key,
                        request_hash=request_hash,
                        guidance_key=guidance_key,
                        expected_head_epoch=request.expected_head_epoch,
                        principal=principal,
                        authorization_ref=authorization_ref,
                        decision="REFUSED",
                        reason_code=str(error),
                    )
                    raise
                try:
                    try:
                        observation = repository_connector.observe_ref(
                            repository_ref=repository_ref,
                            upstream_ref=upstream_ref,
                            subdirectory=subdirectory,
                        )
                    except Exception:
                        ledger.record_failure(guidance_key)
                        raise
                    outcome = (
                        "UNCHANGED"
                        if observation.subtree_hash == recorded_subtree_hash
                        else "CHANGED"
                    )
                    ledger.record(
                        guidance_key,
                        upstream_ref=upstream_ref,
                        observation=observation,
                        outcome=outcome,
                    )
                    attempt = repository.persist_refresh_attempt(
                        scope=scope,
                        idempotency_key=idempotency_key,
                        request_hash=request_hash,
                        guidance_key=guidance_key,
                        expected_head_epoch=request.expected_head_epoch,
                        principal=principal,
                        authorization_ref=authorization_ref,
                        decision="COMPLETED",
                        outcome=outcome,
                        observation=observation,
                    )
                finally:
                    ledger.release(guidance_key, token=lease.token)
        except ValueError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
        except (RuntimeError, requests.RequestException) as error:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error
        return {
            "operation_id": attempt.attempt_id,
            "status": "COMPLETED",
            "outcome": outcome,
            "observed_commit_sha": observation.commit_sha,
            "observed_subtree_hash": observation.subtree_hash,
        }

    @router.get("/api/v1/skills/{guidance_key}/lineage")
    def skill_lineage(
        guidance_key: str,
        human_identity_token: str | None = Header(default=None, alias="Authorization"),
    ) -> dict[str, Any]:
        principal = principal_provider(human_identity_token)
        scope = scope_provider()
        _require_skill_reader(connect, scope=scope, principal=principal)
        with connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT approved_version, head_epoch
                     FROM solvan_operability.guidance_current_heads
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND guidance_key=%(guidance_key)s""",
                {**scope.canonical_dict(), "guidance_key": guidance_key},
            )
            head = cursor.fetchone()
            cursor.execute(
                """SELECT version, lifecycle, revision_hash, content_hash, supersedes_version,
                              source_kind, created_at
                     FROM solvan_operability.guidance_revisions
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND guidance_key=%(guidance_key)s
                    ORDER BY created_at""",
                {**scope.canonical_dict(), "guidance_key": guidance_key},
            )
            revisions = [
                {
                    "version": row[0],
                    "lifecycle": row[1],
                    "revision_hash": row[2],
                    "content_hash": row[3],
                    "supersedes": row[4],
                    "source_kind": row[5],
                    "created_at": row[6].isoformat(),
                }
                for row in cursor.fetchall()
            ]
            cursor.execute(
                """SELECT observed_commit_sha,observed_tree_hash,observed_at
                     FROM solvan_operability.skill_upstream_change_notices
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND guidance_key=%(guidance_key)s
                    ORDER BY observed_at DESC""",
                {**scope.canonical_dict(), "guidance_key": guidance_key},
            )
            refresh_notices = [
                {"commit_sha": row[0], "tree_hash": row[1], "observed_at": row[2].isoformat()}
                for row in cursor.fetchall()
            ]
            cursor.execute(
                """SELECT id,guidance_version,revision_digest,suite_version,decision,
                                  passed_cases,failed_cases,receipt_ref,receipt_hash,
                                  evaluator_principal,evaluated_at
                     FROM solvan_operability.guidance_evaluations
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND guidance_key=%(guidance_key)s
                    ORDER BY evaluated_at DESC""",
                {**scope.canonical_dict(), "guidance_key": guidance_key},
            )
            evaluations = [
                {
                    "id": row[0],
                    "version": row[1],
                    "revision_digest": row[2],
                    "suite_version": row[3],
                    "decision": row[4],
                    "passed_cases": row[5],
                    "failed_cases": row[6],
                    "receipt_ref": row[7],
                    "receipt_hash": row[8],
                    "evaluator_principal": row[9],
                    "evaluated_at": row[10].isoformat(),
                }
                for row in cursor.fetchall()
            ]
            cursor.execute(
                """SELECT id,guidance_version,revision_digest,evaluation_ref,
                                  approver_principal,decision,reason,decided_at
                     FROM solvan_operability.guidance_approvals
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND guidance_key=%(guidance_key)s
                    ORDER BY decided_at DESC""",
                {**scope.canonical_dict(), "guidance_key": guidance_key},
            )
            approvals = [
                {
                    "id": row[0],
                    "version": row[1],
                    "revision_digest": row[2],
                    "evaluation_ref": row[3],
                    "approver_principal": row[4],
                    "decision": row[5],
                    "reason": row[6],
                    "decided_at": row[7].isoformat(),
                }
                for row in cursor.fetchall()
            ]
            cursor.execute(
                """SELECT r.attempt_id,r.guidance_version,r.lifecycle_at_export,
                                  r.export_bundle_hash,r.guidance_content_hash,
                                  r.destination_receipt_ref,r.created_at,
                                  r.stale_acknowledged,r.license_policy_result,
                                  r.byte_rescan_result,r.scanner_receipts_json,
                                  r.disclosure_policy_version,r.destination_kind,
                                  r.destination_binding_ref,r.destination_region,
                                  r.destination_receipt_generation,a.purpose,
                                  a.exporter_principal,a.authorization_ref
                     FROM solvan_operability.skill_export_receipts r
                     JOIN solvan_operability.skill_export_attempts a
                       ON (a.organization_id,a.project_id,a.environment_id,a.id)=
                          (r.organization_id,r.project_id,r.environment_id,r.attempt_id)
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s
                      AND r.environment_id=%(environment_id)s
                      AND r.guidance_key=%(guidance_key)s
                    ORDER BY r.created_at DESC""",
                {**scope.canonical_dict(), "guidance_key": guidance_key},
            )
            exports = [
                {
                    "export_id": row[0],
                    "version": row[1],
                    "lifecycle": row[2],
                    "bundle_hash": row[3],
                    "content_hash": row[4],
                    "destination_receipt_ref": row[5],
                    "created_at": row[6].isoformat(),
                    "stale_acknowledged": row[7],
                    "license_policy_result": row[8],
                    "byte_rescan_result": row[9],
                    "scanner_receipts": row[10],
                    "disclosure_policy_version": row[11],
                    "destination_kind": row[12],
                    "destination_binding_ref": row[13],
                    "destination_region": row[14],
                    "destination_receipt_generation": row[15],
                    "purpose": row[16],
                    "exporter_principal": row[17],
                    "authorization_ref": row[18],
                }
                for row in cursor.fetchall()
            ]
        return {
            "guidance_key": guidance_key,
            "current_head": None if head is None else {"version": head[0], "epoch": head[1]},
            "revisions": revisions,
            "refresh_notices": refresh_notices,
            "evaluations": evaluations,
            "approvals": approvals,
            "exports": exports,
        }

    @router.post("/api/v1/skills/{guidance_key}/export", status_code=status.HTTP_202_ACCEPTED)
    def export_skill(
        guidance_key: str,
        request: SkillExportHttpRequest,
        human_identity_token: str | None = Header(default=None, alias="Authorization"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        principal = principal_provider(human_identity_token)
        if idempotency_key is None or not 8 <= len(idempotency_key) <= 128:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Idempotency-Key is required")
        scope = scope_provider()
        request_material = {
            "scope": scope.canonical_dict(),
            "guidance_key": guidance_key,
            "version": request.version,
            "destination_id": request.destination_id,
            "purpose": request.purpose,
            "disclosure_policy_version": "agent-skills-export/1",
            "principal": principal,
            "stale_acknowledged": request.stale_acknowledged,
        }
        request_hash = canonical_sha256({**request_material, "authorization_ref": None})
        # Each receipt commits on its own: the refusal receipts written by the
        # handlers below must survive the HTTPException they re-raise, and the
        # connection must be closed rather than left to garbage collection.
        with connect() as connection:
            connection.autocommit = True
            repository = PostgresSkillImportRepository(connection, object_writer=object_writer)
            try:
                try:
                    authorization_ref = _require_role(
                        connect,
                        scope=scope,
                        principal=principal,
                        role="GUIDANCE_EXPORTER",
                        purpose=request.purpose,
                        audience=f"skills-export:{request.destination_id}",
                    )
                except HTTPException as error:
                    repository.persist_export_refusal(
                        scope=scope,
                        idempotency_key=idempotency_key,
                        request_hash=request_hash,
                        guidance_key=guidance_key,
                        guidance_version=request.version,
                        destination_id=request.destination_id,
                        purpose=request.purpose,
                        exporter_principal=principal,
                        authorization_ref=None,
                        reason_code="EXPORTER_ROLE_REQUIRED",
                    )
                    raise error
                request_hash = canonical_sha256(
                    {**request_material, "authorization_ref": authorization_ref}
                )
                revision, files = revision_provider.read(
                    scope=scope, guidance_key=guidance_key, version=request.version
                )
                try:
                    registered_destination = _require_export_destination(
                        connect,
                        scope=scope,
                        destination_id=request.destination_id,
                        classification=revision.classification,
                    )
                except HTTPException as error:
                    repository.persist_export_refusal(
                        scope=scope,
                        idempotency_key=idempotency_key,
                        request_hash=request_hash,
                        guidance_key=guidance_key,
                        guidance_version=request.version,
                        destination_id=request.destination_id,
                        purpose=request.purpose,
                        exporter_principal=principal,
                        authorization_ref=authorization_ref,
                        reason_code=str(error.detail),
                    )
                    raise error
                policy_version = repository.require_export_license_policy(
                    scope=scope, normalized_identifier=revision.source_license or ""
                )
                request_hash = canonical_sha256(
                    {
                        **request_material,
                        "authorization_ref": authorization_ref,
                        "revision_content_hash": revision.content_hash,
                        "destination_kind": registered_destination.destination_kind,
                        "destination_binding_ref": registered_destination.binding_ref,
                        "destination_region": registered_destination.region,
                        "destination_classification_ceiling": (
                            registered_destination.classification_ceiling
                        ),
                        "license_policy_version": policy_version,
                    }
                )
                replay = repository.find_export_by_idempotency(
                    scope=scope,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                )
                if replay is not None:
                    prior, destination_ref = replay
                    return {
                        "operation_id": prior.export_id,
                        "status": "COMPLETED",
                        "export_id": prior.export_id,
                        "bundle_hash": prior.bundle_hash,
                        "destination_receipt_ref": destination_ref,
                    }
                export_id = repository.prepare_export(
                    scope=scope,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    guidance_key=guidance_key,
                    guidance_version=request.version,
                    destination_id=request.destination_id,
                    purpose=request.purpose,
                    exporter_principal=principal,
                    authorization_ref=authorization_ref,
                )
                bundle, receipt = export_approved_revision(
                    revision=revision,
                    files=files,
                    destination_id=request.destination_id,
                    stale_acknowledged=request.stale_acknowledged,
                    export_id=export_id,
                )
                export_scans = (
                    *scan_export_bytes(bundle, armor=armor),
                    SecurityScanReceipt(
                        scanner="TENANT_LICENSE_POLICY",
                        version=policy_version,
                        verdict="ALLOWED",
                        reason_codes=(),
                        content_hash=receipt.bundle_hash,
                    ),
                )
                require_allowed(export_scans)
                destination = _write_registered_export(
                    destination=registered_destination,
                    scope=scope,
                    export_id=receipt.export_id,
                    content=bundle,
                )
                repository.persist_export(
                    scope=scope,
                    revision=revision,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    destination_id=request.destination_id,
                    exporter_principal=principal,
                    authorization_ref=authorization_ref,
                    receipt=receipt,
                    stale_acknowledged=request.stale_acknowledged,
                    destination_receipt_ref=str(destination.uri),
                    destination_receipt_generation=str(destination.generation),
                    destination_kind=registered_destination.destination_kind,
                    destination_binding_ref=registered_destination.binding_ref,
                    scanner_receipts=export_scans,
                    storage_region=registered_destination.region,
                )
                stored = repository.find_export(scope=scope, request_hash=request_hash)
                final_receipt, final_destination_ref = stored or (receipt, str(destination.uri))
            except ValueError as error:
                with suppress(ValueError):
                    repository.persist_export_refusal(
                        scope=scope,
                        idempotency_key=idempotency_key,
                        request_hash=request_hash,
                        guidance_key=guidance_key,
                        guidance_version=request.version,
                        destination_id=request.destination_id,
                        purpose=request.purpose,
                        exporter_principal=principal,
                        authorization_ref=locals().get("authorization_ref"),
                        reason_code=str(error),
                    )
                raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
            except (RuntimeError, requests.RequestException) as error:
                if "export_id" not in locals():
                    with suppress(ValueError):
                        repository.persist_export_refusal(
                            scope=scope,
                            idempotency_key=idempotency_key,
                            request_hash=request_hash,
                            guidance_key=guidance_key,
                            guidance_version=request.version,
                            destination_id=request.destination_id,
                            purpose=request.purpose,
                            exporter_principal=principal,
                            authorization_ref=locals().get("authorization_ref"),
                            reason_code="EXPORT_PROVIDER_UNAVAILABLE",
                        )
                raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error
            return {
                "operation_id": final_receipt.export_id,
                "status": "COMPLETED",
                "export_id": final_receipt.export_id,
                "bundle_hash": final_receipt.bundle_hash,
                "destination_receipt_ref": final_destination_ref,
            }

    return router


class _UnavailableSkillObjectWriter:
    def put_bytes(self, *, object_name: str, content: bytes, content_type: str) -> Any:
        del object_name, content, content_type
        raise RuntimeError("skills object storage is not configured")


class _UnavailableSkillObjectReader:
    def get_bytes(self, *, uri: str, expected_hash: str, max_bytes: int = 1_048_576) -> bytes:
        del uri, expected_hash, max_bytes
        raise RuntimeError("skills object storage is not configured")


class _UnavailableRepositoryConnector:
    def observe_ref(self, *, repository_ref: str, upstream_ref: str, subdirectory: str) -> Any:
        del repository_ref, upstream_ref, subdirectory
        raise RuntimeError("no registered repository connector is configured")

    def observe_tree(self, *, repository_ref: str, commit_sha: str, subdirectory: str) -> Any:
        del repository_ref, commit_sha, subdirectory
        raise RuntimeError("no registered repository connector is configured")

    def fetch_archive(self, *, repository_ref: str, commit_sha: str, subdirectory: str) -> Any:
        del repository_ref, commit_sha, subdirectory
        raise RuntimeError("no registered repository connector is configured")


class _UnavailableRevisionProvider:
    def read(self, *, scope: Scope, guidance_key: str, version: str) -> Any:
        del scope, guidance_key, version
        raise RuntimeError("guidance revision provider is not configured")


def include_agent_skills_routes(
    app: FastAPI,
    *,
    principal_provider: Callable[[str | None], str],
    reader_principal_provider: Callable[[str | None], str] | None = None,
    scope_provider: Callable[[], Scope],
    connect: Callable[[], Any],
) -> None:
    """Install the target routes with fail-closed provider dependencies."""
    bucket = os.environ.get("SOLVAN_SKILLS_BUCKET")
    writer: ImmutableObjectWriter = (
        GcsEvidenceWriter(bucket=bucket, session=authorized_session())
        if bucket
        else _UnavailableSkillObjectWriter()
    )
    reader: ImmutableObjectReader = (
        GcsEvidenceReader(allowed_buckets=frozenset({bucket}), session=authorized_session())
        if bucket
        else _UnavailableSkillObjectReader()
    )
    repository_connector: RepositoryMetadataConnector = _UnavailableRepositoryConnector()
    provider = os.environ.get("SOLVAN_SKILLS_REPOSITORY_PROVIDER", "").strip().lower()
    if provider == "github":
        github_token = os.environ.get("SOLVAN_GITHUB_INSTALLATION_TOKEN")
        github_installation_id = os.environ.get("SOLVAN_GITHUB_INSTALLATION_ID")
        github_repositories = frozenset(
            item.strip()
            for item in os.environ.get("SOLVAN_GITHUB_REPOSITORIES", "").split(",")
            if item.strip()
        )
        if github_token and github_installation_id and github_repositories:
            try:
                repository_connector = GitHubMetadataConnector(
                    GitHubClient(
                        transport=cast(Any, requests.Session()),
                        token_provider=ConfiguredGitHubTokenProvider(github_token),
                        installation_id=int(github_installation_id),
                        api_base_url=os.environ.get(
                            "SOLVAN_GITHUB_API_BASE_URL", "https://api.github.com"
                        ),
                    ),
                    allowed_repositories=github_repositories,
                )
            except (TypeError, ValueError):
                repository_connector = _UnavailableRepositoryConnector()
    elif provider == "gitlab":
        gitlab_token = os.environ.get("SOLVAN_GITLAB_TOKEN")
        gitlab_repositories = frozenset(
            item.strip()
            for item in os.environ.get("SOLVAN_GITLAB_REPOSITORIES", "").split(",")
            if item.strip()
        )
        if gitlab_token and gitlab_repositories:
            try:
                repository_connector = GitLabMetadataConnector(
                    transport=cast(Any, requests.Session()),
                    token_provider=ConfiguredGitLabTokenProvider(gitlab_token),
                    allowed_repositories=gitlab_repositories,
                    api_base_url=os.environ.get(
                        "SOLVAN_GITLAB_API_BASE_URL", "https://gitlab.com/api/v4"
                    ),
                )
            except ValueError:
                repository_connector = _UnavailableRepositoryConnector()
    revision_provider: RevisionExportProvider = (
        PostgresRevisionExportProvider(connect, object_reader=reader)
        if bucket
        else _UnavailableRevisionProvider()
    )
    armor: ModelArmorScanner = UnavailableModelArmor()
    template = os.environ.get("SOLVAN_SKILLS_MODEL_ARMOR_TEMPLATE")
    if template:
        armor = GoogleModelArmorScanner(
            GoogleModelArmorTextGate(
                template=template,
                region=os.environ.get("SOLVAN_REGION", "europe-west1"),
            )
        )
    app.include_router(
        agent_skills_router(
            principal_provider=principal_provider,
            reader_principal_provider=reader_principal_provider,
            scope_provider=scope_provider,
            connect=connect,
            object_writer=writer,
            object_reader=reader,
            armor=armor,
            repository_connector=repository_connector,
            revision_provider=revision_provider,
        )
    )
