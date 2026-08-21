"""Cloud SQL authority for Agent Skills quarantine imports.

The caller owns the connection and transaction boundary.  The repository
never treats an object-store response as authority: object references are
written before the immutable SQL rows, and the SQL transaction remains the
source of truth for the attempt outcome.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from psycopg import Connection, errors
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.operational_guidance import (
    BlockedBehavior,
    GuidanceIncompatibilityDeclaration,
    GuidanceKind,
    GuidanceLifecycle,
    GuidanceRevision,
    GuidanceSourceKind,
    GuidanceStepKind,
    GuidanceStepRevision,
)
from solvan.application.skills_governance import (
    ExportReceipt,
    RepositoryObservation,
    skill_name_from_key,
)
from solvan.application.skills_interchange import SkillImportInspection, inspect_skill_archive
from solvan.application.skills_interchange_service import (
    SkillImportAttempt,
    SkillImportCommand,
    SkillImportRepository,
)
from solvan.application.skills_security import SecurityScanReceipt, normalize_license
from solvan.domain import Scope, new_identifier


def _license_state(
    *,
    normalized_license: tuple[str, bytes] | None,
    scan_receipts: tuple[Any, ...],
) -> str:
    if normalized_license is None:
        return "MISSING"
    license_receipt = next(
        (receipt for receipt in scan_receipts if receipt.scanner == "LICENSE_POLICY"),
        None,
    )
    if license_receipt is not None and license_receipt.verdict == "DENIED":
        return "REJECTED_BY_POLICY"
    return "PRESENT"


@dataclass(frozen=True, slots=True)
class SkillRefreshAttempt:
    attempt_id: str
    request_hash: str
    decision: str
    outcome: str | None
    observed_commit_sha: str | None
    observed_tree_hash: str | None
    reason_code: str | None


class PostgresRefreshLedger:
    """Cloud SQL token-fenced refresh lease and notice ledger."""

    def __init__(self, connection: Connection[Any], *, scope: Scope) -> None:
        self._connection = connection
        self._scope = scope

    def acquire(self, guidance_key: str, *, now: datetime | None = None) -> Any:
        current = now or datetime.now(UTC)
        token = secrets.token_hex(16)
        expiry = current + timedelta(minutes=5)
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT lease_expires_at,last_checked_at,failure_count
                     FROM solvan_operability.skill_refresh_ledgers
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND guidance_key=%(guidance_key)s
                    FOR UPDATE""",
                {**self._scope.canonical_dict(), "guidance_key": guidance_key},
            )
            existing = cursor.fetchone()
            if existing is not None:
                lease_expires_at, last_checked_at, failure_count = existing
                if lease_expires_at is not None and lease_expires_at > current:
                    raise ValueError("REFRESH_LEASE_HELD")
                if last_checked_at is not None and last_checked_at > current - timedelta(hours=1):
                    raise ValueError("REFRESH_CADENCE_LIMIT")
                if (
                    last_checked_at is not None
                    and last_checked_at > current - timedelta(days=1)
                    and int(failure_count or 0) >= 3
                ):
                    raise ValueError("REFRESH_RETRY_LIMIT")
            cursor.execute(
                """INSERT INTO solvan_operability.skill_refresh_ledgers
                     (organization_id,project_id,environment_id,guidance_key,
                      lease_token,lease_expires_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(guidance_key)s,%(token)s,%(expiry)s)
                   ON CONFLICT (organization_id,project_id,environment_id,guidance_key)
                   DO UPDATE SET lease_token=EXCLUDED.lease_token,
                                 lease_expires_at=EXCLUDED.lease_expires_at
                    WHERE skill_refresh_ledgers.lease_expires_at IS NULL
                       OR skill_refresh_ledgers.lease_expires_at <= %(now)s
                   RETURNING lease_token, lease_expires_at""",
                {
                    **self._scope.canonical_dict(),
                    "guidance_key": guidance_key,
                    "token": token,
                    "expiry": expiry,
                    "now": current,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise ValueError("REFRESH_LEASE_HELD")
        from solvan.application.skills_governance import RefreshLease

        return RefreshLease(str(row[0]), row[1])

    def release(self, guidance_key: str, *, token: str) -> None:
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_operability.skill_refresh_ledgers
                      SET lease_token=NULL, lease_expires_at=NULL
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND guidance_key=%(guidance_key)s AND lease_token=%(token)s""",
                {**self._scope.canonical_dict(), "guidance_key": guidance_key, "token": token},
            )
            if cursor.rowcount != 1:
                raise ValueError("REFRESH_LEASE_FENCE")

    def record(
        self,
        guidance_key: str,
        *,
        upstream_ref: str,
        observation: RepositoryObservation,
        outcome: str,
        now: datetime | None = None,
    ) -> None:
        current = now or datetime.now(UTC)
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_operability.skill_refresh_ledgers
                      SET last_checked_at=%(now)s, last_outcome=%(outcome)s,
                          failure_count=0
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND guidance_key=%(guidance_key)s""",
                {
                    **self._scope.canonical_dict(),
                    "guidance_key": guidance_key,
                    "outcome": outcome,
                    "now": current,
                },
            )
            if outcome == "CHANGED":
                cursor.execute(
                    """INSERT INTO solvan_operability.skill_upstream_change_notices
                         (organization_id,project_id,environment_id,id,guidance_key,
                          upstream_ref,observed_commit_sha,observed_tree_hash,observed_at)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                               %(guidance_key)s,%(upstream_ref)s,%(commit)s,%(tree)s,%(now)s)
                       ON CONFLICT DO NOTHING""",
                    {
                        **self._scope.canonical_dict(),
                        "id": new_identifier("suc"),
                        "guidance_key": guidance_key,
                        "upstream_ref": upstream_ref,
                        "commit": observation.commit_sha,
                        "tree": observation.subtree_hash,
                        "now": current,
                    },
                )

    def record_failure(self, guidance_key: str, *, now: datetime | None = None) -> None:
        current = now or datetime.now(UTC)
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """UPDATE solvan_operability.skill_refresh_ledgers
                      SET last_checked_at=%(now)s, last_outcome='FAILED',
                          failure_count=failure_count+1
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND guidance_key=%(guidance_key)s""",
                {**self._scope.canonical_dict(), "guidance_key": guidance_key, "now": current},
            )


class ImmutableObjectWriter(Protocol):
    def put_bytes(self, *, object_name: str, content: bytes, content_type: str) -> Any: ...


class ImmutableObjectReader(Protocol):
    def get_bytes(self, *, uri: str, expected_hash: str, max_bytes: int = 1_048_576) -> bytes: ...


class PostgresRevisionExportProvider:
    """Rehydrate an approved revision and its immutable prompt files from Cloud SQL."""

    def __init__(
        self,
        connect: Callable[[], Connection[Any]],
        *,
        object_reader: ImmutableObjectReader,
    ) -> None:
        self._connect = connect
        self._object_reader = object_reader

    def read(
        self, *, scope: Scope, guidance_key: str, version: str
    ) -> tuple[GuidanceRevision, tuple[Any, ...]]:
        with self._connect() as connection, connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT r.*,d.display_name,d.owner_department
                     FROM solvan_operability.guidance_revisions r
                     JOIN solvan_operability.guidance_definitions d USING
                       (organization_id,project_id,environment_id,guidance_key)
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s AND r.environment_id=%(environment_id)s
                      AND r.guidance_key=%(guidance_key)s AND r.version=%(version)s""",
                {**scope.canonical_dict(), "guidance_key": guidance_key, "version": version},
            )
            row = cursor.fetchone()
            if row is None:
                raise ValueError("REVISION_NOT_FOUND")
            cursor.execute(
                """SELECT step_key,ordinal,title,objective,step_kind,
                              prerequisite_step_keys_json,completion_predicate_key,
                              completion_predicate_version,required_evidence_kinds_json,
                              maximum_tool_requests,on_blocked
                     FROM solvan_operability.guidance_steps
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND guidance_key=%(guidance_key)s
                      AND guidance_version=%(version)s ORDER BY ordinal""",
                {**scope.canonical_dict(), "guidance_key": guidance_key, "version": version},
            )
            step_rows = cursor.fetchall()
            cursor.execute(
                """SELECT agent_key FROM solvan_operability.guidance_revision_agents
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND guidance_key=%(guidance_key)s
                      AND guidance_version=%(version)s ORDER BY agent_key""",
                {**scope.canonical_dict(), "guidance_key": guidance_key, "version": version},
            )
            agent_rows = cursor.fetchall()
            cursor.execute(
                """SELECT step_key,tool_key,tool_version
                    FROM solvan_operability.guidance_step_tools
                   WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                     AND environment_id=%(environment_id)s AND guidance_key=%(guidance_key)s
                     AND guidance_version=%(version)s ORDER BY step_key,tool_key,tool_version""",
                {**scope.canonical_dict(), "guidance_key": guidance_key, "version": version},
            )
            tool_rows = cursor.fetchall()
            cursor.execute(
                """SELECT profile_key,profile_version
                    FROM solvan_operability.guidance_revision_profiles
                   WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                     AND environment_id=%(environment_id)s AND guidance_key=%(guidance_key)s
                     AND guidance_version=%(version)s ORDER BY profile_key,profile_version""",
                {**scope.canonical_dict(), "guidance_key": guidance_key, "version": version},
            )
            profile_rows = cursor.fetchall()
            cursor.execute(
                """SELECT incompatible_guidance_key,reason_code
                     FROM solvan_operability.guidance_incompatibilities
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND declaring_guidance_key=%(guidance_key)s
                      AND declaring_version=%(version)s
                    ORDER BY incompatible_guidance_key""",
                {**scope.canonical_dict(), "guidance_key": guidance_key, "version": version},
            )
            incompatibility_rows = cursor.fetchall()
            content_ref = str(row["content_ref"])
            if not content_ref.startswith("skill-import:"):
                raise ValueError("REVISION_CONTENT_REF_UNSUPPORTED")
            attempt_id = content_ref.removeprefix("skill-import:").split("/", 1)[0]
            cursor.execute(
                """SELECT i.id,i.guidance_content_hash
                     FROM solvan_operability.skill_imports i
                    WHERE i.organization_id=%(organization_id)s AND i.project_id=%(project_id)s
                      AND i.environment_id=%(environment_id)s AND i.attempt_id=%(attempt_id)s""",
                {**scope.canonical_dict(), "attempt_id": attempt_id},
            )
            import_row = cursor.fetchone()
            if import_row is None or str(import_row["guidance_content_hash"]) != str(
                row["content_hash"]
            ):
                raise ValueError("REVISION_CONTENT_BINDING_INVALID")
            cursor.execute(
                """SELECT path,object_ref,content_hash,disposition
                     FROM solvan_operability.skill_import_files
                    WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s AND import_id=%(import_id)s
                    ORDER BY path""",
                {**scope.canonical_dict(), "import_id": import_row["id"]},
            )
            file_rows = cursor.fetchall()
        from solvan.application.skills_interchange import SkillFile, SkillFileDisposition

        files = tuple(
            SkillFile(
                path=str(file["path"]),
                content=self._object_reader.get_bytes(
                    uri=str(file["object_ref"]), expected_hash=str(file["content_hash"])
                ),
                disposition=SkillFileDisposition(str(file["disposition"])),
            )
            for file in file_rows
        )
        tools_by_step: dict[str, tuple[str, ...]] = {}
        for tool in tool_rows:
            tools_by_step.setdefault(str(tool["step_key"]), tuple())
            tools_by_step[str(tool["step_key"])] += (f"{tool['tool_key']}@{tool['tool_version']}",)
        steps = tuple(
            GuidanceStepRevision(
                step_key=str(step["step_key"]),
                ordinal=int(step["ordinal"]),
                title=str(step["title"]),
                objective=str(step["objective"]),
                step_kind=GuidanceStepKind(str(step["step_kind"])),
                allowed_tool_revisions=tools_by_step.get(str(step["step_key"]), ()),
                prerequisite_step_keys=tuple(step["prerequisite_step_keys_json"]),
                completion_predicate_key=str(step["completion_predicate_key"]),
                completion_predicate_version=str(step["completion_predicate_version"]),
                required_evidence_kinds=tuple(step["required_evidence_kinds_json"]),
                maximum_tool_requests=int(step["maximum_tool_requests"]),
                on_blocked=BlockedBehavior(str(step["on_blocked"])),
            )
            for step in step_rows
        )
        revision = GuidanceRevision(
            guidance_key=str(row["guidance_key"]),
            version=str(row["version"]),
            display_name=str(row["display_name"]),
            description=str(row["description"]),
            owner_department=str(row["owner_department"]),
            discoverable_departments=tuple(row["discoverable_departments_json"]),
            guidance_kind=GuidanceKind(str(row["guidance_kind"])),
            applicable_service_kinds=tuple(row["applicable_service_kinds_json"]),
            applicable_incident_classes=tuple(row["applicable_incident_classes_json"]),
            symptom_tags=tuple(row["symptom_tags"]),
            purpose=str(row["purpose"]),
            classification=str(row["classification"]),
            eligible_regions=tuple(row["eligible_regions_json"]),
            allowed_agent_keys=tuple(agent["agent_key"] for agent in agent_rows),
            required_profile_revisions=tuple(
                f"{profile['profile_key']}@{profile['profile_version']}" for profile in profile_rows
            ),
            steps=steps,
            content_ref=str(row["content_ref"]),
            content_hash=str(row["content_hash"]),
            source_kind=GuidanceSourceKind(str(row["source_kind"])),
            source_ref=str(row["source_ref"]),
            source_license=None if row["source_license"] is None else str(row["source_license"]),
            incompatibilities=tuple(
                GuidanceIncompatibilityDeclaration(
                    guidance_key=str(item["incompatible_guidance_key"]),
                    reason_code=str(item["reason_code"]),
                )
                for item in incompatibility_rows
            ),
            evaluation_ref=None if row["evaluation_ref"] is None else str(row["evaluation_ref"]),
            approval_ref=None if row["approval_ref"] is None else str(row["approval_ref"]),
            author_principal=str(row["author_principal"]),
            approved_by_principal=(
                None if row["approved_by_principal"] is None else str(row["approved_by_principal"])
            ),
            approved_at=row["approved_at"],
            supersedes=(
                None
                if row["supersedes_version"] is None
                else f"{guidance_key}@{row['supersedes_version']}"
            ),
            lifecycle=GuidanceLifecycle(str(row["lifecycle"])),
        )
        return revision, files


class PostgresSkillImportRepository(SkillImportRepository):
    def __init__(
        self, connection: Connection[Any], *, object_writer: ImmutableObjectWriter
    ) -> None:
        self._connection = connection
        self._object_writer = object_writer

    @property
    def connection(self) -> Connection[Any]:
        return self._connection

    def find_refresh_attempt(
        self, *, scope: Scope, idempotency_key: str, request_hash: str
    ) -> SkillRefreshAttempt | None:
        """Replay an exact refresh command and reject key reuse with changed material."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,refresh_request_hash,decision,outcome,
                          observed_commit_sha,observed_tree_hash,reason_code
                     FROM solvan_operability.skill_refresh_attempts
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND idempotency_key=%(idempotency_key)s""",
                {**scope.canonical_dict(), "idempotency_key": idempotency_key},
            )
            row = cursor.fetchone()
        if row is None:
            return None
        if str(row["refresh_request_hash"]) != request_hash:
            raise ValueError("IDEMPOTENCY_CONFLICT")
        return SkillRefreshAttempt(
            attempt_id=str(row["id"]),
            request_hash=str(row["refresh_request_hash"]),
            decision=str(row["decision"]),
            outcome=None if row["outcome"] is None else str(row["outcome"]),
            observed_commit_sha=(
                None if row["observed_commit_sha"] is None else str(row["observed_commit_sha"])
            ),
            observed_tree_hash=(
                None if row["observed_tree_hash"] is None else str(row["observed_tree_hash"])
            ),
            reason_code=None if row["reason_code"] is None else str(row["reason_code"]),
        )

    def persist_refresh_attempt(
        self,
        *,
        scope: Scope,
        idempotency_key: str,
        request_hash: str,
        guidance_key: str,
        expected_head_epoch: int,
        principal: str,
        authorization_ref: str,
        decision: str = "COMPLETED",
        outcome: str | None = None,
        observation: RepositoryObservation | None = None,
        reason_code: str | None = None,
    ) -> SkillRefreshAttempt:
        if decision == "COMPLETED" and (outcome is None or observation is None):
            raise RuntimeError("REFRESH_ATTEMPT_INCOMPLETE")
        if decision == "REFUSED" and reason_code is None:
            raise RuntimeError("REFRESH_ATTEMPT_INCOMPLETE")
        attempt_id = new_identifier("sra")
        try:
            with self._connection.transaction(), self._connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO solvan_operability.skill_refresh_attempts
                         (organization_id,project_id,environment_id,id,idempotency_key,
                          refresh_request_hash,guidance_key,expected_head_epoch,decision,outcome,
                          observed_commit_sha,observed_tree_hash,reason_code,
                          requester_principal,authorization_ref)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                               %(idempotency_key)s,%(request_hash)s,%(guidance_key)s,%(head_epoch)s,
                               %(decision)s,%(outcome)s,%(commit)s,%(tree)s,%(reason)s,
                               %(principal)s,%(authorization)s)
                       ON CONFLICT (organization_id,project_id,environment_id,idempotency_key)
                       DO NOTHING""",
                    {
                        **scope.canonical_dict(),
                        "id": attempt_id,
                        "idempotency_key": idempotency_key,
                        "request_hash": request_hash,
                        "guidance_key": guidance_key,
                        "head_epoch": expected_head_epoch,
                        "decision": decision,
                        "outcome": outcome,
                        "commit": None if observation is None else observation.commit_sha,
                        "tree": None if observation is None else observation.subtree_hash,
                        "reason": reason_code,
                        "principal": principal,
                        "authorization": authorization_ref,
                    },
                )
        except errors.UniqueViolation as error:
            raise ValueError("IDEMPOTENCY_CONFLICT") from error
        stored = self.find_refresh_attempt(
            scope=scope, idempotency_key=idempotency_key, request_hash=request_hash
        )
        if stored is None:
            raise RuntimeError("refresh attempt was not persisted")
        return stored

    @staticmethod
    def _scan_receipts(value: Any) -> tuple[SecurityScanReceipt, ...]:
        if not isinstance(value, list):
            raise RuntimeError("SCANNER_RECEIPTS_MALFORMED")
        receipts: list[SecurityScanReceipt] = []
        for item in value:
            if not isinstance(item, dict) or not all(
                key in item for key in ("scanner", "version", "verdict", "content_hash")
            ):
                raise RuntimeError("SCANNER_RECEIPTS_MALFORMED")
            receipts.append(
                SecurityScanReceipt(
                    scanner=str(item["scanner"]),
                    version=str(item["version"]),
                    verdict=str(item["verdict"]),
                    reason_codes=tuple(str(code) for code in item.get("reason_codes", [])),
                    content_hash=str(item["content_hash"]),
                )
            )
        return tuple(receipts)

    def load_inspection(
        self, *, scope: Scope, import_id: str, reader: ImmutableObjectReader
    ) -> SkillImportInspection:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT i.package_object_ref, i.package_object_hash,
                          i.source_bundle_hash, a.decision
                     FROM solvan_operability.skill_imports i
                     JOIN solvan_operability.skill_import_attempts a
                       ON a.organization_id=i.organization_id
                      AND a.project_id=i.project_id
                      AND a.environment_id=i.environment_id
                      AND a.id=i.attempt_id
                    WHERE i.organization_id=%(organization_id)s
                      AND i.project_id=%(project_id)s
                      AND i.environment_id=%(environment_id)s
                      AND i.attempt_id=%(import_id)s""",
                {**scope.canonical_dict(), "import_id": import_id},
            )
            row = cursor.fetchone()
        if row is None or row["decision"] != "QUARANTINED":
            raise ValueError("IMPORT_NOT_QUARANTINED")
        source_hash = row["source_bundle_hash"]
        object_hash = row["package_object_hash"]
        if not isinstance(source_hash, str) or not isinstance(object_hash, str):
            raise ValueError("SOURCE_HASH_MISSING")
        archive = reader.get_bytes(
            uri=str(row["package_object_ref"]), expected_hash=object_hash, max_bytes=1_048_576
        )
        inspection = inspect_skill_archive(archive)
        if inspection.source_bundle_hash != source_hash:
            raise ValueError("SOURCE_HASH_MISMATCH")
        return inspection

    def require_compile_context(
        self,
        *,
        scope: Scope,
        import_id: str,
        guidance_key: str,
        owner_department: str,
        normalized_license_identifier: str,
        source_classification: GuidanceSourceKind,
        provenance_attestation_ref: str | None,
        provenance_attestation_hash: str | None,
        contains_third_party_material: bool,
    ) -> str:
        """Validate license, owner-key, and first-party provenance before drafting."""

        skill_name_from_key(guidance_key)
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT a.source_kind,i.license_state,i.normalized_license_identifier,
                          i.license_evidence_hash,
                          p.import_allowed,p.enabled,s.owner_slug
                     FROM solvan_operability.skill_imports i
                     JOIN solvan_operability.skill_import_attempts a ON
                       (a.organization_id,a.project_id,a.environment_id,a.id)=
                       (i.organization_id,i.project_id,i.environment_id,i.attempt_id)
                     LEFT JOIN solvan_operability.skill_license_policies p ON
                       p.organization_id=i.organization_id
                      AND p.project_id=i.project_id
                      AND p.environment_id=i.environment_id
                      AND p.normalized_identifier=i.normalized_license_identifier
                     JOIN solvan_operability.skill_owner_department_slugs s ON
                       s.organization_id=i.organization_id
                      AND s.project_id=i.project_id
                      AND s.environment_id=i.environment_id
                      AND s.owner_department=%(owner_department)s
                      AND s.retired_at IS NULL
                    WHERE i.organization_id=%(organization_id)s
                      AND i.project_id=%(project_id)s
                      AND i.environment_id=%(environment_id)s
                      AND i.attempt_id=%(import_id)s""",
                {
                    **scope.canonical_dict(),
                    "import_id": import_id,
                    "owner_department": owner_department,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise ValueError("COMPILE_POLICY_NOT_REGISTERED")
        if row["license_state"] == "REJECTED_BY_POLICY":
            raise ValueError("LICENSE_POLICY_DENIED")
        if row["license_state"] != "PRESENT" or not row["license_evidence_hash"]:
            raise ValueError("LICENSE_MISSING")
        if str(row["normalized_license_identifier"]) != normalized_license_identifier:
            raise ValueError("LICENSE_IDENTIFIER_MISMATCH")
        if row["enabled"] is None:
            raise ValueError("COMPILE_POLICY_NOT_REGISTERED")
        if not row["enabled"] or not row["import_allowed"]:
            raise ValueError("LICENSE_POLICY_DENIED")
        if guidance_key.partition(".")[0] != str(row["owner_slug"]):
            raise ValueError("GUIDANCE_OWNER_KEY_MISMATCH")
        if source_classification is GuidanceSourceKind.SOLVAN_AUTHORED:
            if (
                row["source_kind"] != "FIRST_PARTY"
                or provenance_attestation_ref is None
                or provenance_attestation_hash is None
                or contains_third_party_material
            ):
                raise ValueError("FIRST_PARTY_PROVENANCE_REQUIRED")
        elif (provenance_attestation_ref is None) != (provenance_attestation_hash is None):
            raise ValueError("FIRST_PARTY_PROVENANCE_INCOMPLETE")
        return str(row["license_evidence_hash"])

    def persist_compile_binding(
        self,
        *,
        scope: Scope,
        import_id: str,
        revision: GuidanceRevision,
        license_evidence_hash: str,
        provenance_attestation_ref: str | None,
        provenance_attestation_hash: str | None,
        contains_third_party_material: bool,
    ) -> None:
        """Bind the immutable quarantine evidence to the exact reviewable draft."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """INSERT INTO solvan_operability.guidance_skill_bindings
                     (organization_id,project_id,environment_id,guidance_key,
                      guidance_version,import_attempt_id,normalized_license_identifier,
                      license_evidence_hash,source_classification,
                      provenance_attestation_ref,provenance_attestation_hash,
                      contains_third_party_material,reviewable_digest,compiled_by_principal)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(guidance_key)s,%(version)s,%(import_id)s,%(license)s,
                           %(license_hash)s,%(source_classification)s,%(attestation_ref)s,
                           %(attestation_hash)s,%(third_party)s,%(digest)s,%(principal)s)
                   ON CONFLICT (organization_id,project_id,environment_id,guidance_key,
                                guidance_version) DO NOTHING""",
                {
                    **scope.canonical_dict(),
                    "guidance_key": revision.guidance_key,
                    "version": revision.version,
                    "import_id": import_id,
                    "license": revision.source_license,
                    "license_hash": license_evidence_hash,
                    "source_classification": revision.source_kind.value,
                    "attestation_ref": provenance_attestation_ref,
                    "attestation_hash": provenance_attestation_hash,
                    "third_party": contains_third_party_material,
                    "digest": revision.approval_digest,
                    "principal": revision.author_principal,
                },
            )
            cursor.execute(
                """SELECT import_attempt_id,normalized_license_identifier,
                          license_evidence_hash,source_classification,
                          provenance_attestation_ref,provenance_attestation_hash,
                          contains_third_party_material,reviewable_digest,
                          compiled_by_principal
                     FROM solvan_operability.guidance_skill_bindings
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND guidance_key=%(guidance_key)s AND guidance_version=%(version)s""",
                {
                    **scope.canonical_dict(),
                    "guidance_key": revision.guidance_key,
                    "version": revision.version,
                },
            )
            stored = cursor.fetchone()
        expected = (
            import_id,
            revision.source_license,
            license_evidence_hash,
            revision.source_kind.value,
            provenance_attestation_ref,
            provenance_attestation_hash,
            contains_third_party_material,
            revision.approval_digest,
            revision.author_principal,
        )
        if stored is None or tuple(stored.values()) != expected:
            raise ValueError("COMPILE_IDEMPOTENCY_CONFLICT")

    def find_by_request_hash(self, *, scope: Scope, request_hash: str) -> SkillImportAttempt | None:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id, import_request_hash, decision, reason_codes_json,
                                  scanner_receipts_json
                   FROM solvan_operability.skill_import_attempts
                  WHERE organization_id=%(organization_id)s
                    AND project_id=%(project_id)s
                    AND environment_id=%(environment_id)s
                    AND import_request_hash=%(request_hash)s""",
                {**scope.canonical_dict(), "request_hash": request_hash},
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return SkillImportAttempt(
            attempt_id=str(row["id"]),
            import_request_hash=str(row["import_request_hash"]),
            decision=str(row["decision"]),
            reason_codes=tuple(str(value) for value in row["reason_codes_json"]),
            inspection=None,
            scan_receipts=self._scan_receipts(row["scanner_receipts_json"]),
        )

    def persist_attempt(
        self,
        *,
        scope: Scope,
        request: SkillImportCommand,
        request_hash: str,
        outcome: SkillImportAttempt,
        archive: bytes,
    ) -> SkillImportAttempt:
        existing = self.find_by_request_hash(scope=scope, request_hash=request_hash)
        if existing is not None:
            return existing
        attempt_id = new_identifier("sia")
        params = {
            **scope.canonical_dict(),
            "id": attempt_id,
            "request_hash": request_hash,
            "idempotency_key": request.idempotency_key or request.command_id,
            "source_kind": request.source_kind,
            "source_ref": request.source_ref,
            "purpose": request.purpose,
            "classification": request.classification,
            "region": request.region,
            "decision": outcome.decision,
            "reasons": Jsonb(list(outcome.reason_codes)),
            "scanners": Jsonb(
                [
                    {
                        "scanner": receipt.scanner,
                        "version": receipt.version,
                        "verdict": receipt.verdict,
                        "reason_codes": list(receipt.reason_codes),
                        "content_hash": receipt.content_hash,
                    }
                    for receipt in outcome.scan_receipts
                ]
            ),
            "principal": request.principal,
            "authorization_ref": request.authorization_ref,
        }
        try:
            with self._connection.transaction(), self._connection.cursor() as cursor:
                cursor.execute(
                    """SELECT id, import_request_hash, decision, reason_codes_json,
                                      scanner_receipts_json
                         FROM solvan_operability.skill_import_attempts
                        WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND idempotency_key=%(idempotency_key)s
                        FOR UPDATE""",
                    {**scope.canonical_dict(), "idempotency_key": params["idempotency_key"]},
                )
                prior = cursor.fetchone()
                if prior is not None:
                    if str(prior[1]) != request_hash:
                        raise ValueError("IDEMPOTENCY_CONFLICT")
                    return SkillImportAttempt(
                        attempt_id=str(prior[0]),
                        import_request_hash=str(prior[1]),
                        decision=str(prior[2]),
                        reason_codes=tuple(str(value) for value in prior[3]),
                        inspection=None,
                        scan_receipts=self._scan_receipts(prior[4]),
                    )
                cursor.execute(
                    """INSERT INTO solvan_operability.skill_import_attempts
                           (organization_id,project_id,environment_id,id,import_request_hash,
                            idempotency_key,source_kind,source_ref,purpose,requested_classification,
                            requested_region,decision,reason_codes_json,scanner_receipts_json,
                            importer_principal,authorization_ref)
                           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                            %(id)s,%(request_hash)s,%(idempotency_key)s,%(source_kind)s,
                            %(source_ref)s,%(purpose)s,
                            %(classification)s,%(region)s,%(decision)s,%(reasons)s,%(scanners)s,
                            %(principal)s,%(authorization_ref)s)
                           ON CONFLICT
                             (organization_id,project_id,environment_id,import_request_hash)
                           DO NOTHING""",
                    params,
                )
                inserted = cursor.rowcount == 1
                cursor.execute(
                    """SELECT id, import_request_hash, decision, reason_codes_json,
                                      scanner_receipts_json
                           FROM solvan_operability.skill_import_attempts
                          WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                            AND environment_id=%(environment_id)s
                            AND import_request_hash=%(request_hash)s""",
                    {**scope.canonical_dict(), "request_hash": request_hash},
                )
                stored = cursor.fetchone()
                if stored is None:
                    raise RuntimeError("skill import attempt was not persisted")
                attempt_id = str(stored[0])
                decision = str(stored[2])
                reasons = tuple(str(value) for value in stored[3])
                scan_receipts = self._scan_receipts(stored[4])
                if inserted and decision == "QUARANTINED" and outcome.inspection is not None:
                    self._persist_quarantine(
                        cursor=cursor,
                        scope=scope,
                        request=request,
                        attempt_id=attempt_id,
                        inspection=outcome.inspection,
                        archive=archive,
                        scan_receipts=outcome.scan_receipts,
                    )
        except errors.UniqueViolation as error:
            # The FOR UPDATE pre-check cannot lock an absent row, so a
            # concurrent writer reusing the idempotency key surfaces here.
            conflict = self.find_by_request_hash(scope=scope, request_hash=request_hash)
            if conflict is not None:
                return conflict
            raise ValueError("IDEMPOTENCY_CONFLICT") from error
        return SkillImportAttempt(
            attempt_id=attempt_id,
            import_request_hash=request_hash,
            decision=decision,
            reason_codes=reasons,
            inspection=outcome.inspection if decision == "QUARANTINED" else None,
            scan_receipts=scan_receipts,
        )

    def prepare_export(
        self,
        *,
        scope: Scope,
        idempotency_key: str,
        request_hash: str,
        guidance_key: str,
        guidance_version: str,
        destination_id: str,
        purpose: str,
        exporter_principal: str,
        authorization_ref: str,
    ) -> str:
        """Commit a stable export identity before any destination side effect.

        The durable arbiter is the export request hash: the same material
        always resolves to its one stored attempt, whatever idempotency key
        carries the retry, and a reused key with changed material conflicts.
        """

        attempt_id = new_identifier("sea")
        try:
            with self._connection.transaction(), self._connection.cursor() as cursor:
                cursor.execute(
                    """SELECT id,export_request_hash,decision,reason_code
                         FROM solvan_operability.skill_export_attempts
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND idempotency_key=%(idempotency_key)s FOR UPDATE""",
                    {**scope.canonical_dict(), "idempotency_key": idempotency_key},
                )
                row = cursor.fetchone()
                if row is not None and str(row[1]) != request_hash:
                    raise ValueError("IDEMPOTENCY_CONFLICT")
                if row is None:
                    cursor.execute(
                        """SELECT id,export_request_hash,decision,reason_code
                             FROM solvan_operability.skill_export_attempts
                            WHERE organization_id=%(organization_id)s
                              AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                              AND export_request_hash=%(request_hash)s FOR UPDATE""",
                        {**scope.canonical_dict(), "request_hash": request_hash},
                    )
                    row = cursor.fetchone()
                if row is not None:
                    if str(row[2]) in {"REJECTED", "CONFLICT"}:
                        raise ValueError(str(row[3] or "EXPORT_REFUSED"))
                    return str(row[0])
                cursor.execute(
                    """INSERT INTO solvan_operability.skill_export_attempts
                       (organization_id,project_id,environment_id,id,idempotency_key,
                        export_request_hash,guidance_key,guidance_version,destination_id,
                        purpose,decision,exporter_principal,authorization_ref)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                               %(idempotency_key)s,%(request_hash)s,%(guidance_key)s,%(version)s,
                               %(destination)s,%(purpose)s,'PREPARED',%(principal)s,%(authorization)s)
                       ON CONFLICT (organization_id,project_id,environment_id,idempotency_key)
                       DO NOTHING""",
                    {
                        **scope.canonical_dict(),
                        "id": attempt_id,
                        "idempotency_key": idempotency_key,
                        "request_hash": request_hash,
                        "guidance_key": guidance_key,
                        "version": guidance_version,
                        "destination": destination_id,
                        "principal": exporter_principal,
                        "purpose": purpose,
                        "authorization": authorization_ref,
                    },
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("export preparation was not persisted")
            return attempt_id
        except errors.UniqueViolation as error:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    """SELECT id,decision,reason_code
                         FROM solvan_operability.skill_export_attempts
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND export_request_hash=%(request_hash)s""",
                    {**scope.canonical_dict(), "request_hash": request_hash},
                )
                racer = cursor.fetchone()
            if racer is not None:
                if str(racer[1]) in {"REJECTED", "CONFLICT"}:
                    raise ValueError(str(racer[2] or "EXPORT_REFUSED")) from error
                return str(racer[0])
            raise ValueError("IDEMPOTENCY_CONFLICT") from error

    def persist_export(
        self,
        *,
        scope: Scope,
        revision: GuidanceRevision,
        idempotency_key: str,
        request_hash: str,
        destination_id: str,
        exporter_principal: str,
        authorization_ref: str,
        receipt: ExportReceipt,
        stale_acknowledged: bool,
        destination_receipt_ref: str | None,
        destination_receipt_generation: str | None,
        destination_kind: str,
        destination_binding_ref: str,
        scanner_receipts: tuple[SecurityScanReceipt, ...],
        storage_region: str,
    ) -> ExportReceipt:
        """Commit one export attempt and its immutable receipt atomically."""
        license_receipt = next(
            (item for item in scanner_receipts if item.scanner == "TENANT_LICENSE_POLICY"), None
        )
        rescan_receipts = tuple(
            item
            for item in scanner_receipts
            if item.scanner in {"SECRET_SCANNER", "PII_SCANNER", "MODEL_ARMOR"}
        )
        if license_receipt is None or {item.scanner for item in rescan_receipts} != {
            "SECRET_SCANNER",
            "PII_SCANNER",
            "MODEL_ARMOR",
        }:
            raise ValueError("EXPORT_SCAN_RECEIPTS_INCOMPLETE")
        license_policy_result = license_receipt.verdict
        byte_rescan_result = (
            "ALLOWED" if all(item.verdict == "ALLOWED" for item in rescan_receipts) else "DENIED"
        )
        if license_policy_result != "ALLOWED" or byte_rescan_result != "ALLOWED":
            raise ValueError("EXPORT_SCAN_REFUSED")
        with self._connection.transaction(), self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT export_request_hash,decision,guidance_key,guidance_version,
                          destination_id,exporter_principal,authorization_ref
                     FROM solvan_operability.skill_export_attempts
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(id)s FOR UPDATE""",
                {**scope.canonical_dict(), "id": receipt.export_id},
            )
            prepared = cursor.fetchone()
            prior = self._stored_export(cursor=cursor, scope=scope, request_hash=request_hash)
            if prior is not None:
                return prior
            if prepared is None or tuple(str(value) for value in prepared) != (
                request_hash,
                "PREPARED",
                revision.guidance_key,
                revision.version,
                destination_id,
                exporter_principal,
                authorization_ref,
            ):
                raise ValueError("EXPORT_PREPARATION_MISMATCH")
            retention_days, retention_region = self._retention_policy(
                cursor=cursor, scope=scope, requested_region=storage_region
            )
            retention_until = datetime.now(UTC) + timedelta(days=retention_days)
            cursor.execute(
                """INSERT INTO solvan_operability.skill_export_receipts
                   (organization_id,project_id,environment_id,attempt_id,guidance_key,
                    guidance_version,lifecycle_at_export,export_request_hash,export_bundle_hash,
                    guidance_content_hash,stale_acknowledged,license_policy_result,byte_rescan_result,
                    scanner_receipts_json,disclosure_policy_version,destination_kind,
                    destination_binding_ref,destination_region,destination_receipt_ref,
                    destination_receipt_generation)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                           %(guidance_key)s,%(version)s,%(lifecycle)s,%(request_hash)s,
                           %(bundle_hash)s,%(content_hash)s,%(stale_acknowledged)s,
                           %(license_policy_result)s,%(byte_rescan_result)s,
                           %(scanner_receipts)s,'agent-skills-export/1',%(destination_kind)s,
                           %(destination_binding_ref)s,%(destination_region)s,
                           %(destination_receipt)s,%(destination_generation)s)
                   ON CONFLICT DO NOTHING""",
                {
                    **scope.canonical_dict(),
                    "id": receipt.export_id,
                    "guidance_key": revision.guidance_key,
                    "version": revision.version,
                    "lifecycle": revision.lifecycle.value,
                    "request_hash": request_hash,
                    "bundle_hash": receipt.bundle_hash,
                    "content_hash": receipt.content_hash,
                    "stale_acknowledged": stale_acknowledged,
                    "license_policy_result": license_policy_result,
                    "byte_rescan_result": byte_rescan_result,
                    "scanner_receipts": Jsonb(
                        [
                            {
                                "scanner": item.scanner,
                                "version": item.version,
                                "verdict": item.verdict,
                                "reason_codes": list(item.reason_codes),
                                "content_hash": item.content_hash,
                            }
                            for item in scanner_receipts
                        ]
                    ),
                    "destination_kind": destination_kind,
                    "destination_binding_ref": destination_binding_ref,
                    "destination_region": storage_region,
                    "destination_receipt": destination_receipt_ref,
                    "destination_generation": destination_receipt_generation,
                },
            )
            cursor.execute(
                """UPDATE solvan_operability.skill_export_attempts
                      SET decision='EXPORTED'
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND id=%(id)s AND decision='PREPARED'""",
                {**scope.canonical_dict(), "id": receipt.export_id},
            )
            if cursor.rowcount != 1:
                raise ValueError("EXPORT_PREPARATION_MISMATCH")
            self._register_retention(
                cursor=cursor,
                scope=scope,
                object_kind="EXPORT_RECEIPT",
                object_id=receipt.export_id,
                object_uri=destination_receipt_ref,
                object_generation=destination_receipt_generation,
                retention_until=retention_until,
                storage_region=retention_region,
            )
            stored = self._stored_export(cursor=cursor, scope=scope, request_hash=request_hash)
            if stored is None:
                raise RuntimeError("export receipt was not persisted")
            return stored

    @staticmethod
    def _stored_export(*, cursor: Any, scope: Scope, request_hash: str) -> ExportReceipt | None:
        cursor.execute(
            """SELECT r.attempt_id, r.guidance_key, r.guidance_version,
                      r.export_bundle_hash, r.guidance_content_hash,
                      r.lifecycle_at_export, a.destination_id
                 FROM solvan_operability.skill_export_receipts r
                 JOIN solvan_operability.skill_export_attempts a
                   ON (a.organization_id,a.project_id,a.environment_id,a.id)=
                      (r.organization_id,r.project_id,r.environment_id,r.attempt_id)
                WHERE r.organization_id=%(organization_id)s
                  AND r.project_id=%(project_id)s AND r.environment_id=%(environment_id)s
                  AND r.export_request_hash=%(request_hash)s""",
            {**scope.canonical_dict(), "request_hash": request_hash},
        )
        stored = cursor.fetchone()
        if stored is None:
            return None
        return ExportReceipt(
            export_id=str(stored[0]),
            guidance_key=str(stored[1]),
            version=str(stored[2]),
            bundle_hash=str(stored[3]),
            content_hash=str(stored[4]),
            lifecycle=str(stored[5]),
            destination_id=str(stored[6]),
        )

    def require_export_license_policy(self, *, scope: Scope, normalized_identifier: str) -> str:
        """Return the exact active policy version only when redistribution is allowed."""

        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT policy_version,redistribution_allowed,enabled
                     FROM solvan_operability.skill_license_policies
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND normalized_identifier=%(identifier)s""",
                {**scope.canonical_dict(), "identifier": " ".join(normalized_identifier.split())},
            )
            row = cursor.fetchone()
        if row is None:
            raise ValueError("LICENSE_POLICY_NOT_REGISTERED")
        if not bool(row[1]) or not bool(row[2]):
            raise ValueError("LICENSE_REDISTRIBUTION_DENIED")
        return str(row[0])

    def find_export_by_idempotency(
        self, *, scope: Scope, idempotency_key: str, request_hash: str
    ) -> tuple[ExportReceipt, str | None] | None:
        """Replay an exact export, or refuse reuse of its key with changed material.

        The same request hash returns the stored receipt whatever idempotency
        key carries the retry; a reused key with changed material conflicts.
        """

        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT export_request_hash,decision,reason_code
                     FROM solvan_operability.skill_export_attempts
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND idempotency_key=%(idempotency_key)s""",
                {**scope.canonical_dict(), "idempotency_key": idempotency_key},
            )
            row = cursor.fetchone()
        if row is None:
            return self.find_export(scope=scope, request_hash=request_hash)
        if str(row[0]) != request_hash:
            raise ValueError("IDEMPOTENCY_CONFLICT")
        if str(row[1]) == "PREPARED":
            return None
        if str(row[1]) != "EXPORTED":
            raise ValueError(str(row[2] or "EXPORT_REFUSED"))
        found = self.find_export(scope=scope, request_hash=request_hash)
        if found is None:
            raise RuntimeError("completed export attempt has no receipt")
        return found

    def persist_export_refusal(
        self,
        *,
        scope: Scope,
        idempotency_key: str,
        request_hash: str,
        guidance_key: str,
        guidance_version: str,
        destination_id: str,
        purpose: str,
        exporter_principal: str,
        authorization_ref: str | None,
        reason_code: str,
    ) -> str:
        """Audit a fail-closed export decision without requiring eligible references."""

        attempt_id = new_identifier("sea")
        with self._connection.transaction(), self._connection.cursor() as cursor:
            try:
                with self._connection.transaction():
                    cursor.execute(
                        """INSERT INTO solvan_operability.skill_export_attempts
                           (organization_id,project_id,environment_id,id,idempotency_key,
                            export_request_hash,guidance_key,guidance_version,destination_id,
                            purpose,decision,reason_code,exporter_principal,authorization_ref)
                           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                                   %(idempotency_key)s,%(request_hash)s,%(guidance_key)s,%(version)s,
                                   %(destination)s,%(purpose)s,'REJECTED',%(reason)s,%(principal)s,
                                   %(authorization)s)
                           ON CONFLICT (organization_id,project_id,environment_id,idempotency_key)
                           DO UPDATE SET decision='REJECTED',reason_code=EXCLUDED.reason_code
                             WHERE skill_export_attempts.export_request_hash=
                                   EXCLUDED.export_request_hash
                               AND skill_export_attempts.decision='PREPARED'""",
                        {
                            **scope.canonical_dict(),
                            "id": attempt_id,
                            "idempotency_key": idempotency_key,
                            "request_hash": request_hash,
                            "guidance_key": guidance_key,
                            "version": guidance_version,
                            "destination": destination_id,
                            "purpose": purpose,
                            "reason": reason_code,
                            "principal": exporter_principal,
                            "authorization": authorization_ref,
                        },
                    )
            except errors.UniqueViolation as error:
                raise ValueError("IDEMPOTENCY_CONFLICT") from error
            cursor.execute(
                """SELECT id,export_request_hash,decision,reason_code
                     FROM solvan_operability.skill_export_attempts
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                      AND idempotency_key=%(idempotency_key)s""",
                {**scope.canonical_dict(), "idempotency_key": idempotency_key},
            )
            stored = cursor.fetchone()
        if stored is None:
            raise RuntimeError("export refusal was not persisted")
        if str(stored[1]) != request_hash:
            raise ValueError("IDEMPOTENCY_CONFLICT")
        if str(stored[2]) == "EXPORTED":
            raise ValueError("EXPORT_ALREADY_COMPLETED")
        return str(stored[0])

    def find_export(
        self, *, scope: Scope, request_hash: str
    ) -> tuple[ExportReceipt, str | None] | None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT r.attempt_id, r.guidance_key, r.guidance_version,
                          r.export_bundle_hash, r.guidance_content_hash,
                          r.lifecycle_at_export, a.destination_id, r.destination_receipt_ref
                     FROM solvan_operability.skill_export_receipts r
                     JOIN solvan_operability.skill_export_attempts a
                       ON (a.organization_id,a.project_id,a.environment_id,a.id)=
                          (r.organization_id,r.project_id,r.environment_id,r.attempt_id)
                    WHERE r.organization_id=%(organization_id)s
                      AND r.project_id=%(project_id)s AND r.environment_id=%(environment_id)s
                      AND r.export_request_hash=%(request_hash)s""",
                {**scope.canonical_dict(), "request_hash": request_hash},
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return (
            ExportReceipt(
                export_id=str(row[0]),
                guidance_key=str(row[1]),
                version=str(row[2]),
                bundle_hash=str(row[3]),
                content_hash=str(row[4]),
                lifecycle=str(row[5]),
                destination_id=str(row[6]),
            ),
            None if row[7] is None else str(row[7]),
        )

    def _persist_quarantine(
        self,
        *,
        cursor: Any,
        scope: Scope,
        request: SkillImportCommand,
        attempt_id: str,
        inspection: SkillImportInspection,
        archive: bytes,
        scan_receipts: tuple[Any, ...],
    ) -> None:
        retention_days, storage_region = self._retention_policy(
            cursor=cursor, scope=scope, requested_region=request.region
        )
        retention_until = datetime.now(UTC) + timedelta(days=retention_days)
        source_object = self._object_writer.put_bytes(
            object_name=f"skills/{scope.organization_id}/{attempt_id}/source.bin",
            content=archive,
            content_type="application/octet-stream",
        )
        # A repository source may not have an uploaded archive. The writer
        # contract still requires a content-addressed object reference; this
        # manifest is the durable prompt-visible representation.
        manifest = json.dumps(
            [
                {
                    "path": item.path,
                    "content_hash": item.digest,
                    "disposition": item.disposition.value,
                }
                for item in inspection.files
            ],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        manifest_object = self._object_writer.put_bytes(
            object_name=f"skills/{scope.organization_id}/{attempt_id}/manifest.json",
            content=manifest,
            content_type="application/json",
        )
        self._register_retention(
            cursor=cursor,
            scope=scope,
            object_kind="SOURCE_PACKAGE",
            object_id=attempt_id,
            object_uri=str(source_object.uri),
            object_generation=str(getattr(source_object, "generation", "")),
            retention_until=retention_until,
            storage_region=storage_region,
        )
        self._register_retention(
            cursor=cursor,
            scope=scope,
            object_kind="CONTENT_MANIFEST",
            object_id=attempt_id,
            object_uri=str(manifest_object.uri),
            object_generation=str(getattr(manifest_object, "generation", "")),
            retention_until=retention_until,
            storage_region=storage_region,
        )
        license_value = normalize_license(inspection.frontmatter)
        license_ref = None
        license_hash = None
        if license_value is not None:
            license_object = self._object_writer.put_bytes(
                object_name=f"skills/{scope.organization_id}/{attempt_id}/license.txt",
                content=license_value[1],
                content_type="text/plain",
            )
            license_ref = str(license_object.uri)
            license_hash = str(license_object.content_hash)
            self._register_retention(
                cursor=cursor,
                scope=scope,
                object_kind="LICENSE_EVIDENCE",
                object_id=attempt_id,
                object_uri=license_ref,
                object_generation=str(getattr(license_object, "generation", "")),
                retention_until=retention_until,
                storage_region=storage_region,
            )
        import_id = new_identifier("si")
        cursor.execute(
            """INSERT INTO solvan_operability.skill_imports
               (organization_id,project_id,environment_id,id,attempt_id,source_skill_name,
                source_bundle_hash,normalized_package_hash,guidance_content_hash,
                canonicalization_version,package_object_ref,package_object_hash,
                content_manifest_ref,
                license_state,normalized_license_identifier,
                license_evidence_ref,license_evidence_hash,
                upstream_ref,upstream_subdirectory,upstream_commit_sha,upstream_subtree_hash,
                scanner_versions_json)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,%(attempt_id)s,
                %(name)s,%(source_hash)s,%(normalized_hash)s,%(content_hash)s,
                'skill-canonicalization/1',%(package_ref)s,%(package_hash)s,%(manifest_ref)s,
                %(license_state)s,%(license_identifier)s,%(license_ref)s,%(license_hash)s,
                %(upstream_ref)s,%(upstream_subdirectory)s,
                %(upstream_commit_sha)s,%(upstream_subtree_hash)s,%(scanners)s)""",
            {
                **scope.canonical_dict(),
                "id": import_id,
                "attempt_id": attempt_id,
                "name": str(inspection.frontmatter.get("name", "unknown")),
                "source_hash": inspection.source_bundle_hash,
                "normalized_hash": inspection.normalized_package_hash,
                "content_hash": inspection.guidance_content_hash,
                "package_ref": str(source_object.uri),
                "package_hash": str(source_object.content_hash),
                "manifest_ref": str(manifest_object.uri),
                "license_state": _license_state(
                    normalized_license=license_value,
                    scan_receipts=scan_receipts,
                ),
                "license_identifier": None if license_value is None else license_value[0],
                "license_ref": license_ref,
                "license_hash": license_hash,
                "upstream_ref": request.upstream_ref,
                "upstream_subdirectory": request.upstream_subdirectory,
                "upstream_commit_sha": request.upstream_commit_sha,
                "upstream_subtree_hash": request.upstream_subtree_hash,
                "scanners": Jsonb({receipt.scanner: receipt.version for receipt in scan_receipts}),
            },
        )

        for item in inspection.files:
            object_receipt = self._object_writer.put_bytes(
                object_name=f"skills/{scope.organization_id}/{attempt_id}/files/{item.path}",
                content=item.content,
                content_type=(
                    "text/markdown" if item.path.endswith(".md") else "application/octet-stream"
                ),
            )
            self._register_retention(
                cursor=cursor,
                scope=scope,
                object_kind="IMPORT_FILE",
                object_id=f"{import_id}:{item.path}",
                object_uri=str(object_receipt.uri),
                object_generation=str(getattr(object_receipt, "generation", "")),
                retention_until=retention_until,
                storage_region=storage_region,
            )
            cursor.execute(
                """INSERT INTO solvan_operability.skill_import_files
                   (organization_id,project_id,environment_id,import_id,path,size_bytes,
                    media_type,content_hash,object_ref,disposition)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(import_id)s,
                    %(path)s,%(size)s,%(media)s,%(hash)s,%(ref)s,%(disposition)s)""",
                {
                    **scope.canonical_dict(),
                    "import_id": import_id,
                    "path": item.path,
                    "size": len(item.content),
                    "media": (
                        "text/markdown" if item.path.endswith(".md") else "application/octet-stream"
                    ),
                    "hash": f"sha256:{item.digest}",
                    "ref": str(object_receipt.uri),
                    "disposition": item.disposition.value,
                },
            )
        validation_findings: list[tuple[str, dict[str, Any]]] = [
            (
                reason_code,
                {
                    "source": "skill-import-profile/1",
                    "verdict": "NORMALIZE"
                    if reason_code not in {"REFERENCE_NOT_MARKDOWN", "FILE_OVER_SIZE"}
                    else "STRIP",
                },
            )
            for reason_code in inspection.warnings
        ]
        for receipt in scan_receipts:
            validation_findings.extend(
                (
                    reason_code,
                    {
                        "scanner": receipt.scanner,
                        "version": receipt.version,
                        "verdict": receipt.verdict,
                        "content_hash": receipt.content_hash,
                    },
                )
                for reason_code in receipt.reason_codes
            )
        for sequence, (reason_code, detail) in enumerate(validation_findings, start=1):
            receipt_object = self._object_writer.put_bytes(
                object_name=f"skills/{scope.organization_id}/{attempt_id}/validation/{sequence}.json",
                content=json.dumps(
                    {
                        "reason_code": reason_code,
                        **detail,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode(),
                content_type="application/json",
            )
            self._register_retention(
                cursor=cursor,
                scope=scope,
                object_kind="VALIDATION_RECEIPT",
                object_id=f"{import_id}:{sequence}",
                object_uri=str(receipt_object.uri),
                object_generation=str(getattr(receipt_object, "generation", "")),
                retention_until=retention_until,
                storage_region=storage_region,
            )
            cursor.execute(
                """INSERT INTO solvan_operability.skill_validation_receipts
                   (organization_id,project_id,environment_id,import_id,sequence,
                           reason_code,path,detail_json,object_ref,object_generation)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(import_id)s,
                           %(sequence)s,%(reason)s,NULL,%(detail)s,%(object_ref)s,%(object_generation)s)""",
                {
                    **scope.canonical_dict(),
                    "import_id": import_id,
                    "sequence": sequence,
                    "reason": reason_code,
                    "detail": Jsonb(detail),
                    "object_ref": str(receipt_object.uri),
                    "object_generation": str(getattr(receipt_object, "generation", "")),
                },
            )

    def load_refresh_binding(
        self, *, scope: Scope, guidance_key: str, expected_head_epoch: int
    ) -> tuple[str, str, str, str, str, str, int]:
        """Resolve immutable repository provenance from the fenced current head."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT h.head_epoch,d.owner_department,a.source_ref AS repository_ref,
                          i.upstream_ref,i.upstream_subdirectory,
                          i.upstream_commit_sha,i.upstream_subtree_hash
                     FROM solvan_operability.guidance_current_heads h
                     JOIN solvan_operability.guidance_definitions d USING
                       (organization_id,project_id,environment_id,guidance_key)
                     JOIN solvan_operability.guidance_revisions r ON
                       (r.organization_id,r.project_id,r.environment_id,r.guidance_key,r.version)=
                       (h.organization_id,h.project_id,h.environment_id,h.guidance_key,
                        h.approved_version)
                     JOIN solvan_operability.skill_imports i ON
                       i.organization_id=r.organization_id
                      AND i.project_id=r.project_id
                      AND i.environment_id=r.environment_id
                      AND r.source_ref=('skill-import:' || i.attempt_id)
                     JOIN solvan_operability.skill_import_attempts a ON
                       (a.organization_id,a.project_id,a.environment_id,a.id)=
                       (i.organization_id,i.project_id,i.environment_id,i.attempt_id)
                    WHERE h.organization_id=%(organization_id)s
                      AND h.project_id=%(project_id)s
                      AND h.environment_id=%(environment_id)s
                      AND h.guidance_key=%(guidance_key)s
                    FOR SHARE OF h,r,i""",
                {**scope.canonical_dict(), "guidance_key": guidance_key},
            )
            row = cursor.fetchone()
        if row is None:
            raise ValueError("LINEAGE_NOT_FOUND")
        if int(row["head_epoch"]) != expected_head_epoch:
            raise ValueError("LINEAGE_CONFLICT")
        values = (
            row["owner_department"],
            row["repository_ref"],
            row["upstream_ref"],
            row["upstream_commit_sha"],
            row["upstream_subtree_hash"],
        )
        if any(not isinstance(value, str) or not value for value in values):
            raise ValueError("REGISTERED_CONNECTOR_REQUIRED")
        return (
            str(row["owner_department"]),
            str(row["repository_ref"]),
            str(row["upstream_ref"]),
            str(row["upstream_subdirectory"] or ""),
            str(row["upstream_commit_sha"]),
            str(row["upstream_subtree_hash"]),
            int(row["head_epoch"]),
        )

    @staticmethod
    def _retention_policy(*, cursor: Any, scope: Scope, requested_region: str) -> tuple[int, str]:
        cursor.execute(
            """SELECT storage_region, retention_days
                 FROM solvan_operability.skill_retention_policies
                WHERE organization_id=%(organization_id)s
                  AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                  AND policy_id='default'
                FOR UPDATE""",
            {**scope.canonical_dict()},
        )
        row = cursor.fetchone()
        if row is None:
            raise RuntimeError("RETENTION_POLICY_UNCONFIGURED")
        storage_region = str(row[0])
        if storage_region != requested_region:
            raise RuntimeError("RETENTION_REGION_DENIED")
        return int(row[1]), storage_region

    @staticmethod
    def _register_retention(
        *,
        cursor: Any,
        scope: Scope,
        object_kind: str,
        object_id: str,
        object_uri: str | None,
        object_generation: str | None,
        retention_until: datetime | None,
        storage_region: str | None,
    ) -> None:
        if (
            not object_uri
            or not object_uri.startswith("gs://")
            or not object_generation
            or not object_generation.isdigit()
        ):
            raise RuntimeError("RETENTION_OBJECT_RECEIPT_MISSING")
        if retention_until is None or storage_region is None:
            raise RuntimeError("RETENTION_POLICY_UNCONFIGURED")
        params = {
            **scope.canonical_dict(),
            "object_kind": object_kind,
            "object_id": object_id,
            "storage_region": storage_region,
            "retention_until": retention_until,
            "object_uri": object_uri,
            "object_generation": object_generation,
        }
        cursor.execute(
            """INSERT INTO solvan_operability.skill_retention_controls
                   (organization_id,project_id,environment_id,object_kind,object_id,
                    storage_region,retention_until,object_uri,object_generation,deletion_state)
                VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(object_kind)s,
                        %(object_id)s,%(storage_region)s,%(retention_until)s,%(object_uri)s,
                        %(object_generation)s,'RETAINED')
                ON CONFLICT (organization_id,project_id,environment_id,object_kind,object_id)
                DO NOTHING""",
            params,
        )
        cursor.execute(
            """SELECT storage_region,retention_until,object_uri,object_generation
                 FROM solvan_operability.skill_retention_controls
                WHERE organization_id=%(organization_id)s AND project_id=%(project_id)s
                  AND environment_id=%(environment_id)s AND object_kind=%(object_kind)s
                  AND object_id=%(object_id)s""",
            params,
        )
        row = cursor.fetchone()
        if row is None or (
            str(row[0]) != storage_region
            or row[1] != retention_until
            or str(row[2]) != object_uri
            or str(row[3]) != object_generation
        ):
            raise RuntimeError("RETENTION_OBJECT_CONFLICT")
