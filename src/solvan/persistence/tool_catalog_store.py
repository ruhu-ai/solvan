"""PostgreSQL authority for immutable Tools, profiles, probes, and run bindings."""

from __future__ import annotations

from typing import Any, cast

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from solvan.application.tool_catalog import (
    CapabilityProbe,
    CatalogLifecycle,
    CatalogPrincipal,
    ToolConnectionRequirement,
    ToolProfileRevision,
    ToolRevision,
)
from solvan.application.tool_catalog import ToolCatalogError as CatalogError
from solvan.domain import Scope, new_identifier
from solvan.persistence.tool_capability_attestation import ToolCapabilityAttestationMixin
from solvan.persistence.tool_catalog_projection import ToolCatalogProjectionMixin
from solvan.persistence.tool_catalog_run_binding import ToolCatalogRunBindingMixin


class PostgresToolCatalogStore(
    ToolCatalogRunBindingMixin, ToolCatalogProjectionMixin, ToolCapabilityAttestationMixin
):
    """All tenant operations are scope-bound; target DDL adds RLS as a backstop."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def register_principal(self, principal: CatalogPrincipal) -> int:
        """Publish this principal's material and point its head at it.

        This refused any change to an already-registered key, which is correct
        for an immutable record and impossible to satisfy: the material carries
        an agent-manifest digest, so the first release that edited a manifest
        could not publish its catalog at all. Publication now resolves the
        material to a revision — reusing the existing one when nothing changed,
        appending the next version when it did — and moves the head, which is
        how every other governed record in this schema evolves.

        Returns the published version so a caller can record what it moved to.
        """

        material = (
            principal.display_name,
            str(principal.registry_kind),
            str(principal.execution_role),
            principal.model_backed,
            principal.manifest_hash,
        )
        with self._connection.cursor() as cursor:
            # Serialize concurrent publishers of the same key so two releases
            # cannot mint the same next version.
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"solvan-catalog-principal:{principal.principal_key}",),
            )
            cursor.execute(
                """INSERT INTO solvan_operability.catalog_principal_revisions
                     (principal_key, version, display_name, registry_kind,
                      execution_role, model_backed, manifest_hash)
                   SELECT %(principal_key)s,
                          coalesce(max(existing.version), 0) + 1,
                          %(display_name)s,%(registry_kind)s,%(execution_role)s,
                          %(model_backed)s,%(manifest_hash)s
                     FROM solvan_operability.catalog_principal_revisions existing
                    WHERE existing.principal_key = %(principal_key)s
                   ON CONFLICT (principal_key, display_name, registry_kind,
                                execution_role, model_backed, manifest_hash)
                     DO NOTHING
                   RETURNING version""",
                {
                    "principal_key": principal.principal_key,
                    "display_name": principal.display_name,
                    "registry_kind": str(principal.registry_kind),
                    "execution_role": str(principal.execution_role),
                    "model_backed": principal.model_backed,
                    "manifest_hash": principal.manifest_hash,
                },
            )
            inserted = cursor.fetchone()
            if inserted is None:
                cursor.execute(
                    """SELECT version
                         FROM solvan_operability.catalog_principal_revisions
                        WHERE principal_key = %s AND display_name = %s
                          AND registry_kind = %s AND execution_role = %s
                          AND model_backed = %s AND manifest_hash = %s""",
                    (principal.principal_key, *material),
                )
                existing_revision = cursor.fetchone()
                if existing_revision is None:
                    raise CatalogError("catalog principal material could not be published")
                version = int(existing_revision[0])
            else:
                version = int(inserted[0])
            # An unchanged head is left alone so republishing an identical
            # catalog neither burns a head epoch nor records a move that did
            # not happen.
            cursor.execute(
                """INSERT INTO solvan_operability.catalog_principals
                     (principal_key, version, head_epoch, display_name,
                      registry_kind, execution_role, model_backed, manifest_hash)
                   VALUES (%s,%s,1,%s,%s,%s,%s,%s)
                   ON CONFLICT (principal_key) DO UPDATE
                      SET version = EXCLUDED.version,
                          head_epoch = solvan_operability.catalog_principals.head_epoch + 1,
                          display_name = EXCLUDED.display_name,
                          registry_kind = EXCLUDED.registry_kind,
                          execution_role = EXCLUDED.execution_role,
                          model_backed = EXCLUDED.model_backed,
                          manifest_hash = EXCLUDED.manifest_hash
                    WHERE solvan_operability.catalog_principals.version
                          <> EXCLUDED.version""",
                (principal.principal_key, version, *material),
            )
        return version

    def publish_tool(self, revision: ToolRevision) -> None:
        with self._connection.cursor() as cursor:
            # A Tool's definition metadata evolves the same way its revisions
            # do. This refused any later display name or owning department,
            # so renaming a Tool or moving it between departments blocked the
            # whole catalog publication rather than the one field that changed.
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"solvan-tool-definition:{revision.tool_key}",),
            )
            cursor.execute(
                """INSERT INTO solvan_operability.tool_definition_revisions
                     (tool_key, version, display_name, owner_department)
                   SELECT %(tool_key)s, coalesce(max(existing.version), 0) + 1,
                          %(display_name)s, %(owner_department)s
                     FROM solvan_operability.tool_definition_revisions existing
                    WHERE existing.tool_key = %(tool_key)s
                   ON CONFLICT (tool_key, display_name, owner_department) DO NOTHING
                   RETURNING version""",
                {
                    "tool_key": revision.tool_key,
                    "display_name": revision.display_name,
                    "owner_department": revision.owner_department,
                },
            )
            inserted_definition = cursor.fetchone()
            if inserted_definition is None:
                cursor.execute(
                    """SELECT version FROM solvan_operability.tool_definition_revisions
                        WHERE tool_key = %s AND display_name = %s
                          AND owner_department = %s""",
                    (revision.tool_key, revision.display_name, revision.owner_department),
                )
                existing_definition = cursor.fetchone()
                if existing_definition is None:
                    raise CatalogError("Tool definition material could not be published")
                definition_version = int(existing_definition[0])
            else:
                definition_version = int(inserted_definition[0])
            cursor.execute(
                """INSERT INTO solvan_operability.tool_definitions
                     (tool_key, version, head_epoch, display_name, owner_department)
                   VALUES (%s,%s,1,%s,%s)
                   ON CONFLICT (tool_key) DO UPDATE
                      SET version = EXCLUDED.version,
                          head_epoch = solvan_operability.tool_definitions.head_epoch + 1,
                          display_name = EXCLUDED.display_name,
                          owner_department = EXCLUDED.owner_department
                    WHERE solvan_operability.tool_definitions.version <> EXCLUDED.version""",
                (
                    revision.tool_key,
                    definition_version,
                    revision.display_name,
                    revision.owner_department,
                ),
            )
            cursor.execute(
                """INSERT INTO solvan_operability.tool_revisions
                     (tool_key, version, description, permission_class,
                      implementation_kind, required_capabilities_json,
                      required_connection_providers_json, input_schema_ref,
                      input_schema_hash, output_schema_ref, output_schema_hash,
                      use_cases_json, anti_use_cases_json, evidence_kind,
                      output_semantics_json, supported_retrieval_controls_json,
                      no_data_semantics, failure_taxonomy_json,
                      supported_data_classes_json, runtime_regions_json,
                      registry_resource, gateway_destination, model_armor_coverage,
                      network_policy_hash, timeout_ms, max_input_bytes,
                      max_output_bytes, default_call_budget, idempotency, lifecycle,
                      approval_ref, evaluation_ref, supersedes_version, content_hash)
                   VALUES
                     (%(tool_key)s,%(version)s,%(description)s,%(permission_class)s,
                      %(implementation_kind)s,%(required_capabilities)s,
                      %(required_providers)s,%(input_schema_ref)s,%(input_schema_hash)s,
                      %(output_schema_ref)s,%(output_schema_hash)s,%(use_cases)s,
                      %(anti_use_cases)s,%(evidence_kind)s,%(output_semantics)s,
                      %(retrieval_controls)s,%(no_data_semantics)s,%(failure_taxonomy)s,
                      %(data_classes)s,%(runtime_regions)s,%(registry_resource)s,
                      %(gateway_destination)s,%(armor)s,%(network_policy_hash)s,
                      %(timeout_ms)s,%(max_input_bytes)s,%(max_output_bytes)s,
                      %(call_budget)s,%(idempotency)s,%(lifecycle)s,%(approval_ref)s,
                      %(evaluation_ref)s,%(supersedes)s,%(content_hash)s)
                   ON CONFLICT (tool_key, version) DO NOTHING""",
                {
                    "tool_key": revision.tool_key,
                    "version": revision.version,
                    "description": revision.description,
                    "permission_class": str(revision.permission_class),
                    "implementation_kind": str(revision.implementation_kind),
                    "required_capabilities": Jsonb(list(revision.required_capabilities)),
                    "required_providers": Jsonb(list(revision.required_connection_providers)),
                    "input_schema_ref": revision.input_schema_ref,
                    "input_schema_hash": revision.input_schema_hash,
                    "output_schema_ref": revision.output_schema_ref,
                    "output_schema_hash": revision.output_schema_hash,
                    "use_cases": Jsonb(list(revision.use_cases)),
                    "anti_use_cases": Jsonb(list(revision.anti_use_cases)),
                    "evidence_kind": str(revision.evidence_kind),
                    "output_semantics": Jsonb(list(revision.output_semantics)),
                    "retrieval_controls": Jsonb(list(revision.supported_retrieval_controls)),
                    "no_data_semantics": str(revision.no_data_semantics),
                    "failure_taxonomy": Jsonb(list(revision.failure_taxonomy)),
                    "data_classes": Jsonb(list(revision.supported_data_classes)),
                    "runtime_regions": Jsonb(list(revision.runtime_regions)),
                    "registry_resource": revision.registry_resource,
                    "gateway_destination": revision.gateway_destination,
                    "armor": str(revision.model_armor_coverage),
                    "network_policy_hash": revision.network_policy_hash,
                    "timeout_ms": revision.timeout_ms,
                    "max_input_bytes": revision.max_input_bytes,
                    "max_output_bytes": revision.max_output_bytes,
                    "call_budget": revision.default_call_budget,
                    "idempotency": str(revision.idempotency),
                    "lifecycle": str(revision.lifecycle),
                    "approval_ref": revision.approval_ref,
                    "evaluation_ref": revision.evaluation_ref,
                    "supersedes": self._supersedes_version(revision),
                    "content_hash": revision.content_hash,
                },
            )
            cursor.execute(
                """SELECT content_hash, approval_ref, evaluation_ref
                    FROM solvan_operability.tool_revisions
                    WHERE tool_key = %s AND version = %s""",
                (revision.tool_key, revision.version),
            )
            existing_revision = cursor.fetchone()
            if existing_revision is None or not self._same_tool_revision_material(
                revision,
                content_hash=str(existing_revision[0]),
                approval_ref=cast(str | None, existing_revision[1]),
                evaluation_ref=cast(str | None, existing_revision[2]),
            ):
                raise CatalogError("a Tool revision already has different immutable material")
            for requester in revision.allowed_requester_keys:
                cursor.execute(
                    """INSERT INTO solvan_operability.tool_revision_requesters
                         (tool_key, tool_version, requester_key)
                       VALUES (%s,%s,%s) ON CONFLICT DO NOTHING""",
                    (revision.tool_key, revision.version, requester),
                )

    @staticmethod
    def _same_tool_revision_material(
        revision: ToolRevision,
        *,
        content_hash: str,
        approval_ref: str | None,
        evaluation_ref: str | None,
    ) -> bool:
        """Accept only an exact revision or the same material under a later release gate."""

        if revision.content_hash == content_hash:
            return True
        persisted_governance = revision.model_copy(
            update={"approval_ref": approval_ref, "evaluation_ref": evaluation_ref}
        )
        return persisted_governance.content_hash == content_hash

    @staticmethod
    def _supersedes_version(revision: ToolRevision) -> str | None:
        if revision.supersedes is None:
            return None
        tool_key, separator, version = revision.supersedes.partition("@")
        if separator != "@" or tool_key != revision.tool_key or not version:
            raise CatalogError("a Tool may supersede only an exact revision of itself")
        return version

    def publish_profile(self, *, scope: Scope, profile: ToolProfileRevision) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan_operability.tool_profile_revisions
                     (schema_version, canonicalization_version,
                      profile_key, version, purpose, allowed_agent_key,
                      maximum_total_calls, maximum_parallel_calls,
                      maximum_read_window_ms, maximum_aggregate_evidence_bytes,
                      data_classification_ceiling, runtime_region, lifecycle,
                      profile_material_hash, approval_ref, evaluation_ref)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (profile_key, version) DO NOTHING""",
                (
                    profile.schema_version,
                    profile.canonicalization_version,
                    profile.profile_key,
                    profile.version,
                    profile.purpose,
                    profile.allowed_agent_key,
                    profile.maximum_total_calls,
                    profile.maximum_parallel_calls,
                    profile.maximum_read_window_ms,
                    profile.maximum_aggregate_evidence_bytes,
                    profile.data_classification_ceiling,
                    profile.runtime_region,
                    str(profile.lifecycle),
                    profile.profile_material_hash,
                    profile.approval_ref,
                    profile.evaluation_ref,
                ),
            )
            cursor.execute(
                """SELECT profile_material_hash FROM solvan_operability.tool_profile_revisions
                    WHERE profile_key = %s AND version = %s""",
                (profile.profile_key, profile.version),
            )
            if cursor.fetchone() != (profile.profile_material_hash,):
                raise CatalogError("a profile revision already has different immutable material")
            for ordinal, revision_ref in enumerate(profile.tool_revisions, start=1):
                tool_key, version = revision_ref.split("@", 1)
                cursor.execute(
                    """INSERT INTO solvan_operability.tool_profile_members
                         (profile_key, profile_version, ordinal, tool_key, tool_version)
                       VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                    (profile.profile_key, profile.version, ordinal, tool_key, version),
                )
                cursor.execute(
                    """INSERT INTO solvan_operability.tool_profile_connection_requirements
                         (profile_key, profile_version, ordinal, tool_key, tool_version,
                          binding_kind, provider, capability_key, external_project_selector)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT DO NOTHING""",
                    (
                        profile.profile_key,
                        profile.version,
                        ordinal,
                        tool_key,
                        version,
                        str(profile.tool_connection_requirements[ordinal - 1].binding_kind),
                        profile.tool_connection_requirements[ordinal - 1].provider,
                        profile.tool_connection_requirements[ordinal - 1].capability_key,
                        profile.tool_connection_requirements[ordinal - 1].external_project_selector,
                    ),
                )

    def record_probe(self, *, scope: Scope, probe: CapabilityProbe) -> str:
        probe_id = new_identifier("tpr")
        tool_key, tool_version = probe.tool_revision.split("@", 1)
        with self._connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO solvan_operability.tool_probe_receipts
                     (organization_id, project_id, environment_id, id, connection_id,
                      connection_epoch, tool_key, tool_version, agent_key, identity_ref,
                      registry_resource, gateway_policy_ref, network_policy_hash,
                      outcome, reason_code, missing_grant, observed_at, expires_at,
                      receipt_ref, receipt_hash)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
                           %(connection_id)s,%(connection_epoch)s,%(tool_key)s,
                           %(tool_version)s,%(agent_key)s,%(identity_ref)s,
                           %(registry_resource)s,%(gateway_policy_ref)s,
                           %(network_policy_hash)s,%(outcome)s,%(reason_code)s,
                           %(missing_grant)s,%(observed_at)s,%(expires_at)s,
                           %(receipt_ref)s,%(receipt_hash)s)""",
                {
                    **scope.canonical_dict(),
                    "id": probe_id,
                    "connection_id": probe.connection_id,
                    "connection_epoch": probe.connection_epoch,
                    "tool_key": tool_key,
                    "tool_version": tool_version,
                    "agent_key": probe.agent_key,
                    "identity_ref": probe.identity_ref,
                    "registry_resource": probe.registry_resource,
                    "gateway_policy_ref": probe.gateway_policy_ref,
                    "network_policy_hash": probe.network_policy_hash,
                    "outcome": probe.outcome,
                    "reason_code": probe.reason_code,
                    "missing_grant": probe.missing_grant,
                    "observed_at": probe.observed_at,
                    "expires_at": probe.expires_at,
                    "receipt_ref": probe.receipt_ref,
                    "receipt_hash": probe.receipt_hash,
                },
            )
        return probe_id

    def load_profile(self, *, scope: Scope, profile_key: str, version: str) -> ToolProfileRevision:
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT p.*, array_agg(m.tool_key || '@' || m.tool_version
                                           ORDER BY m.ordinal)
                                           FILTER (WHERE m.tool_key IS NOT NULL)
                                           AS tool_revisions
                     FROM solvan_operability.tool_profile_revisions p
                     LEFT JOIN solvan_operability.tool_profile_members m
                       ON (m.profile_key,m.profile_version)=(p.profile_key,p.version)
                    WHERE p.profile_key=%(profile_key)s AND p.version=%(version)s
                    GROUP BY p.profile_key,p.version""",
                {**scope.canonical_dict(), "profile_key": profile_key, "version": version},
            )
            row = cursor.fetchone()
        if row is None:
            raise CatalogError("Tool profile revision was not found")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT ordinal, tool_key || '@' || tool_version AS tool_revision,
                          binding_kind, provider, capability_key, external_project_selector
                     FROM solvan_operability.tool_profile_connection_requirements
                    WHERE profile_key=%(profile_key)s AND profile_version=%(version)s
                    ORDER BY ordinal""",
                {"profile_key": profile_key, "version": version},
            )
            requirements = cursor.fetchall()
        return ToolProfileRevision(
            schema_version=cast(int, row["schema_version"]),
            canonicalization_version=cast(int, row["canonicalization_version"]),
            profile_key=cast(str, row["profile_key"]),
            version=cast(str, row["version"]),
            purpose=cast(str, row["purpose"]),
            allowed_agent_key=cast(str, row["allowed_agent_key"]),
            tool_revisions=tuple(row["tool_revisions"] or ()),
            maximum_total_calls=cast(int, row["maximum_total_calls"]),
            maximum_parallel_calls=cast(int, row["maximum_parallel_calls"]),
            maximum_read_window_ms=cast(int, row["maximum_read_window_ms"]),
            maximum_aggregate_evidence_bytes=cast(int, row["maximum_aggregate_evidence_bytes"]),
            tool_connection_requirements=tuple(
                ToolConnectionRequirement.model_validate(
                    {
                        "ordinal": int(requirement["ordinal"]),
                        "tool_revision": str(requirement["tool_revision"]),
                        "binding_kind": str(requirement["binding_kind"]),
                        "provider": requirement["provider"],
                        "capability_key": requirement["capability_key"],
                        "external_project_selector": requirement["external_project_selector"],
                    }
                )
                for requirement in requirements
            ),
            data_classification_ceiling=cast(str, row["data_classification_ceiling"]),
            runtime_region=cast(str, row["runtime_region"]),
            lifecycle=CatalogLifecycle(cast(str, row["lifecycle"])),
            approval_ref=cast(str | None, row["approval_ref"]),
            evaluation_ref=cast(str | None, row["evaluation_ref"]),
        )
