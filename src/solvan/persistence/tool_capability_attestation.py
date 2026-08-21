"""Commit one observed Tool capability as the two records a bind needs.

`resolve_and_bind_run` admits a policy-source Tool only when a capability
receipt and a connection coverage row agree, joined on
`coverage.probe_receipt_ref = receipt.receipt_ref`. Two writers minting their
own references would produce records that each look correct in isolation and
never join, so both are written here, from one observation, in one transaction.

Nothing in this module decides whether a capability exists. It commits what
`solvan.platform.tool_capability_probe` observed, and refuses to commit a pass
that the observation did not report.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from psycopg import Connection

from solvan.application.tool_capability_evidence import ToolCapabilityObservation
from solvan.application.tool_catalog import (
    SOURCE_CONNECTION_PAIRS,
    CapabilityProbe,
)
from solvan.application.tool_catalog import ToolCatalogError as CatalogError
from solvan.domain import Scope


class ToolCapabilityAttestationMixin:
    """Writes the coverage row and the receipt that a run binding joins."""

    _connection: Connection[Any]

    if TYPE_CHECKING:
        # Declared, never defined here. The receipt table has exactly one
        # writer, on the concrete store, and this mixin composes with it rather
        # than opening a second way into that table.
        def record_probe(self, *, scope: Scope, probe: CapabilityProbe) -> str: ...

    def record_observed_tool_capability(
        self,
        *,
        scope: Scope,
        observation: ToolCapabilityObservation,
        connection_id: str,
        expected_connection_epoch: int,
        connection_provider: str,
        capability_class: str,
        external_project_id: str,
        workload_region: str,
        agent_key: str,
        identity_ref: str,
        registry_resource: str,
        gateway_policy_ref: str,
        network_policy_hash: str,
        classification_ceiling: str,
    ) -> str:
        """Commit one observation; return the receipt identifier.

        A `PASSED` receipt is written only for an observation that reported one,
        and only alongside the coverage row carrying the same reference. A
        failed observation records its receipt and writes no coverage, so a
        denial can never be the thing that makes a Tool selectable.
        """

        observation = observation.validated()
        tool_key, tool_version = observation.tool_revision.split("@", 1)
        if SOURCE_CONNECTION_PAIRS.get(connection_provider) != capability_class:
            raise CatalogError("Tool capability class is not valid for the connection provider")
        with self._connection.transaction(), self._connection.cursor() as cursor:
            # The epoch is rechecked under a row lock. A connection rotated or
            # revoked between the provider read and this commit invalidates the
            # observation: the credential that was probed is no longer the
            # credential a run would use.
            cursor.execute(
                """SELECT connection_epoch, provider, availability
                     FROM solvan.tenant_connections
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND id=%(connection_id)s
                      AND lifecycle NOT IN ('REVOKED','DISABLED')
                      FOR UPDATE""",
                {**scope.canonical_dict(), "connection_id": connection_id},
            )
            row = cursor.fetchone()
            if row is None:
                raise CatalogError("connection is absent, revoked, or disabled")
            if int(row[0]) != expected_connection_epoch:
                raise CatalogError("connection authority changed during the Tool probe")
            if str(row[1]) != connection_provider:
                raise CatalogError("connection provider does not match the probed Tool")
            cursor.execute(
                """SELECT t.required_capabilities_json,t.required_connection_providers_json,
                          t.registry_resource,t.network_policy_hash,t.supported_data_classes_json
                     FROM solvan_operability.tool_revisions t
                     JOIN solvan_operability.tool_revision_requesters requester
                       ON (requester.tool_key,requester.tool_version,requester.requester_key)=
                          (t.tool_key,t.version,%(agent_key)s)
                    WHERE t.tool_key=%(tool_key)s AND t.version=%(tool_version)s
                      AND t.lifecycle='APPROVED'""",
                {
                    "tool_key": tool_key,
                    "tool_version": tool_version,
                    "agent_key": agent_key,
                },
            )
            tool = cursor.fetchone()
            if tool is None:
                raise CatalogError("Tool probe does not name an approved Tool for this Agent")
            if (
                observation.capability not in tool[0]
                or connection_provider not in tool[1]
                or registry_resource != tool[2]
                or network_policy_hash != tool[3]
                or classification_ceiling not in tool[4]
            ):
                raise CatalogError("Tool probe material does not match its approved revision")

            if observation.available:
                # Coverage is reach, never authority: it records that this
                # connection reached this external project for this capability
                # class, under the reference of the observation that saw it.
                cursor.execute(
                    """INSERT INTO solvan_onboarding.connection_external_project_coverage
                         (organization_id, project_id, environment_id, connection_id,
                          capability_class, external_project_id, connection_epoch,
                          workload_region, observed_at, probe_receipt_ref)
                       VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
                          %(connection_id)s, %(capability_class)s, %(external_project_id)s,
                          %(connection_epoch)s, %(workload_region)s, %(observed_at)s,
                          %(probe_receipt_ref)s)
                       ON CONFLICT (organization_id, project_id, environment_id,
                          connection_id, capability_class, external_project_id,
                          connection_epoch, workload_region)
                       DO UPDATE SET observed_at = EXCLUDED.observed_at,
                          probe_receipt_ref = EXCLUDED.probe_receipt_ref""",
                    {
                        **scope.canonical_dict(),
                        "connection_id": connection_id,
                        "capability_class": capability_class,
                        "external_project_id": external_project_id,
                        "connection_epoch": expected_connection_epoch,
                        "workload_region": workload_region,
                        "observed_at": observation.observed_at,
                        "probe_receipt_ref": observation.receipt_ref,
                    },
                )

            probe = CapabilityProbe(
                connection_id=connection_id,
                tool_revision=observation.tool_revision,
                agent_key=agent_key,
                connection_provider=connection_provider,
                capabilities=frozenset({observation.capability}),
                connection_epoch=expected_connection_epoch,
                identity_ref=identity_ref,
                registry_resource=registry_resource,
                gateway_policy_ref=gateway_policy_ref,
                network_policy_hash=network_policy_hash,
                region=workload_region,
                classification_ceiling=classification_ceiling,
                outcome=observation.probe_outcome,
                reason_code=observation.reason_code,
                missing_grant=observation.missing_grant,
                observed_at=observation.observed_at,
                expires_at=observation.expires_at,
                receipt_ref=observation.receipt_ref,
                receipt_hash=observation.receipt_hash,
            )
            # `record_probe` is the single writer of the receipt table, and
            # `CapabilityProbe` refuses a PASSED row that carries a missing grant,
            # so an inconsistent observation cannot reach storage through here.
            return self.record_probe(scope=scope, probe=probe)
