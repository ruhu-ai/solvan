"""Run-bound Tool resolution and reader-safe catalog projection."""

from __future__ import annotations

from typing import Any, cast

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.effective_tool_set import (
    EffectiveToolBindingV1,
    EffectiveToolSetV1,
    ToolConnectionBindingKind,
    ToolRevisionRefV1,
    accepted_step_budget_hash,
)
from solvan.application.tool_catalog import (
    DATA_CLASSIFICATION_RANKS,
)
from solvan.application.tool_catalog import (
    ToolCatalogError as CatalogError,
)
from solvan.application.workspaces import WorkspaceTaskBudget
from solvan.domain import Scope, StepBudget


class ToolCatalogRunBindingMixin:
    _connection: Connection[Any]

    @staticmethod
    def _run_budget(
        *, material: dict[str, Any], workspace: bool
    ) -> StepBudget | WorkspaceTaskBudget:
        try:
            return WorkspaceTaskBudget(**material) if workspace else StepBudget(**material)
        except (TypeError, ValueError) as error:
            raise CatalogError("run carries a malformed coordinator-owned budget") from error

    def load_bound_effective_tool_set(
        self, *, scope: Scope, agent_run_id: str
    ) -> EffectiveToolSetV1:
        """Reconstruct the sole Runtime/Gateway preimage from frozen rows."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT b.*,a.agent_key,a.agent_revision
                     FROM solvan_operability.agent_run_tool_bindings b
                     JOIN solvan.agent_runs a ON
                       (a.organization_id,a.project_id,a.environment_id,a.id)=
                       (b.organization_id,b.project_id,b.environment_id,b.agent_run_id)
                    WHERE b.organization_id=%(organization_id)s
                      AND b.project_id=%(project_id)s
                      AND b.environment_id=%(environment_id)s
                      AND b.agent_run_id=%(agent_run_id)s""",
                {**scope.canonical_dict(), "agent_run_id": agent_run_id},
            )
            binding = cursor.fetchone()
            if binding is None:
                raise CatalogError("run has no frozen Tool binding")
            cursor.execute(
                """SELECT tool_key,tool_version,binding_kind,provider,capability_key,
                          external_project_selector,connection_id,connection_epoch,
                          capability_receipt_id,capability_receipt_hash,external_project_id
                     FROM solvan_operability.agent_run_accepted_tool_bindings
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND agent_run_id=%(agent_run_id)s ORDER BY ordinal""",
                {**scope.canonical_dict(), "agent_run_id": agent_run_id},
            )
            rows = cursor.fetchall()
        tools = tuple(
            ToolRevisionRefV1(tool_key=str(row["tool_key"]), version=str(row["tool_version"]))
            for row in rows
        )
        effective = EffectiveToolSetV1(
            profile_material_hash=str(binding["profile_material_hash"]),
            accepted_tools=tools,
            agent_key=str(binding["agent_key"]),
            agent_revision=str(binding["agent_revision"]),
            scope=scope.canonical_dict(),
            connection_bindings=tuple(
                EffectiveToolBindingV1(
                    tool=tools[index],
                    binding_kind=ToolConnectionBindingKind(str(row["binding_kind"])),
                    provider=row["provider"],
                    capability_key=row["capability_key"],
                    external_project_selector=row["external_project_selector"],
                    connection_id=row["connection_id"],
                    connection_epoch=row["connection_epoch"],
                    capability_receipt_id=row["capability_receipt_id"],
                    capability_receipt_hash=row["capability_receipt_hash"],
                    external_project_id=row["external_project_id"],
                )
                for index, row in enumerate(rows)
            ),
            runtime_region=str(binding["runtime_region"]),
            accepted_data_classification=str(binding["accepted_data_classification"]),
            classification_ceiling=str(binding["classification_ceiling"]),
            policy_head_activation_id=binding["policy_head_activation_id"],
            policy_head_epoch=int(binding["policy_head_epoch"]),
            placement_epoch=int(binding["placement_epoch"]),
            accepted_step_budget_hash=str(binding["accepted_step_budget_hash"]),
        )
        if effective.effective_tool_set_hash != binding["effective_tool_set_hash"]:
            raise CatalogError("stored Tool binding no longer reconstructs its digest")
        return effective

    def resolve_and_bind_run(
        self,
        *,
        scope: Scope,
        agent_run_id: str,
        profile_key: str,
        profile_version: str,
        identity_ref: str,
        runtime_region: str,
        data_classification: str,
        accepted_tool_ordinals: tuple[int, ...],
        connection_epochs: dict[str, int],
        registered_gateway_destinations: frozenset[str],
        target_external_project_id: str | None,
        policy_head_activation_id: str | None,
        policy_head_epoch: int,
        placement_epoch: int,
        target_workload_region: str | None = None,
    ) -> str:
        """Resolve the stored catalog and freeze one run before Runtime dispatch."""

        if not identity_ref:
            raise CatalogError("verified Agent Identity is required")
        ranks = DATA_CLASSIFICATION_RANKS
        if data_classification not in ranks:
            raise CatalogError("run data classification is unknown")
        if (
            any(ordinal < 1 for ordinal in accepted_tool_ordinals)
            or tuple(sorted(set(accepted_tool_ordinals))) != accepted_tool_ordinals
        ):
            raise CatalogError("accepted Tool ordinals must be unique and strictly ordered")
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT b.profile_key,b.profile_version,b.profile_material_hash,
                          b.accepted_tool_count,b.effective_tool_set_hash,b.identity_ref,
                          b.runtime_region,b.classification_ceiling,
                          b.accepted_data_classification,
                          b.policy_head_activation_id,b.policy_head_epoch,
                          b.placement_epoch,b.accepted_step_budget_hash,
                          a.agent_key,a.agent_revision,a.budget_json,a.workspace_id
                     FROM solvan_operability.agent_run_tool_bindings b
                     JOIN solvan.agent_runs a ON
                       (a.organization_id,a.project_id,a.environment_id,a.id)=
                       (b.organization_id,b.project_id,b.environment_id,b.agent_run_id)
                    WHERE b.organization_id=%(organization_id)s
                      AND b.project_id=%(project_id)s
                      AND b.environment_id=%(environment_id)s
                      AND b.agent_run_id=%(agent_run_id)s""",
                {**scope.canonical_dict(), "agent_run_id": agent_run_id},
            )
            existing_binding = cursor.fetchone()
            if existing_binding is not None:
                cursor.execute(
                    """SELECT ordinal,tool_key,tool_version,binding_kind,
                              provider,capability_key,external_project_selector,
                              connection_id,connection_epoch,capability_receipt_id,
                              capability_receipt_hash,external_project_id
                         FROM solvan_operability.agent_run_accepted_tool_bindings
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND agent_run_id=%(agent_run_id)s
                        ORDER BY ordinal""",
                    {**scope.canonical_dict(), "agent_run_id": agent_run_id},
                )
                accepted_rows = cursor.fetchall()
                observed_connections = {
                    str(row["connection_id"]): int(row["connection_epoch"])
                    for row in accepted_rows
                    if row["connection_id"] is not None
                }
                observed_projects = {
                    str(row["external_project_id"])
                    for row in accepted_rows
                    if row["external_project_id"] is not None
                }
                observed_ordinals = tuple(int(row["ordinal"]) for row in accepted_rows)
                replay_budget = self._run_budget(
                    material=dict(existing_binding["budget_json"]),
                    workspace=existing_binding["workspace_id"] is not None,
                )
                expected = (
                    profile_key,
                    profile_version,
                    len(accepted_rows),
                    accepted_tool_ordinals,
                    identity_ref,
                    runtime_region,
                    data_classification,
                    connection_epochs,
                    ({target_external_project_id} if target_external_project_id else set()),
                    policy_head_activation_id,
                    policy_head_epoch,
                    placement_epoch,
                    accepted_step_budget_hash(replay_budget),
                )
                observed = (
                    existing_binding["profile_key"],
                    existing_binding["profile_version"],
                    existing_binding["accepted_tool_count"],
                    observed_ordinals,
                    existing_binding["identity_ref"],
                    existing_binding["runtime_region"],
                    existing_binding["accepted_data_classification"],
                    observed_connections,
                    observed_projects,
                    existing_binding["policy_head_activation_id"],
                    existing_binding["policy_head_epoch"],
                    existing_binding["placement_epoch"],
                    existing_binding["accepted_step_budget_hash"],
                )
                if observed != expected:
                    raise CatalogError("run already has a different frozen Tool binding")
                replay_tools = tuple(
                    ToolRevisionRefV1(
                        tool_key=str(row["tool_key"]), version=str(row["tool_version"])
                    )
                    for row in accepted_rows
                )
                replay_bindings = tuple(
                    EffectiveToolBindingV1(
                        tool=replay_tools[index],
                        binding_kind=ToolConnectionBindingKind(str(row["binding_kind"])),
                        provider=row["provider"],
                        capability_key=row["capability_key"],
                        external_project_selector=row["external_project_selector"],
                        connection_id=row["connection_id"],
                        connection_epoch=row["connection_epoch"],
                        capability_receipt_id=row["capability_receipt_id"],
                        capability_receipt_hash=row["capability_receipt_hash"],
                        external_project_id=row["external_project_id"],
                    )
                    for index, row in enumerate(accepted_rows)
                )
                replay_set = EffectiveToolSetV1(
                    profile_material_hash=str(existing_binding["profile_material_hash"]),
                    accepted_tools=replay_tools,
                    agent_key=str(existing_binding["agent_key"]),
                    agent_revision=str(existing_binding["agent_revision"]),
                    scope=scope.canonical_dict(),
                    connection_bindings=replay_bindings,
                    runtime_region=str(existing_binding["runtime_region"]),
                    accepted_data_classification=str(
                        existing_binding["accepted_data_classification"]
                    ),
                    classification_ceiling=str(existing_binding["classification_ceiling"]),
                    policy_head_activation_id=existing_binding["policy_head_activation_id"],
                    policy_head_epoch=int(existing_binding["policy_head_epoch"]),
                    placement_epoch=int(existing_binding["placement_epoch"]),
                    accepted_step_budget_hash=str(existing_binding["accepted_step_budget_hash"]),
                )
                if (
                    replay_set.effective_tool_set_hash
                    != existing_binding["effective_tool_set_hash"]
                ):
                    raise CatalogError("stored Tool binding no longer reconstructs its digest")
                return cast(str, existing_binding["effective_tool_set_hash"])
            cursor.execute(
                """SELECT a.agent_key,a.agent_revision,a.status,a.workspace_id,a.budget_json,
                          a.effective_tool_set_hash AS run_tool_set_hash,
                          p.*
                     FROM solvan.agent_runs a
                     JOIN solvan_operability.tool_profile_revisions p
                       ON p.profile_key=%(profile_key)s AND p.version=%(profile_version)s
                    WHERE a.organization_id=%(organization_id)s
                      AND a.project_id=%(project_id)s AND a.environment_id=%(environment_id)s
                      AND a.id=%(agent_run_id)s
                    """,
                {
                    **scope.canonical_dict(),
                    "agent_run_id": agent_run_id,
                    "profile_key": profile_key,
                    "profile_version": profile_version,
                },
            )
            profile = cursor.fetchone()
            if profile is None or profile["status"] != "CREATED":
                raise CatalogError("run is absent or no longer bindable")
            if profile["lifecycle"] != "APPROVED":
                raise CatalogError("only an approved exact profile may enter Runtime")
            if profile["allowed_agent_key"] != profile["agent_key"]:
                raise CatalogError("Tool profile belongs to another Agent")
            if profile["runtime_region"] not in {runtime_region, "POLICY_BOUND"}:
                raise CatalogError("Tool profile runtime region does not match the run")
            if ranks[data_classification] > ranks[str(profile["data_classification_ceiling"])]:
                raise CatalogError("run classification exceeds the Tool profile ceiling")
            cursor.execute(
                """SELECT m.ordinal,t.*,q.requester_key,
                          requirement.binding_kind, requirement.provider AS requirement_provider,
                          requirement.capability_key AS requirement_capability_key,
                          requirement.external_project_selector
                     FROM solvan_operability.tool_profile_members m
                     JOIN solvan_operability.tool_revisions t
                       ON (t.tool_key,t.version)=(m.tool_key,m.tool_version)
                     JOIN solvan_operability.tool_profile_connection_requirements requirement
                       ON (requirement.profile_key,requirement.profile_version,requirement.ordinal,
                           requirement.tool_key,requirement.tool_version)
                        = (m.profile_key,m.profile_version,m.ordinal,m.tool_key,m.tool_version)
                     LEFT JOIN solvan_operability.tool_revision_requesters q
                       ON (q.tool_key,q.tool_version,q.requester_key)=
                          (t.tool_key,t.version,%(agent_key)s)
                    WHERE m.profile_key=%(profile_key)s
                      AND m.profile_version=%(profile_version)s ORDER BY m.ordinal""",
                {
                    "agent_key": profile["agent_key"],
                    "profile_key": profile_key,
                    "profile_version": profile_version,
                },
            )
            profile_tool_rows = cursor.fetchall()
            profile_ordinals = {int(row["ordinal"]) for row in profile_tool_rows}
            if not set(accepted_tool_ordinals).issubset(profile_ordinals):
                raise CatalogError("accepted Tool subset names an ordinal outside the profile")
            accepted_ordinal_set = set(accepted_tool_ordinals)
            tool_rows = [
                row for row in profile_tool_rows if int(row["ordinal"]) in accepted_ordinal_set
            ]
            budget = self._run_budget(
                material=dict(profile["budget_json"]), workspace=profile["workspace_id"] is not None
            )
            budget_hash = accepted_step_budget_hash(budget)
            if not accepted_tool_ordinals and (
                profile_tool_rows or budget.max_tool_calls != 0 or budget.max_model_calls != 0
            ):
                raise CatalogError(
                    "an empty Tool selection requires a tool-less, zero-model, zero-Tool run"
                )
            if budget.max_tool_calls > int(profile["maximum_total_calls"]):
                raise CatalogError("accepted step Tool budget exceeds the approved profile")
            requires_connection = any(
                row["binding_kind"] == str(ToolConnectionBindingKind.POLICY_SOURCE_CONNECTION)
                for row in tool_rows
            )
            if requires_connection != bool(connection_epochs):
                raise CatalogError("run binding must match whether the profile has Tool reads")
            if tool_rows and not registered_gateway_destinations:
                raise CatalogError("explicit Gateway routes are required for Tool use")
            proven_connections: set[str] = set()
            accepted_tools: list[ToolRevisionRefV1] = []
            accepted_bindings: list[EffectiveToolBindingV1] = []
            for tool in tool_rows:
                revision_ref = f"{tool['tool_key']}@{tool['version']}"
                if tool["lifecycle"] != "APPROVED" or tool["requester_key"] is None:
                    raise CatalogError(f"Tool revision {revision_ref} is not approved for Agent")
                if tool["permission_class"] == "MUTATE":
                    raise CatalogError("a model-backed Agent profile cannot contain MUTATE")
                if data_classification not in tool["supported_data_classes_json"]:
                    raise CatalogError(
                        f"Tool revision {revision_ref} does not support the run classification"
                    )
                if runtime_region not in tool["runtime_regions_json"]:
                    raise CatalogError(f"Tool revision {revision_ref} is unavailable in region")
                if tool["gateway_destination"] not in registered_gateway_destinations:
                    raise CatalogError(f"Tool revision {revision_ref} has no Gateway route")
                if tool["binding_kind"] == str(ToolConnectionBindingKind.COMPUTE_ONLY):
                    accepted_tools.append(
                        ToolRevisionRefV1(
                            tool_key=str(tool["tool_key"]), version=str(tool["version"])
                        )
                    )
                    accepted_bindings.append(
                        EffectiveToolBindingV1(
                            tool=accepted_tools[-1],
                            binding_kind=ToolConnectionBindingKind.COMPUTE_ONLY,
                        )
                    )
                    continue
                if target_external_project_id is None or target_workload_region is None:
                    raise CatalogError(
                        "a policy-source Tool requires an exact frozen Graph target "
                        "project and region"
                    )
                candidates: list[dict[str, Any]] = []
                for connection_id, epoch in connection_epochs.items():
                    cursor.execute(
                        """SELECT p.id AS capability_receipt_id,
                                  p.receipt_hash AS capability_receipt_hash,
                                  p.connection_id,p.connection_epoch,
                                  coverage.external_project_id
                             FROM solvan_operability.tool_probe_receipts p
                            JOIN solvan.tenant_connections c ON
                              (c.organization_id,c.project_id,c.environment_id,c.id)=
                              (p.organization_id,p.project_id,p.environment_id,p.connection_id)
                            JOIN solvan_onboarding.connection_external_project_coverage coverage
                              ON (coverage.organization_id,coverage.project_id,
                                  coverage.environment_id,coverage.connection_id,
                                  coverage.connection_epoch)=
                                 (p.organization_id,p.project_id,p.environment_id,
                                  p.connection_id,p.connection_epoch)
                             AND coverage.capability_class=%(capability_key)s
                             AND coverage.external_project_id=%(external_project_id)s
                             AND coverage.workload_region=%(target_workload_region)s
                             AND coverage.probe_receipt_ref=p.receipt_ref
                            JOIN solvan_onboarding.environment_external_project_bindings authorized
                              ON (authorized.organization_id,authorized.project_id,
                                  authorized.environment_id,authorized.external_project_id)=
                                 (coverage.organization_id,coverage.project_id,
                                  coverage.environment_id,coverage.external_project_id)
                             AND authorized.workload_region=coverage.workload_region
                             AND authorized.is_current
                           WHERE p.organization_id=%(organization_id)s
                             AND p.project_id=%(project_id)s
                             AND p.environment_id=%(environment_id)s
                             AND p.connection_id=%(connection_id)s
                             AND p.connection_epoch=%(connection_epoch)s
                             AND p.tool_key=%(tool_key)s AND p.tool_version=%(tool_version)s
                             AND p.agent_key=%(agent_key)s AND p.identity_ref=%(identity_ref)s
                             AND p.registry_resource=%(registry_resource)s
                             AND p.network_policy_hash=%(network_policy_hash)s
                            AND p.outcome='PASSED' AND p.expires_at > now()
                            AND c.connection_epoch=p.connection_epoch
                            AND c.provider=ANY(%(providers)s)
                            AND c.availability IN ('READY','DEGRADED')
                            AND c.residency_region=%(runtime_region)s
                           ORDER BY p.observed_at DESC LIMIT 1""",
                        {
                            **scope.canonical_dict(),
                            "connection_id": connection_id,
                            "connection_epoch": epoch,
                            "tool_key": tool["tool_key"],
                            "tool_version": tool["version"],
                            "agent_key": profile["agent_key"],
                            "identity_ref": identity_ref,
                            "registry_resource": tool["registry_resource"],
                            "network_policy_hash": tool["network_policy_hash"],
                            "providers": list(tool["required_connection_providers_json"]),
                            "capability_key": tool["requirement_capability_key"],
                            "external_project_id": target_external_project_id,
                            "target_workload_region": target_workload_region,
                            "runtime_region": runtime_region,
                        },
                    )
                    candidate = cursor.fetchone()
                    if candidate is not None:
                        candidates.append(dict(candidate))
                if not candidates:
                    raise CatalogError(
                        f"Tool revision {revision_ref} has no current exact capability proof"
                    )
                if len(candidates) != 1:
                    raise CatalogError(
                        f"Tool revision {revision_ref} resolves to multiple eligible connections"
                    )
                candidate = candidates[0]
                proven_connections.add(str(candidate["connection_id"]))
                accepted_tools.append(
                    ToolRevisionRefV1(tool_key=str(tool["tool_key"]), version=str(tool["version"]))
                )
                accepted_bindings.append(
                    EffectiveToolBindingV1(
                        tool=accepted_tools[-1],
                        binding_kind=ToolConnectionBindingKind.POLICY_SOURCE_CONNECTION,
                        provider=str(tool["requirement_provider"]),
                        capability_key=str(tool["requirement_capability_key"]),
                        external_project_selector=str(tool["external_project_selector"]),
                        connection_id=str(candidate["connection_id"]),
                        connection_epoch=int(candidate["connection_epoch"]),
                        capability_receipt_id=str(candidate["capability_receipt_id"]),
                        capability_receipt_hash=str(candidate["capability_receipt_hash"]),
                        external_project_id=str(candidate["external_project_id"]),
                    )
                )
            if proven_connections != set(connection_epochs):
                raise CatalogError("one or more profile connections prove no frozen Tool")
            effective_set = EffectiveToolSetV1(
                profile_material_hash=str(profile["profile_material_hash"]),
                accepted_tools=tuple(accepted_tools),
                agent_key=str(profile["agent_key"]),
                agent_revision=str(profile["agent_revision"]),
                scope=scope.canonical_dict(),
                connection_bindings=tuple(accepted_bindings),
                runtime_region=runtime_region,
                accepted_data_classification=data_classification,
                classification_ceiling=str(profile["data_classification_ceiling"]),
                policy_head_activation_id=policy_head_activation_id,
                policy_head_epoch=policy_head_epoch,
                placement_epoch=placement_epoch,
                accepted_step_budget_hash=budget_hash,
            )
            effective_hash = effective_set.effective_tool_set_hash
            run_tool_set_hash = profile["run_tool_set_hash"]
            if run_tool_set_hash is not None and run_tool_set_hash != effective_hash:
                raise CatalogError(
                    "precommitted Runtime request disagrees with the resolved Tool binding"
                )
            if profile["workspace_id"] is not None and run_tool_set_hash is None:
                raise CatalogError("a Workspace request lacks its precommitted Tool-set hash")
            cursor.execute(
                """INSERT INTO solvan_operability.agent_run_tool_bindings
                     (organization_id,project_id,environment_id,agent_run_id,
                      profile_key,profile_version,profile_material_hash,accepted_tool_count,
                      effective_tool_set_hash,identity_ref,runtime_region,
                      accepted_data_classification,classification_ceiling,
                      policy_head_activation_id,
                      policy_head_epoch,placement_epoch,accepted_step_budget_hash)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(agent_run_id)s,%(profile_key)s,%(profile_version)s,
                           %(profile_material_hash)s,%(accepted_tool_count)s,
                           %(effective_hash)s,%(identity_ref)s,%(runtime_region)s,
                           %(accepted_data_classification)s,%(classification_ceiling)s,
                           %(policy_head_activation_id)s,
                           %(policy_head_epoch)s,%(placement_epoch)s,%(budget_hash)s)""",
                {
                    **scope.canonical_dict(),
                    "agent_run_id": agent_run_id,
                    "profile_key": profile_key,
                    "profile_version": profile_version,
                    "profile_material_hash": profile["profile_material_hash"],
                    "accepted_tool_count": len(accepted_bindings),
                    "effective_hash": effective_hash,
                    "identity_ref": identity_ref,
                    "runtime_region": runtime_region,
                    "accepted_data_classification": data_classification,
                    "classification_ceiling": profile["data_classification_ceiling"],
                    "policy_head_activation_id": policy_head_activation_id,
                    "policy_head_epoch": policy_head_epoch,
                    "placement_epoch": placement_epoch,
                    "budget_hash": budget_hash,
                },
            )
            for ordinal, binding in zip(accepted_tool_ordinals, accepted_bindings, strict=True):
                binding_row = binding.model_dump(mode="json")
                tool_ref = binding_row.pop("tool")
                cursor.execute(
                    """INSERT INTO solvan_operability.agent_run_accepted_tool_bindings
                         (organization_id,project_id,environment_id,agent_run_id,
                          profile_key,profile_version,ordinal,tool_key,tool_version,
                          binding_kind,provider,capability_key,external_project_selector,
                          connection_id,connection_epoch,capability_receipt_id,
                          capability_receipt_hash,external_project_id)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                               %(agent_run_id)s,%(profile_key)s,%(profile_version)s,
                               %(ordinal)s,%(tool_key)s,%(tool_version)s,%(binding_kind)s,
                               %(provider)s,%(capability_key)s,%(external_project_selector)s,
                               %(connection_id)s,%(connection_epoch)s,
                               %(capability_receipt_id)s,%(capability_receipt_hash)s,
                               %(external_project_id)s)""",
                    {
                        **scope.canonical_dict(),
                        "agent_run_id": agent_run_id,
                        "profile_key": profile_key,
                        "profile_version": profile_version,
                        "provider": None,
                        "capability_key": None,
                        "external_project_selector": None,
                        "connection_id": None,
                        "connection_epoch": None,
                        "capability_receipt_id": None,
                        "capability_receipt_hash": None,
                        "external_project_id": None,
                        "ordinal": ordinal,
                        "tool_key": tool_ref["tool_key"],
                        "tool_version": tool_ref["version"],
                        **binding_row,
                    },
                )
            cursor.execute(
                """UPDATE solvan.agent_runs
                      SET effective_tool_set_hash=%(effective_hash)s
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND id=%(agent_run_id)s AND status='CREATED'
                      AND (effective_tool_set_hash IS NULL OR
                           effective_tool_set_hash=%(effective_hash)s)""",
                {
                    **scope.canonical_dict(),
                    "agent_run_id": agent_run_id,
                    "effective_hash": effective_hash,
                },
            )
            if cursor.rowcount != 1:
                raise CatalogError("run Tool-set hash changed while the binding was frozen")
        return effective_hash
