"""Freeze an exact approved Tool profile before any Agent Runtime dispatch."""

from __future__ import annotations

from typing import Any

from psycopg import Connection

from apps.coordinator.contracts import GovernedAgentBinding
from solvan.application import RuntimeDispatch
from solvan.application.effective_tool_set import EffectiveToolSetV1
from solvan.domain import Scope
from solvan.persistence.operational_guidance_store import PostgresOperationalGuidanceStore
from solvan.persistence.operational_guidance_types import GuidanceSelectedMaterial
from solvan.persistence.tool_catalog_store import PostgresToolCatalogStore


class PostgresAgentRunBinder:
    def __init__(
        self,
        *,
        region: str,
        bindings: dict[str, GovernedAgentBinding],
        connection: Connection[Any],
    ) -> None:
        self._region = region
        self._bindings = bindings
        self._connection = connection
        self._store = PostgresToolCatalogStore(connection)

    def bind(self, dispatch: RuntimeDispatch) -> EffectiveToolSetV1:
        target_external_project_id = dispatch.context.get("target_external_project_id")
        if target_external_project_id is not None and not isinstance(
            target_external_project_id, str
        ):
            raise RuntimeError("frozen graph target project is malformed")
        target_workload_region = dispatch.context.get("target_workload_region")
        if target_workload_region is not None and (
            not isinstance(target_workload_region, str) or not target_workload_region
        ):
            raise RuntimeError("frozen graph target workload region is malformed")
        self.bind_run(
            scope=dispatch.scope,
            run_id=dispatch.run_id,
            agent_key=dispatch.agent_key,
            target_external_project_id=target_external_project_id,
            target_workload_region=target_workload_region,
            policy_head_activation_id=self._optional_string(
                dispatch.context, "policy_head_activation_id"
            ),
            policy_head_epoch=self._nonnegative_int(dispatch.context, "policy_head_epoch", 0),
            placement_epoch=self._positive_int(dispatch.context, "placement_epoch", 1),
        )
        return self._store.load_bound_effective_tool_set(
            scope=dispatch.scope, agent_run_id=dispatch.run_id
        )

    def bind_run(
        self,
        *,
        scope: Scope,
        run_id: str,
        agent_key: str,
        target_external_project_id: str | None = None,
        target_workload_region: str | None = None,
        policy_head_activation_id: str | None = None,
        policy_head_epoch: int = 0,
        placement_epoch: int = 1,
    ) -> str:
        try:
            binding = self._bindings[agent_key]
        except KeyError as error:
            raise RuntimeError(f"governed Tool binding for {agent_key} is missing") from error
        return self._store.resolve_and_bind_run(
            scope=scope,
            agent_run_id=run_id,
            profile_key=binding.profile_key,
            profile_version=binding.profile_version,
            identity_ref=binding.identity_ref,
            runtime_region=self._region,
            data_classification=binding.data_classification,
            accepted_tool_ordinals=binding.accepted_tool_ordinals,
            connection_epochs=binding.connection_epochs,
            registered_gateway_destinations=binding.gateway_destinations,
            target_external_project_id=target_external_project_id,
            target_workload_region=target_workload_region,
            policy_head_activation_id=policy_head_activation_id,
            policy_head_epoch=policy_head_epoch,
            placement_epoch=placement_epoch,
        )

    @staticmethod
    def _optional_string(context: dict[str, Any], key: str) -> str | None:
        value = context.get(key)
        if value is not None and (not isinstance(value, str) or not value):
            raise RuntimeError(f"frozen {key} is malformed")
        return value

    @staticmethod
    def _nonnegative_int(context: dict[str, Any], key: str, default: int) -> int:
        value = context.get(key, default)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise RuntimeError(f"frozen {key} is malformed")
        return value

    @staticmethod
    def _positive_int(context: dict[str, Any], key: str, default: int) -> int:
        value = context.get(key, default)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise RuntimeError(f"frozen {key} is malformed")
        return value

    def bind_trigger_guidance(
        self, *, dispatch: RuntimeDispatch
    ) -> GuidanceSelectedMaterial | None:
        binding = self._bindings[dispatch.agent_key]
        guidance = PostgresOperationalGuidanceStore(self._connection)
        exact = guidance.trigger_guidance_for_run(
            scope=dispatch.scope, agent_run_id=dispatch.run_id
        )
        if exact is None:
            return None
        key, version, digest = exact
        return guidance.select_approved(
            scope=dispatch.scope,
            agent_run_id=dispatch.run_id,
            guidance_key=key,
            version=version,
            expected_guidance_hash=digest,
            runtime_region=self._region,
            purpose="INCIDENT_INVESTIGATION",
            data_classification=binding.data_classification,
            role="PRIMARY",
            reason="Exact revision bound by the approved trigger policy.",
        )
