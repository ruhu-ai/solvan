"""Test-only investigation dispatcher that SIGKILLs at a Runtime boundary."""

from __future__ import annotations

import argparse
import os
import signal
from uuid import UUID

import psycopg

from solvan.application import (
    CoordinatorAuthority,
    InvestigationCoordinator,
    RuntimeDispatch,
    RuntimeInvocationReceipt,
)
from solvan.application.effective_tool_set import (
    EffectiveToolBindingV1,
    EffectiveToolSetV1,
    ToolConnectionBindingKind,
    ToolRevisionRefV1,
    accepted_step_budget_hash,
)
from solvan.domain import Scope
from solvan.persistence import PostgresInvestigationStore


class CrashBinder:
    def __init__(self, *, boundary: str) -> None:
        self._boundary = boundary

    def bind(self, dispatch: RuntimeDispatch) -> EffectiveToolSetV1:
        if self._boundary == "after-created-before-provider":
            os.kill(os.getpid(), signal.SIGKILL)
        tools = tuple(
            ToolRevisionRefV1(tool_key=name, version="fixture")
            for name in dispatch.allowed_tool_names
        )
        return EffectiveToolSetV1(
            profile_material_hash="sha256:" + "c" * 64,
            accepted_tools=tools,
            agent_key=dispatch.agent_key,
            agent_revision=dispatch.agent_revision,
            scope=dispatch.scope.canonical_dict(),
            connection_bindings=tuple(
                EffectiveToolBindingV1(
                    binding_kind=ToolConnectionBindingKind.COMPUTE_ONLY, tool=tool
                )
                for tool in tools
            ),
            runtime_region="europe-west1",
            accepted_data_classification="INTERNAL",
            classification_ceiling="INTERNAL",
            policy_head_epoch=0,
            placement_epoch=1,
            accepted_step_budget_hash=accepted_step_budget_hash(dispatch.budget),
        )


class CrashRuntime:
    def __init__(self, *, database_url: str, marker: str) -> None:
        self._database_url = database_url
        self._marker = marker

    def invoke(self, dispatch: RuntimeDispatch) -> RuntimeInvocationReceipt:
        with psycopg.connect(self._database_url) as connection:
            connection.execute(
                """INSERT INTO solvan.fixture_admin_actions
                  (idempotency_key, action_id, request_id, before_generation,
                   after_generation, result)
                  VALUES (%s, %s, %s, 'before', 'after', 'EFFECT_CONFIRMED')
                  ON CONFLICT (idempotency_key) DO NOTHING""",
                (
                    self._marker,
                    f"runtime-provider-{self._marker}",
                    dispatch.invocation_id,
                ),
            )
            connection.commit()
        os.kill(os.getpid(), signal.SIGKILL)
        raise AssertionError("SIGKILL fixture must not return from Runtime invoke")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--environment-id", required=True)
    parser.add_argument("--incident-id", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--lease-token", required=True)
    parser.add_argument("--workflow-version", required=True, type=int)
    parser.add_argument(
        "--boundary",
        required=True,
        choices=("after-created-before-provider", "after-provider-acceptance"),
    )
    parser.add_argument("--marker", required=True)
    args = parser.parse_args()
    scope = Scope(args.organization_id, args.project_id, args.environment_id)
    with psycopg.connect(args.database_url) as connection:
        InvestigationCoordinator(
            PostgresInvestigationStore(connection),
            CrashRuntime(database_url=args.database_url, marker=args.marker),
            CrashBinder(boundary=args.boundary),
        ).dispatch_ready_steps(
            scope=scope,
            incident_id=args.incident_id,
            authority=CoordinatorAuthority(
                args.owner,
                UUID(args.lease_token),
                args.workflow_version,
            ),
        )


if __name__ == "__main__":
    main()
