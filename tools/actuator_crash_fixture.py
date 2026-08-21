"""Test-only actuator worker that SIGKILLs after its durable fixture effect."""

from __future__ import annotations

import argparse
import os
import signal
from datetime import UTC, datetime

import psycopg

from solvan.application import ActionActuator
from solvan.application.actions import ExecutionAuthorization
from solvan.application.actuator import (
    CustomerAuditRecord,
    MutationCall,
    PredictedEffect,
    Reconciliation,
    ReconciliationResult,
    TargetObservation,
    UndoPlan,
)
from solvan.domain import AuthorizedActionMaterial, Scope
from solvan.persistence import PostgresActionStore


class DatabaseFixtureConnector:
    """Make the synthetic external effect durable and independently observable."""

    def __init__(self, database_url: str, *, kill_after_effect: bool = False) -> None:
        self._database_url = database_url
        self._kill_after_effect = kill_after_effect
        self.mutate_calls = 0

    def observe(self, _material: AuthorizedActionMaterial) -> TargetObservation:
        with psycopg.connect(self._database_url) as connection:
            row = connection.execute(
                """SELECT state_value FROM solvan.fixture_runtime_state
                  WHERE state_key = 'pool_generation'"""
            ).fetchone()
        if row is None:
            raise RuntimeError("fixture pool generation is absent")
        version = f"pool-generation-{int(row[0])}"
        return TargetObservation(f"payments://connection-pool/{version}", version)

    def dry_run(
        self, material: AuthorizedActionMaterial, *, before_state: TargetObservation
    ) -> PredictedEffect:
        return PredictedEffect(material.expected_effect, "process-kill-fixture.v1")

    def derive_undo(
        self, material: AuthorizedActionMaterial, *, before_state: TargetObservation
    ) -> UndoPlan:
        return UndoPlan.from_object(
            {
                "before_state_ref": before_state.state_ref,
                "before_version": before_state.version,
                "profile": "process-kill-fixture-compensation.v1",
                "target_key": material.target_key,
            }
        )

    def mutate(self, material: AuthorizedActionMaterial, *, idempotency_key: str) -> MutationCall:
        self.mutate_calls += 1
        request_id = f"process-kill-{material.action_id}"
        with psycopg.connect(self._database_url) as connection, connection.transaction():
            row = connection.execute(
                """SELECT state_value FROM solvan.fixture_runtime_state
                  WHERE state_key = 'pool_generation' FOR UPDATE"""
            ).fetchone()
            if row is None:
                raise RuntimeError("fixture pool generation is absent")
            before_value = int(row[0])
            before = f"pool-generation-{before_value}"
            after = f"pool-generation-{before_value + 1}"
            inserted = connection.execute(
                """INSERT INTO solvan.fixture_admin_actions
                  (idempotency_key, action_id, request_id, before_generation,
                   after_generation, result)
                  VALUES (%s, %s, %s, %s, %s, 'EFFECT_CONFIRMED')
                  ON CONFLICT (idempotency_key) DO NOTHING RETURNING request_id""",
                (idempotency_key, material.action_id, request_id, before, after),
            ).fetchone()
            if inserted is not None:
                connection.execute(
                    """UPDATE solvan.fixture_runtime_state
                      SET state_value = %s, updated_at = now()
                      WHERE state_key = 'pool_generation'""",
                    (before_value + 1,),
                )
        if self._kill_after_effect:
            os.kill(os.getpid(), signal.SIGKILL)
        return MutationCall(request_id, datetime.now(UTC))

    def reconcile(
        self, material: AuthorizedActionMaterial, *, idempotency_key: str
    ) -> Reconciliation:
        with psycopg.connect(self._database_url) as connection:
            row = connection.execute(
                """SELECT request_id, after_generation
                  FROM solvan.fixture_admin_actions
                  WHERE idempotency_key = %s AND action_id = %s""",
                (idempotency_key, material.action_id),
            ).fetchone()
        if row is None:
            return Reconciliation(ReconciliationResult.NO_EFFECT_CONFIRMED, None, datetime.now(UTC))
        version = str(row[1])
        return Reconciliation(
            ReconciliationResult.EFFECT_CONFIRMED,
            TargetObservation(f"payments://connection-pool/{version}", version),
            datetime.now(UTC),
        )


class UnreachableAudit:
    def write(self, *, sink_ref: str, record: CustomerAuditRecord) -> str:
        del sink_ref, record
        raise AssertionError("SIGKILL fixture must die before customer audit")


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class CrashFixtureActionGate:
    """Test-only gate: target autonomy schemas are outside the base crash harness."""

    def check(self, *, scope: Scope, authority: ExecutionAuthorization) -> None:
        assert authority.material.scope == scope


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--environment-id", required=True)
    parser.add_argument("--action-id", required=True)
    parser.add_argument("--actuator-id", required=True)
    args = parser.parse_args()
    scope = Scope(args.organization_id, args.project_id, args.environment_id)
    with psycopg.connect(args.database_url) as connection:
        ActionActuator(
            store=PostgresActionStore(connection),
            connector=DatabaseFixtureConnector(args.database_url, kill_after_effect=True),
            customer_audit=UnreachableAudit(),
            clock=SystemClock(),
            actuator_id=args.actuator_id,
            actor_identity="spiffe://solvan/process-kill-fixture",
            reservation_ttl_ms=10_000,
            pre_mutation_gate=CrashFixtureActionGate(),
        ).execute(scope=scope, action_id=args.action_id, trace_id="f" * 32)


if __name__ == "__main__":
    main()
