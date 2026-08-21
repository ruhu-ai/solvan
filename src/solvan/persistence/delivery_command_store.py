"""Cloud SQL repository for immutable private delivery command material."""

from __future__ import annotations

from typing import Any, Protocol, cast

from psycopg import Connection
from psycopg.rows import dict_row
from pydantic import ValidationError

from solvan.application.delivery_commands import (
    DeliveryCommandError,
    DeliveryCommandKind,
    DeliveryCommandStatus,
    PrivateCommandRecord,
    PrivateCommandResponse,
)
from solvan.application.workspace_hashing import canonical_sha256
from solvan.domain import Scope


class DeliveryCommandConflict(DeliveryCommandError):
    """A command replay differs from the already durable outcome."""


class ImmutableCommandPayloadReader(Protocol):
    """Read one immutable, hash-bound command payload outside Cloud SQL."""

    def get_json(self, *, uri: str, expected_hash: str, max_bytes: int) -> object: ...


class PostgresDeliveryCommandStore:
    """Persist command material before dispatch and complete it exactly once."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def prepare(self, command: PrivateCommandRecord) -> bool:
        """Insert one PREPARED command; return false only for an exact replay."""

        if command.status is not DeliveryCommandStatus.PREPARED:
            raise DeliveryCommandError("only a PREPARED command can be persisted")
        values = self._values(command)
        with (
            self._connection.transaction(),
            self._connection.cursor(row_factory=dict_row) as cursor,
        ):
            cursor.execute(
                """INSERT INTO solvan_delivery.private_command_dispatches
                    (id,organization_id,project_id,environment_id,command_kind,subject_id,
                     material_hash,idempotency_key,payload_ref,payload_hash,payload_schema_hash,
                     admitted_caller_identity,admitted_audience_hash,deadline,
                     operation_key,operation_ordinal,status)
                   VALUES (%(command_id)s,%(organization_id)s,%(project_id)s,%(environment_id)s,
                     %(command_kind)s,%(subject_id)s,%(material_hash)s,%(idempotency_key)s,
                     %(payload_ref)s,%(payload_hash)s,%(payload_schema_hash)s,
                     %(admitted_caller_identity)s,%(admitted_audience_hash)s,%(deadline)s,
                     %(operation_key)s,%(operation_ordinal)s,'PREPARED')
                   ON CONFLICT DO NOTHING""",
                values,
            )
            if cursor.rowcount == 1:
                return True
            cursor.execute(
                """SELECT organization_id,project_id,environment_id,command_kind,subject_id,
                           material_hash,idempotency_key,payload_ref,payload_hash,payload_schema_hash,
                           admitted_caller_identity,admitted_audience_hash,deadline,
                           operation_key,operation_ordinal,status
                      FROM solvan_delivery.private_command_dispatches WHERE id=%(command_id)s""",
                values,
            )
            row = cursor.fetchone()
            expected = {
                **command.scope.canonical_dict(),
                "command_kind": command.command_kind.value,
                "subject_id": command.subject_id,
                "material_hash": command.material_hash,
                "idempotency_key": command.idempotency_key,
                "payload_ref": command.payload_ref,
                "payload_hash": command.payload_hash,
                "payload_schema_hash": command.payload_schema_hash,
                "admitted_caller_identity": command.admitted_caller_identity,
                "admitted_audience_hash": command.admitted_audience_hash,
                "deadline": command.deadline,
                "operation_key": values["operation_key"],
                "operation_ordinal": values["operation_ordinal"],
                "status": "PREPARED",
            }
            if row is None or dict(row) != expected:
                raise DeliveryCommandConflict(
                    "private command identifier or idempotency material conflicts"
                )
            return False

    def prepare_workspace_tool(self, command: PrivateCommandRecord) -> bool:
        """Reserve one sequential, profile-bound Workspace Tool call.

        The model supplies Tool arguments, never the ordinal or budget.  The
        Coordinator constructs this record and this transaction proves that it
        is the next call under the exact run/profile/guidance authority.
        """

        if command.command_kind is not DeliveryCommandKind.WORKSPACE_TOOL_INVOKE:
            raise DeliveryCommandError("workspace Tool reservation requires its exact command kind")
        revision = cast(str, command.payload["tool_revision"])
        ordinal = cast(int, command.payload["call_ordinal"])
        per_tool_limits = {
            "workspace.code-repair.read-artifact@1": 64,
            "workspace.code-repair.write-candidate-artifact@1": 32,
            "workspace.code-repair.run-in-sandbox@1": 8,
        }
        with (
            self._connection.transaction(),
            self._connection.cursor(row_factory=dict_row) as cursor,
        ):
            cursor.execute(
                """SELECT 1 FROM solvan_delivery.private_command_dispatches
                    WHERE id=%(command_id)s""",
                {"command_id": command.command_id},
            )
            if cursor.fetchone() is not None:
                return self.prepare(command)
            cursor.execute(
                """SELECT a.deadline,a.budget_json,a.effective_tool_set_hash,
                          b.effective_tool_set_hash AS bound_tool_set_hash,
                          b.profile_key,b.profile_version,
                          EXISTS (
                            SELECT 1
                              FROM solvan_delivery.repair_plan_guidance_selection_sets g
                             WHERE g.organization_id=a.organization_id
                               AND g.project_id=a.project_id
                               AND g.environment_id=a.environment_id
                               AND g.repair_plan_id=a.repair_plan_id
                               AND g.repair_plan_version=a.repair_plan_version
                               AND g.status='BOUND' AND g.bound_agent_run_id=a.id
                          ) AS guidance_bound,
                          EXISTS (
                            SELECT 1
                              FROM solvan_operability.agent_run_accepted_tool_bindings t
                             WHERE t.organization_id=a.organization_id
                               AND t.project_id=a.project_id
                               AND t.environment_id=a.environment_id
                               AND t.agent_run_id=a.id
                               AND t.tool_key=%(tool_key)s AND t.tool_version='1'
                          ) AS tool_bound
                     FROM solvan.agent_runs a
                     JOIN solvan.repair_plans p
                       ON (p.organization_id,p.project_id,p.environment_id,p.id)=
                          (a.organization_id,a.project_id,a.environment_id,a.repair_plan_id)
                     JOIN solvan_operability.agent_run_tool_bindings b
                       ON (b.organization_id,b.project_id,b.environment_id,b.agent_run_id)=
                          (a.organization_id,a.project_id,a.environment_id,a.id)
                    WHERE a.organization_id=%(organization_id)s
                      AND a.project_id=%(project_id)s
                      AND a.environment_id=%(environment_id)s
                      AND a.id=%(agent_run_id)s
                      AND a.agent_key='workspace-agent'
                      AND a.workspace_task_kind='REPAIR'
                      AND a.status IN ('DISPATCHED','RUNNING')
                      AND a.deadline>now() AND p.status='ACTIVE'
                      AND p.plan_version=a.repair_plan_version
                    FOR UPDATE OF a""",
                {
                    **command.scope.canonical_dict(),
                    "agent_run_id": command.subject_id,
                    "tool_key": revision.removesuffix("@1"),
                },
            )
            authority = cursor.fetchone()
            if (
                authority is None
                or authority["profile_key"] != "workspace.code-repair.v1"
                or authority["profile_version"] != "1"
                or authority["effective_tool_set_hash"] != authority["bound_tool_set_hash"]
                or authority["guidance_bound"] is not True
                or authority["tool_bound"] is not True
                or command.deadline > authority["deadline"]
            ):
                raise DeliveryCommandError("workspace Tool call lacks exact live run authority")
            budget = authority["budget_json"]
            if not isinstance(budget, dict) or type(budget.get("max_tool_calls")) is not int:
                raise DeliveryCommandError("workspace Tool run budget is malformed")
            cursor.execute(
                """SELECT count(*) AS total,
                          count(*) FILTER (WHERE operation_key=%(operation_key)s) AS per_tool
                     FROM solvan_delivery.private_command_dispatches
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND command_kind='WORKSPACE_TOOL_INVOKE'
                      AND subject_id=%(agent_run_id)s""",
                {
                    **command.scope.canonical_dict(),
                    "agent_run_id": command.subject_id,
                    "operation_key": revision,
                },
            )
            usage = cursor.fetchone()
            if usage is None:
                raise DeliveryCommandError("workspace Tool usage could not be read")
            total = int(usage["total"])
            per_tool = int(usage["per_tool"])
            if (
                ordinal != total + 1
                or total >= int(budget["max_tool_calls"])
                or per_tool >= per_tool_limits[revision]
            ):
                raise DeliveryCommandError("workspace Tool call exceeds its sequential budget")
            return self.prepare(command)

    def load(
        self,
        *,
        command_id: str,
        payload_reader: ImmutableCommandPayloadReader,
    ) -> PrivateCommandRecord:
        """Load immutable command authority and its exact content-addressed body.

        The private HTTP envelope is deliberately not a source of payload
        authority.  A receiver calls this before validating its envelope, so a
        forged or replayed body cannot steer an otherwise authentic command ID.
        """

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id,organization_id,project_id,environment_id,command_kind,subject_id,
                           material_hash,idempotency_key,payload_ref,payload_hash,payload_schema_hash,
                           admitted_caller_identity,admitted_audience_hash,deadline,status
                      FROM solvan_delivery.private_command_dispatches
                    WHERE id=%(command_id)s""",
                {"command_id": command_id},
            )
            row = cursor.fetchone()
        if row is None:
            raise DeliveryCommandError("private command does not exist")
        payload = payload_reader.get_json(
            uri=str(row["payload_ref"]),
            expected_hash=str(row["payload_hash"]),
            max_bytes=16_384,
        )
        if not isinstance(payload, dict) or any(not isinstance(key, str) for key in payload):
            raise DeliveryCommandError("private command payload has an invalid shape")
        if canonical_sha256(payload) != str(row["payload_hash"]):
            raise DeliveryCommandError("private command payload hash does not match durable record")
        try:
            return PrivateCommandRecord(
                command_id=str(row["id"]),
                scope=Scope(
                    str(row["organization_id"]),
                    str(row["project_id"]),
                    str(row["environment_id"]),
                ),
                command_kind=DeliveryCommandKind(str(row["command_kind"])),
                subject_id=str(row["subject_id"]),
                material_hash=str(row["material_hash"]),
                idempotency_key=str(row["idempotency_key"]),
                payload_ref=str(row["payload_ref"]),
                payload=cast(dict[str, Any], payload),
                payload_hash=str(row["payload_hash"]),
                payload_schema_hash=str(row["payload_schema_hash"]),
                admitted_caller_identity=str(row["admitted_caller_identity"]),
                admitted_audience_hash=str(row["admitted_audience_hash"]),
                deadline=cast(Any, row["deadline"]),
                status=DeliveryCommandStatus(str(row["status"])),
            )
        except (ValidationError, ValueError) as error:
            raise DeliveryCommandError("durable private command is malformed") from error

    def claim_for_issue(self, *, command_id: str) -> bool:
        """Atomically fence the sole first external effect for a command.

        A `False` result means that a previous worker already claimed or
        terminally resolved it.  The caller must load/reconcile that durable
        state; it must not call the external provider again.
        """

        return self._advance(
            command_id=command_id,
            expected=(DeliveryCommandStatus.PREPARED,),
            status=DeliveryCommandStatus.ISSUED,
        )

    def begin_reconciliation(self, *, command_id: str) -> bool:
        """Fence post-issue recovery before an authoritative provider read."""

        return self._advance(
            command_id=command_id,
            expected=(DeliveryCommandStatus.ISSUED,),
            status=DeliveryCommandStatus.RECONCILING,
        )

    def expire_prepared(self, *, command_id: str) -> bool:
        """Terminally expire an unissued command; issued work is reconciled."""

        return self._advance(
            command_id=command_id,
            expected=(DeliveryCommandStatus.PREPARED,),
            status=DeliveryCommandStatus.EXPIRED,
            completed=True,
        )

    def complete(
        self,
        response: PrivateCommandResponse,
        *,
        response_ref: str,
        response_hash: str,
    ) -> bool:
        """Persist one content-addressed response envelope exactly once."""

        if response.outcome.value not in {"ACCEPTED", "REFUSED", "AMBIGUOUS"}:
            raise DeliveryCommandError("retryable responses are not durable terminal outcomes")
        status = {
            "ACCEPTED": "SUCCEEDED",
            "REFUSED": "REFUSED",
            "AMBIGUOUS": "AMBIGUOUS",
        }[response.outcome.value]
        if not response_ref.startswith("gs://"):
            raise DeliveryCommandError("private command response reference must be a GCS URI")
        if response_hash != canonical_sha256(response.model_dump(mode="json")):
            raise DeliveryCommandError("private command response hash differs from its envelope")
        values = {
            "command_id": response.command_id,
            "status": status,
            "response_ref": response_ref,
            "response_hash": response_hash,
            "completed_at": response.observed_at,
        }
        with (
            self._connection.transaction(),
            self._connection.cursor(row_factory=dict_row) as cursor,
        ):
            cursor.execute(
                """UPDATE solvan_delivery.private_command_dispatches
                      SET status=%(status)s,response_ref=%(response_ref)s,
                          response_hash=%(response_hash)s,
                          completed_at=%(completed_at)s
                    WHERE id=%(command_id)s AND status IN ('PREPARED','ISSUED','RECONCILING')""",
                values,
            )
            if cursor.rowcount == 1:
                return True
            cursor.execute(
                """SELECT status,response_ref,response_hash
                      FROM solvan_delivery.private_command_dispatches
                    WHERE id=%(command_id)s""",
                values,
            )
            row = cursor.fetchone()
            if row is None or dict(row) != {
                "status": status,
                "response_ref": response_ref,
                "response_hash": response_hash,
            }:
                raise DeliveryCommandConflict(
                    "private command completion conflicts with durable outcome"
                )
            return False

    def load_terminal_response(
        self,
        *,
        command_id: str,
        payload_reader: ImmutableCommandPayloadReader,
    ) -> PrivateCommandResponse | None:
        """Return the exact prior terminal response, or none for live work."""

        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT status,response_ref,response_hash
                     FROM solvan_delivery.private_command_dispatches WHERE id=%(command_id)s""",
                {"command_id": command_id},
            )
            row = cursor.fetchone()
        if row is None:
            raise DeliveryCommandError("private command does not exist")
        if row["status"] not in {"SUCCEEDED", "REFUSED", "AMBIGUOUS"}:
            return None
        if not isinstance(row["response_ref"], str) or not isinstance(row["response_hash"], str):
            raise DeliveryCommandError("terminal private command has no response envelope")
        value = payload_reader.get_json(
            uri=row["response_ref"], expected_hash=row["response_hash"], max_bytes=16_384
        )
        try:
            response = PrivateCommandResponse.model_validate(value)
        except (ValidationError, ValueError) as error:
            raise DeliveryCommandError("terminal private command response is malformed") from error
        if response.command_id != command_id:
            raise DeliveryCommandError("terminal private command response has another identifier")
        return response

    def _advance(
        self,
        *,
        command_id: str,
        expected: tuple[DeliveryCommandStatus, ...],
        status: DeliveryCommandStatus,
        completed: bool = False,
    ) -> bool:
        if not expected:
            raise DeliveryCommandError("private command transition needs an expected state")
        values = {
            "command_id": command_id,
            "status": status.value,
            "expected": tuple(item.value for item in expected),
        }
        completed_clause = ",completed_at=now()" if completed else ""
        with (
            self._connection.transaction(),
            self._connection.cursor(row_factory=dict_row) as cursor,
        ):
            cursor.execute(
                f"""UPDATE solvan_delivery.private_command_dispatches
                       SET status=%(status)s{completed_clause}
                     WHERE id=%(command_id)s AND status = ANY(%(expected)s)""",
                values,
            )
            return cursor.rowcount == 1

    @staticmethod
    def _values(command: PrivateCommandRecord) -> dict[str, object]:
        workspace_tool = command.command_kind is DeliveryCommandKind.WORKSPACE_TOOL_INVOKE
        return {
            **command.scope.canonical_dict(),
            "command_id": command.command_id,
            "command_kind": command.command_kind.value,
            "subject_id": command.subject_id,
            "material_hash": command.material_hash,
            "idempotency_key": command.idempotency_key,
            "payload_ref": command.payload_ref,
            "payload_hash": command.payload_hash,
            "payload_schema_hash": command.payload_schema_hash,
            "admitted_caller_identity": command.admitted_caller_identity,
            "admitted_audience_hash": command.admitted_audience_hash,
            "deadline": command.deadline,
            "operation_key": command.payload["tool_revision"] if workspace_tool else None,
            "operation_ordinal": command.payload["call_ordinal"] if workspace_tool else None,
        }
