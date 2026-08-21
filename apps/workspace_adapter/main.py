"""Private, deterministic admission boundary for Workspace code-repair tools."""

from __future__ import annotations

import base64
import os
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, status
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict, Field

from solvan.application.delivery_commands import (
    DeliveryCommandError,
    DeliveryCommandKind,
    DeliveryCommandStatus,
    DeliveryOutcome,
    DeliveryReasonCode,
    PrivateCommandEnvelope,
    PrivateCommandResponse,
)
from solvan.application.workspace_candidate import (
    CandidateFile,
    CandidateTree,
    candidate_tree_from_manifest,
)
from solvan.application.workspace_hashing import canonical_sha256, sha256_bytes
from solvan.application.workspaces import workspace_artifact_handle
from solvan.observability import instrument_fastapi
from solvan.persistence.delivery_command_store import PostgresDeliveryCommandStore
from solvan.persistence.workspace_repair_history import WorkspaceRepairConflict
from solvan.persistence.workspace_repair_store import (
    PostgresWorkspaceRepairStore,
)
from solvan.platform.database import connect_database
from solvan.platform.evidence_objects import GcsEvidenceReader, GcsEvidenceWriter
from solvan.platform.exploratory_sandbox import (
    CloudRunExploratorySandboxExecutor,
    ExploratorySandboxConfiguration,
    GoogleIdentityTokenProvider,
)
from solvan.platform.google_rest import authorized_session
from solvan.platform.repository_snapshot import parse_repository_snapshot


def _candidate_manifest(tree: CandidateTree) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "files": [
            {
                "path": item.path,
                "content_base64": base64.b64encode(item.content.encode()).decode(),
                "content_hash": item.content_hash,
            }
            for item in tree.files
        ],
    }


def _tree_from_manifest(value: dict[str, Any], *, globs: tuple[str, ...]) -> CandidateTree:
    try:
        return candidate_tree_from_manifest(value, allowed_file_globs=globs)
    except ValueError as error:
        raise WorkspaceRepairConflict("candidate manifest is invalid") from error


def _declared_input_manifest(
    value: dict[str, Any], *, resolved_input_paths: tuple[str, ...]
) -> dict[str, Any]:
    """Expose only the catalog's base-resolved files to the sandbox."""

    if set(value) != {"schema_version", "files"} or value["schema_version"] != 1:
        raise WorkspaceRepairConflict("candidate manifest has an unsupported shape")
    files = value["files"]
    if not isinstance(files, list):
        raise WorkspaceRepairConflict("candidate manifest files are malformed")
    by_path: dict[str, dict[str, Any]] = {}
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise WorkspaceRepairConflict("candidate manifest entry is malformed")
        path = str(item["path"])
        if path in by_path:
            raise WorkspaceRepairConflict("candidate manifest paths are not unique")
        by_path[path] = item
    if any(path not in by_path for path in resolved_input_paths):
        raise WorkspaceRepairConflict("catalog input disappeared from the candidate tree")
    return {
        "schema_version": 1,
        "files": [by_path[path] for path in resolved_input_paths],
    }


class AdapterSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    audience: str = Field(pattern=r"^https://")
    coordinator_principal: str = Field(min_length=3)
    sandbox_url: str = Field(pattern=r"^https://")
    sandbox_audience: str = Field(pattern=r"^https://")
    runtime_bucket: str = Field(min_length=3)
    sandbox_image_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @classmethod
    def from_env(cls) -> AdapterSettings:
        audience = os.environ.get("SOLVAN_WORKSPACE_ADAPTER_AUDIENCE")
        principal = os.environ.get("SOLVAN_COORDINATOR_SERVICE_ACCOUNT")
        sandbox_url = os.environ.get("SOLVAN_WORKSPACE_SANDBOX_URL")
        sandbox_audience = os.environ.get("SOLVAN_WORKSPACE_SANDBOX_AUDIENCE")
        runtime_bucket = os.environ.get("SOLVAN_RUNTIME_BUCKET")
        sandbox_image_hash = os.environ.get("SOLVAN_WORKSPACE_SANDBOX_IMAGE_HASH")
        if not all(
            (audience, principal, sandbox_url, sandbox_audience, runtime_bucket, sandbox_image_hash)
        ):
            raise RuntimeError("workspace adapter settings are required")
        return cls(
            audience=str(audience),
            coordinator_principal=f"serviceAccount:{principal}",
            sandbox_url=str(sandbox_url),
            sandbox_audience=str(sandbox_audience),
            runtime_bucket=str(runtime_bucket),
            sandbox_image_hash=str(sandbox_image_hash),
        )


def _authenticate(authorization: str | None, settings: AdapterSettings) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing workspace provider identity")
    try:
        claims = id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
            authorization.removeprefix("Bearer "), GoogleRequest(), audience=settings.audience
        )
    except (GoogleAuthError, ValueError) as error:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "invalid workspace provider identity"
        ) from error
    email = claims.get("email")
    expected = settings.coordinator_principal.removeprefix("serviceAccount:").lower()
    if (
        claims.get("email_verified") is not True
        or not isinstance(email, str)
        or email.lower() != expected
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "workspace provider is not admitted")
    return f"serviceAccount:{email.lower()}"


def _load_tree(
    *,
    command: Any,
    reader: GcsEvidenceReader,
    repair_store: PostgresWorkspaceRepairStore,
) -> tuple[Any, CandidateTree]:
    material = repair_store.load_candidate_material(
        scope=command.scope, agent_run_id=command.subject_id
    )
    if material.parent_manifest_ref is not None and material.parent_manifest_hash is not None:
        manifest = reader.get_json(
            uri=material.parent_manifest_ref,
            expected_hash=material.parent_manifest_hash,
            max_bytes=1_200_000,
        )
        tree = _tree_from_manifest(manifest, globs=material.allowed_file_globs)
        if not material.base_tree_hash:
            raise WorkspaceRepairConflict("candidate generation has no frozen base tree")
        return material, tree
    snapshot_value = reader.get_json(
        uri=material.repository_snapshot_ref,
        expected_hash=material.repository_snapshot_hash,
        max_bytes=800_000,
    )
    snapshot = parse_repository_snapshot(
        snapshot_value,
        expected_commit_sha=material.base_commit_sha,
        allowed_file_globs=material.allowed_file_globs,
        max_total_content_bytes=800_000,
    )
    return material, CandidateTree(
        tuple(CandidateFile(item.path, item.content) for item in snapshot.files),
        material.allowed_file_globs,
    )


def _read_artifact(
    *, command: Any, reader: GcsEvidenceReader, repair_store: PostgresWorkspaceRepairStore
) -> dict[str, Any]:
    tool_input = command.payload["tool_input"]
    offset = int(tool_input["offset_bytes"])
    limit = int(tool_input["limit_bytes"])
    if offset < 0 or not 1 <= limit <= 65_536:
        raise WorkspaceRepairConflict("workspace artifact slice is outside its ceiling")
    material, tree = _load_tree(command=command, reader=reader, repair_store=repair_store)
    handle = str(tool_input["artifact_handle"])
    by_handle = {
        workspace_artifact_handle(item.path, item.content_hash): item for item in tree.files
    }
    candidate = by_handle.get(handle)
    if candidate is not None:
        content = candidate.content.encode()
        media_type = "text/plain; charset=utf-8"
        content_hash = candidate.content_hash
    else:
        manifest = reader.get_json(
            uri=material.input_manifest_ref,
            expected_hash=material.input_manifest_hash,
            max_bytes=1_200_000,
        )
        entries = manifest.get("entries")
        if not isinstance(entries, list):
            raise WorkspaceRepairConflict("workspace input manifest entries are malformed")
        entry = next(
            (
                item
                for item in entries
                if isinstance(item, dict)
                and isinstance(item.get("path"), str)
                and isinstance(item.get("content_hash"), str)
                and workspace_artifact_handle(item["path"], item["content_hash"]) == handle
            ),
            None,
        )
        if entry is None or not str(entry.get("path", "")).startswith("guidance/"):
            raise WorkspaceRepairConflict("artifact handle is not visible to this run")
        content = reader.get_bytes(
            uri=str(entry["object_ref"]),
            expected_hash=str(entry["content_hash"]),
            max_bytes=65_536,
        )
        media_type = str(entry["media_type"])
        content_hash = str(entry["content_hash"])
    if offset > len(content):
        raise WorkspaceRepairConflict("workspace artifact offset exceeds its size")
    sliced = content[offset : offset + limit]
    try:
        text = sliced.decode("utf-8")
    except UnicodeDecodeError as error:
        raise WorkspaceRepairConflict("workspace artifact slice is not UTF-8 aligned") from error
    return {
        "schema_version": 1,
        "artifact_handle": handle,
        "content_hash": content_hash,
        "total_size_bytes": len(content),
        "offset_bytes": offset,
        "returned_bytes": len(sliced),
        "media_type": media_type,
        "content_utf8": text,
    }


def _write_candidate(
    *,
    command: Any,
    reader: GcsEvidenceReader,
    writer: GcsEvidenceWriter,
    repair_store: PostgresWorkspaceRepairStore,
) -> dict[str, Any]:
    material, tree = _load_tree(command=command, reader=reader, repair_store=repair_store)
    tool_input = command.payload["tool_input"]
    successor = tree.write(
        operation=str(tool_input["operation"]),
        relative_path=str(tool_input["relative_path"]),
        expected_prior_hash=(
            str(tool_input["expected_prior_hash"])
            if tool_input["expected_prior_hash"] is not None
            else None
        ),
        content_utf8=(
            str(tool_input["content_utf8"]) if tool_input["content_utf8"] is not None else None
        ),
    )
    manifest = _candidate_manifest(successor)
    prefix = (
        f"{command.scope.organization_id}/{command.scope.project_id}/"
        f"{command.scope.environment_id}/workspace-tools/{command.command_id}"
    )
    receipt = writer.put_json(object_name=f"{prefix}/candidate-manifest.json", value=manifest)
    base_tree_hash = material.base_tree_hash or tree.tree_hash
    generation = repair_store.append_generation(
        scope=command.scope,
        repair_plan_id=material.repair_plan_id,
        repair_plan_version=material.repair_plan_version,
        agent_run_id=command.subject_id,
        parent_generation_id=material.parent_generation_id,
        base_tree_hash=base_tree_hash,
        tree=successor,
        manifest_ref=receipt.uri,
        manifest_hash=receipt.content_hash,
        input_hash=canonical_sha256(
            {
                "command_material_hash": command.material_hash,
                "plan_content_hash": material.plan_content_hash,
                "parent_generation_id": material.parent_generation_id,
                "parent_tree_hash": tree.tree_hash,
            }
        ),
    )
    changed_path = str(tool_input["relative_path"])
    changed = next((item for item in successor.files if item.path == changed_path), None)
    return {
        "schema_version": 1,
        "candidate_generation_id": generation.generation_id,
        "candidate_tree_hash": successor.tree_hash,
        "artifact_handle": (
            workspace_artifact_handle(changed.path, changed.content_hash)
            if changed is not None
            else None
        ),
        "relative_path": changed_path,
        "content_hash": changed.content_hash if changed is not None else None,
        "operation": str(tool_input["operation"]),
    }


def _complete_result(
    *,
    command: Any,
    result: dict[str, Any],
    writer: GcsEvidenceWriter,
    observed_at: datetime,
) -> PrivateCommandResponse:
    prefix = (
        f"{command.scope.organization_id}/{command.scope.project_id}/"
        f"{command.scope.environment_id}/workspace-tools/{command.command_id}"
    )
    result_receipt = writer.put_json(object_name=f"{prefix}/receipt.json", value=result)
    response = PrivateCommandResponse(
        command_id=command.command_id,
        outcome=DeliveryOutcome.ACCEPTED,
        reason_code=DeliveryReasonCode.OPERATION_COMPLETED,
        receipt_ref=result_receipt.uri,
        receipt_hash=result_receipt.content_hash,
        observed_at=observed_at,
    )
    response_receipt = writer.put_json(
        object_name=f"{prefix}/command-response.json",
        value=response.model_dump(mode="json"),
    )
    with connect_database() as connection:
        PostgresDeliveryCommandStore(connection).complete(
            response,
            response_ref=response_receipt.uri,
            response_hash=response_receipt.content_hash,
        )
    return response


def _mark_ambiguous(*, command: Any, writer: GcsEvidenceWriter, observed_at: datetime) -> None:
    response = PrivateCommandResponse(
        command_id=command.command_id,
        outcome=DeliveryOutcome.AMBIGUOUS,
        reason_code=DeliveryReasonCode.EXTERNAL_STATE_AMBIGUOUS,
        observed_at=observed_at,
    )
    prefix = (
        f"{command.scope.organization_id}/{command.scope.project_id}/"
        f"{command.scope.environment_id}/workspace-tools/{command.command_id}"
    )
    receipt = writer.put_json(
        object_name=f"{prefix}/command-response.json",
        value=response.model_dump(mode="json"),
    )
    with connect_database() as connection:
        PostgresDeliveryCommandStore(connection).complete(
            response,
            response_ref=receipt.uri,
            response_hash=receipt.content_hash,
        )


def _run_in_sandbox(
    *, envelope: PrivateCommandEnvelope, authorization: str | None
) -> dict[str, Any]:
    settings = AdapterSettings.from_env()
    caller = _authenticate(authorization, settings)
    google = authorized_session()
    reader = GcsEvidenceReader(allowed_buckets=frozenset({settings.runtime_bucket}), session=google)
    writer = GcsEvidenceWriter(bucket=settings.runtime_bucket, session=google)
    started_at = datetime.now(UTC)
    try:
        with connect_database() as connection:
            commands = PostgresDeliveryCommandStore(connection)
            command = commands.load(command_id=envelope.command_id, payload_reader=reader)
            command.validate_envelope(
                envelope,
                caller_identity=caller,
                audience_hash=sha256_bytes(settings.audience.encode()),
                now=started_at,
            )
            prior = commands.load_terminal_response(
                command_id=command.command_id, payload_reader=reader
            )
            if prior is not None:
                result = (
                    reader.get_json(
                        uri=prior.receipt_ref,
                        expected_hash=prior.receipt_hash,
                        max_bytes=1_200_000,
                    )
                    if prior.receipt_ref is not None and prior.receipt_hash is not None
                    else None
                )
                return {"command": prior.model_dump(mode="json"), "result": result}
            if command.command_kind is not DeliveryCommandKind.WORKSPACE_TOOL_INVOKE:
                raise DeliveryCommandError("adapter accepts only Workspace Tool commands")
            revision = command.payload["tool_revision"]
            if revision in {
                "workspace.code-repair.read-artifact@1",
                "workspace.code-repair.write-candidate-artifact@1",
            }:
                repair_store = PostgresWorkspaceRepairStore(connection)
                if command.status is DeliveryCommandStatus.PREPARED:
                    if not commands.claim_for_issue(command_id=command.command_id):
                        raise DeliveryCommandError(
                            "workspace Tool command issue fence was already claimed"
                        )
                elif command.status is DeliveryCommandStatus.ISSUED:
                    if not commands.begin_reconciliation(command_id=command.command_id):
                        raise DeliveryCommandError(
                            "workspace Tool command reconciliation was already claimed"
                        )
                elif command.status is not DeliveryCommandStatus.RECONCILING:
                    raise DeliveryCommandError("workspace Tool command is no longer recoverable")
                try:
                    result = (
                        _read_artifact(
                            command=command,
                            reader=reader,
                            repair_store=repair_store,
                        )
                        if revision == "workspace.code-repair.read-artifact@1"
                        else _write_candidate(
                            command=command,
                            reader=reader,
                            writer=writer,
                            repair_store=repair_store,
                        )
                    )
                    response = _complete_result(
                        command=command,
                        result=result,
                        writer=writer,
                        observed_at=datetime.now(UTC),
                    )
                except Exception as error:
                    _mark_ambiguous(
                        command=command,
                        writer=writer,
                        observed_at=datetime.now(UTC),
                    )
                    raise HTTPException(
                        status.HTTP_409_CONFLICT,
                        "workspace Tool outcome is ambiguous and will not be replayed",
                    ) from error
                return {"command": response.model_dump(mode="json"), "result": result}
            if revision != "workspace.code-repair.run-in-sandbox@1":
                raise DeliveryCommandError("Workspace Tool revision is not implemented")
            if command.status is not DeliveryCommandStatus.PREPARED:
                _mark_ambiguous(
                    command=command,
                    writer=writer,
                    observed_at=datetime.now(UTC),
                )
                raise DeliveryCommandError(
                    "issued exploratory work cannot be executed a second time"
                )
            tool_input = command.payload["tool_input"]
            repair_store = PostgresWorkspaceRepairStore(connection)
            material = repair_store.load_exploratory_material(
                scope=command.scope,
                agent_run_id=command.subject_id,
                catalog_id=str(tool_input["test_command_id"]),
                candidate_tree_hash=str(tool_input["candidate_tree_hash"]),
            )
            manifest = reader.get_json(
                uri=material.candidate_manifest_ref,
                expected_hash=material.candidate_manifest_hash,
                max_bytes=1_200_000,
            )
            sandbox_manifest = _declared_input_manifest(
                manifest, resolved_input_paths=material.resolved_input_paths
            )
            sandbox_manifest_hash = canonical_sha256(sandbox_manifest)
            if not commands.claim_for_issue(command_id=command.command_id):
                raise DeliveryCommandError("workspace Tool command issue fence was already claimed")
        try:
            with httpx.Client() as client:
                sandbox = CloudRunExploratorySandboxExecutor(
                    config=ExploratorySandboxConfiguration(
                        base_url=settings.sandbox_url,
                        audience=settings.sandbox_audience,
                    ),
                    client=client,
                    token_provider=GoogleIdentityTokenProvider(),
                ).execute(
                    execution_name=command.command_id,
                    command=material.catalog_command,
                    candidate_manifest=sandbox_manifest,
                    candidate_manifest_hash=sandbox_manifest_hash,
                )
        except Exception as error:
            _mark_ambiguous(
                command=command,
                writer=writer,
                observed_at=datetime.now(UTC),
            )
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "exploratory sandbox outcome is ambiguous and will not be replayed",
            ) from error
        completed_at = datetime.now(UTC)
        prefix = (
            f"{command.scope.organization_id}/{command.scope.project_id}/"
            f"{command.scope.environment_id}/workspace-tools/{command.command_id}"
        )
        stdout = writer.put_bytes(
            object_name=f"{prefix}/stdout.bin",
            content=sandbox.stdout,
            content_type="application/octet-stream",
            allow_empty=True,
        )
        stderr = writer.put_bytes(
            object_name=f"{prefix}/stderr.bin",
            content=sandbox.stderr,
            content_type="application/octet-stream",
            allow_empty=True,
        )
        with connect_database() as connection:
            stored = PostgresWorkspaceRepairStore(connection).record_exploratory_receipt(
                scope=command.scope,
                material=material,
                sandbox_image_hash=settings.sandbox_image_hash,
                request_hash=sandbox.request_hash,
                exit_code=sandbox.exit_code,
                stdout_ref=stdout.uri,
                stdout_hash=stdout.content_hash,
                stderr_ref=stderr.uri,
                stderr_hash=stderr.content_hash,
                output_bytes=sandbox.output_bytes,
                started_at=started_at,
                completed_at=completed_at,
            )
            result = {
                "schema_version": 1,
                "trust_class": "EXPERIMENTAL",
                "receipt_id": stored.receipt_id,
                "command_catalog_id": material.catalog_command.command_id,
                "candidate_tree_hash": material.candidate_tree_hash,
                "exit_code": sandbox.exit_code,
                "stdout_utf8": sandbox.stdout.decode("utf-8", errors="replace"),
                "stderr_utf8": sandbox.stderr.decode("utf-8", errors="replace"),
                "stdout_hash": stdout.content_hash,
                "stderr_hash": stderr.content_hash,
                "request_hash": sandbox.request_hash,
            }
            receipt = writer.put_json(object_name=f"{prefix}/receipt.json", value=result)
            response = PrivateCommandResponse(
                command_id=command.command_id,
                outcome=DeliveryOutcome.ACCEPTED,
                reason_code=DeliveryReasonCode.OPERATION_COMPLETED,
                receipt_ref=receipt.uri,
                receipt_hash=receipt.content_hash,
                observed_at=completed_at,
            )
            response_receipt = writer.put_json(
                object_name=f"{prefix}/command-response.json",
                value=response.model_dump(mode="json"),
            )
            PostgresDeliveryCommandStore(connection).complete(
                response,
                response_ref=response_receipt.uri,
                response_hash=response_receipt.content_hash,
            )
        return {"command": response.model_dump(mode="json"), "result": result}
    except (DeliveryCommandError, WorkspaceRepairConflict, ValueError) as error:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "workspace Tool command was refused"
        ) from error


def create_app() -> FastAPI:
    app = FastAPI(title="Solvan Workspace Adapter", version="1.0.0")

    @app.get("/live")
    def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post("/internal/v1/workspace-tools:invoke")
    def invoke(
        envelope: PrivateCommandEnvelope, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        return _run_in_sandbox(envelope=envelope, authorization=authorization)

    instrument_fastapi(app, service_name="solvan-workspace-adapter")
    return app


app = create_app()
