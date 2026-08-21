"""Coordinator-side client for the private self-hosted Antigravity SDK provider."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast

import httpx
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token

from solvan.application import (
    WorkspaceArtifactDescriptor,
    WorkspaceContractError,
    WorkspaceProviderAttemptReceipt,
    WorkspaceRehydrationReceipt,
    WorkspaceRehydrationRequest,
    WorkspaceTaskInvocation,
    WorkspaceTaskResult,
    workspace_artifact_handle,
)
from solvan.platform.evidence_objects import ObjectReceipt


class AntigravityProviderError(RuntimeError):
    """The private provider failed or returned a result outside its durable fence."""


class IdentityTokenProvider(Protocol):
    def token(self, *, audience: str) -> str: ...


class WorkspaceObjectWriter(Protocol):
    def put_bytes(
        self, *, object_name: str, content: bytes, content_type: str
    ) -> ObjectReceipt: ...


class GoogleIdentityTokenProvider:
    def token(self, *, audience: str) -> str:
        token = id_token.fetch_id_token(  # type: ignore[no-untyped-call]
            GoogleAuthRequest(), audience
        )
        return cast(str, token)


@dataclass(frozen=True, slots=True)
class AntigravityProviderConfiguration:
    base_url: str
    audience: str
    provider_revision: str
    implementation_sdk_distribution_hash: str
    provider_artifact_digest: str
    effective_tool_set_hash: str
    effective_network_policy_hash: str
    artifact_bucket: str

    def __post_init__(self) -> None:
        if not self.base_url.startswith("https://") or self.base_url.endswith("/"):
            raise ValueError("Antigravity provider URL must be one HTTPS origin")
        if not self.audience.startswith("https://"):
            raise ValueError("Antigravity provider audience must be HTTPS")
        if not self.provider_revision:
            raise ValueError("Antigravity provider revision is required")
        for value in (
            self.implementation_sdk_distribution_hash,
            self.provider_artifact_digest,
            self.effective_tool_set_hash,
            self.effective_network_policy_hash,
        ):
            if len(value) != 71 or not value.startswith("sha256:"):
                raise ValueError("Antigravity provider hashes must be lowercase sha256 values")
        if not self.artifact_bucket or "/" in self.artifact_bucket:
            raise ValueError("workspace artifact bucket must be one bucket name")


class AntigravityWorkspaceProvider:
    """Invoke, fence, persist, and translate one self-hosted SDK attempt."""

    def __init__(
        self,
        *,
        config: AntigravityProviderConfiguration,
        client: httpx.AsyncClient,
        token_provider: IdentityTokenProvider,
        object_writer: WorkspaceObjectWriter,
    ) -> None:
        self._config = config
        self._client = client
        self._token_provider = token_provider
        self._object_writer = object_writer

    async def execute(self, invocation: WorkspaceTaskInvocation) -> WorkspaceTaskResult:
        self._validate_request(invocation)
        remaining = (invocation.deadline - datetime.now(UTC)).total_seconds()
        timeout = min(float(invocation.budget.max_runtime_seconds), remaining)
        if timeout <= 0:
            raise TimeoutError("workspace request expired before provider dispatch")
        token = await asyncio.to_thread(
            self._token_provider.token,
            audience=self._config.audience,
        )
        try:
            response = await self._client.post(
                f"{self._config.base_url}/internal/v1/workspace-tasks:execute",
                json=invocation.model_dump(mode="json"),
                headers={"Authorization": f"Bearer {token}"},
                timeout=timeout,
            )
            response.raise_for_status()
        except httpx.TimeoutException as error:
            raise TimeoutError("Antigravity provider request timed out") from error
        except httpx.HTTPError as error:
            raise AntigravityProviderError("Antigravity provider request failed") from error
        if len(response.content) > invocation.budget.max_output_bytes:
            raise AntigravityProviderError("Antigravity provider response exceeded its byte budget")
        try:
            attempt = WorkspaceProviderAttemptReceipt.model_validate_json(response.content)
            attempt.assert_matches(invocation)
            self._validate_attempt(attempt)
        except (ValueError, WorkspaceContractError) as error:
            raise AntigravityProviderError("Antigravity provider receipt was rejected") from error

        artifacts = await self._persist_candidates(invocation, attempt)
        result_ref = self._result_uri(invocation)
        proposal = attempt.proposal
        result = WorkspaceTaskResult.build(
            schema_version=1,
            request_id=invocation.request_id,
            request_hash=invocation.request_hash,
            run_id=invocation.run_id,
            invocation_id=invocation.invocation_id,
            workspace_id=invocation.workspace_id,
            workspace_generation=invocation.workspace_generation,
            task_kind=invocation.task_kind,
            provider=invocation.provider,
            provider_revision=attempt.provider_revision,
            provider_service_revision=attempt.provider_service_revision,
            provider_boot_hash=attempt.provider_boot_hash,
            implementation_sdk=attempt.implementation_sdk,
            implementation_sdk_version=attempt.implementation_sdk_version,
            implementation_sdk_distribution_hash=(attempt.implementation_sdk_distribution_hash),
            provider_artifact_digest=attempt.provider_artifact_digest,
            input_manifest_hash=attempt.input_manifest_hash,
            effective_tool_set_hash=attempt.effective_tool_set_hash,
            effective_network_policy_hash=attempt.effective_network_policy_hash,
            budget=invocation.budget,
            terminal_status=proposal.terminal_status,
            summary=proposal.summary,
            mechanism=proposal.mechanism,
            base_commit_sha=proposal.base_commit_sha,
            unified_diff=proposal.unified_diff,
            reproduction_command=proposal.reproduction_command,
            test_command=proposal.test_command,
            hypotheses=proposal.hypotheses,
            remediation_plan=proposal.remediation_plan,
            artifacts=artifacts,
            tool_receipts=attempt.tool_receipts,
            citations=proposal.citations,
            residual_risks=proposal.residual_risks,
            output_ref=result_ref,
            completed_at=attempt.completed_at,
            trace_id=attempt.trace_id,
            span_id=attempt.span_id,
        )
        result.assert_matches(invocation)
        content = json.dumps(
            result.model_dump(mode="json", exclude={"output_hash"}),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        receipt = await asyncio.to_thread(
            self._object_writer.put_bytes,
            object_name=self._result_object_name(invocation),
            content=content,
            content_type="application/json",
        )
        if receipt.uri != result_ref:
            raise AntigravityProviderError("workspace result persisted outside its expected path")
        if receipt.content_hash != result.output_hash:
            raise AntigravityProviderError("workspace result object hash is not canonical")
        return result

    async def rehydrate(self, request: WorkspaceRehydrationRequest) -> WorkspaceRehydrationReceipt:
        """Ask a fresh provider revision to consume one immutable checkpoint manifest."""

        if (
            request.provider_revision != self._config.provider_revision
            or request.implementation_sdk_distribution_hash
            != self._config.implementation_sdk_distribution_hash
            or request.provider_artifact_digest != self._config.provider_artifact_digest
            or request.effective_tool_set_hash != self._config.effective_tool_set_hash
            or request.effective_network_policy_hash != self._config.effective_network_policy_hash
        ):
            raise WorkspaceContractError("rehydration request does not match provider policy")
        token = await asyncio.to_thread(
            self._token_provider.token,
            audience=self._config.audience,
        )
        try:
            response = await self._client.post(
                f"{self._config.base_url}/internal/v1/workspaces:rehydrate",
                json=request.model_dump(mode="json"),
                headers={"Authorization": f"Bearer {token}"},
                timeout=60,
            )
            response.raise_for_status()
            receipt = WorkspaceRehydrationReceipt.model_validate_json(response.content)
            receipt.assert_matches(request)
        except httpx.HTTPError as error:
            raise AntigravityProviderError("Antigravity rehydration request failed") from error
        except ValueError as error:
            raise AntigravityProviderError(
                "Antigravity rehydration receipt was rejected"
            ) from error
        if (
            receipt.implementation_sdk_distribution_hash
            != self._config.implementation_sdk_distribution_hash
            or receipt.provider_artifact_digest != self._config.provider_artifact_digest
        ):
            raise AntigravityProviderError("rehydration SDK provenance changed")
        return receipt

    def _validate_request(self, invocation: WorkspaceTaskInvocation) -> None:
        if invocation.provider.value != "ANTIGRAVITY_SDK_CLOUD_RUN":
            raise WorkspaceContractError("the Antigravity adapter received another provider")
        pairs = (
            (invocation.provider_revision, self._config.provider_revision),
            (
                invocation.implementation_sdk_distribution_hash,
                self._config.implementation_sdk_distribution_hash,
            ),
            (invocation.provider_artifact_digest, self._config.provider_artifact_digest),
            (invocation.effective_tool_set_hash, self._config.effective_tool_set_hash),
            (
                invocation.effective_network_policy_hash,
                self._config.effective_network_policy_hash,
            ),
        )
        if any(actual != expected for actual, expected in pairs):
            raise WorkspaceContractError("workspace request does not match provider configuration")

    def _validate_attempt(self, attempt: WorkspaceProviderAttemptReceipt) -> None:
        if (
            attempt.implementation_sdk != "google-antigravity"
            or attempt.implementation_sdk_version != "0.1.13"
            or attempt.implementation_sdk_distribution_hash
            != self._config.implementation_sdk_distribution_hash
            or attempt.provider_artifact_digest != self._config.provider_artifact_digest
        ):
            raise WorkspaceContractError("provider SDK provenance does not match deployment")
        candidate_paths = {candidate.path for candidate in attempt.candidate_artifacts}
        if candidate_paths != set(attempt.proposal.candidate_artifact_paths):
            raise WorkspaceContractError("provider candidates do not match its proposal")

    async def _persist_candidates(
        self,
        invocation: WorkspaceTaskInvocation,
        attempt: WorkspaceProviderAttemptReceipt,
    ) -> tuple[WorkspaceArtifactDescriptor, ...]:
        descriptors: list[WorkspaceArtifactDescriptor] = []
        for candidate in sorted(attempt.candidate_artifacts, key=lambda item: item.path):
            receipt = await asyncio.to_thread(
                self._object_writer.put_bytes,
                object_name=self._candidate_object_name(invocation, candidate.path),
                content=candidate.content.encode("utf-8"),
                content_type=candidate.media_type,
            )
            if receipt.content_hash != candidate.content_hash:
                raise AntigravityProviderError("persisted candidate hash changed")
            descriptors.append(
                WorkspaceArtifactDescriptor(
                    artifact_handle=workspace_artifact_handle(candidate.path, receipt.content_hash),
                    path=candidate.path,
                    object_ref=receipt.uri,
                    content_hash=receipt.content_hash,
                    size_bytes=candidate.size_bytes,
                    media_type=candidate.media_type,
                    provenance_refs=(
                        invocation.request_hash,
                        invocation.input_manifest_hash,
                        attempt.response_hash,
                    ),
                )
            )
        return tuple(descriptors)

    def _prefix(self, invocation: WorkspaceTaskInvocation) -> str:
        return (
            f"workspaces/{invocation.workspace_id}/generation-{invocation.workspace_generation}/"
            f"runs/{invocation.run_id}"
        )

    def _candidate_object_name(self, invocation: WorkspaceTaskInvocation, path: str) -> str:
        return f"{self._prefix(invocation)}/candidates/{path}"

    def _result_object_name(self, invocation: WorkspaceTaskInvocation) -> str:
        return f"{self._prefix(invocation)}/result.json"

    def _result_uri(self, invocation: WorkspaceTaskInvocation) -> str:
        return f"gs://{self._config.artifact_bucket}/{self._result_object_name(invocation)}"
