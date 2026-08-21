"""Typed private connector for the bounded payments connection-pool recycle."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Protocol

import httpx
from pydantic import AwareDatetime, BaseModel, ConfigDict

from solvan.application.actuator import (
    AmbiguousMutation,
    MutationCall,
    PredictedEffect,
    Reconciliation,
    ReconciliationResult,
    TargetObservation,
    UndoPlan,
)
from solvan.domain import ActionType, AuthorizedActionMaterial


class ConnectorContractError(RuntimeError):
    """The private endpoint returned an invalid or disallowed response."""


class AccessTokenProvider(Protocol):
    def token(self, *, audience: str) -> str: ...


class PoolState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pool_generation: str
    state_ref: str


class PoolOperation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    admin_operation: Literal["RECYCLE_DB_POOL"]
    drain_timeout_ms: int


class RecycleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str
    returned_at: AwareDatetime


class RecycleStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: Literal["EFFECT_CONFIRMED", "NO_EFFECT_CONFIRMED", "UNKNOWN"]
    state_ref: str | None
    pool_generation: str | None
    reconciled_at: AwareDatetime


class PaymentsAdminConnector:
    """Calls only the registered private payments-admin operation surface."""

    def __init__(
        self,
        *,
        base_url: str,
        token_provider: AccessTokenProvider,
        client: httpx.Client,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token_provider = token_provider
        self._client = client

    def observe(self, material: AuthorizedActionMaterial) -> TargetObservation:
        self._require_pool_recycle(material)
        response = self._client.get(
            f"{self._base_url}/v1/admin/connection-pool",
            headers=self._headers(),
        )
        self._raise_for_status(response)
        state = PoolState.model_validate(response.json())
        return TargetObservation(state.state_ref, state.pool_generation)

    def dry_run(
        self, material: AuthorizedActionMaterial, *, before_state: TargetObservation
    ) -> PredictedEffect:
        self._require_pool_recycle(material)
        operation = PoolOperation.model_validate(material.payload_object())
        if before_state.version != material.expected_target_version:
            raise ConnectorContractError("pool generation changed before dry run")
        return PredictedEffect.from_object(
            {
                "action_type": material.action_type.value,
                "from_pool_generation": before_state.version,
                "operation": operation.model_dump(mode="json"),
                "profile": "payments-pool-recycle.v1",
                "schema_version": 1,
                "target_key": material.target_key,
            },
            connector_revision="payments-admin-connector.v1",
        )

    def mutate(self, material: AuthorizedActionMaterial, *, idempotency_key: str) -> MutationCall:
        self._require_pool_recycle(material)
        try:
            response = self._client.post(
                f"{self._base_url}/v1/admin/connection-pool:recycle",
                headers={**self._headers(), "idempotency-key": idempotency_key},
                json={
                    "schema_version": 1,
                    "action_id": material.action_id,
                    "expected_pool_generation": material.expected_target_version,
                    "operation": material.payload_object(),
                },
            )
        except httpx.TimeoutException as error:
            raise AmbiguousMutation(None) from error
        self._raise_for_status(response)
        result = RecycleResponse.model_validate(response.json())
        return MutationCall(result.request_id, _datetime(result.returned_at))

    def derive_undo(
        self, material: AuthorizedActionMaterial, *, before_state: TargetObservation
    ) -> UndoPlan:
        operation = PoolOperation.model_validate(material.payload_object())
        return UndoPlan.from_object(
            {
                "before_state_ref": before_state.state_ref,
                "before_version": before_state.version,
                "compensating_operation": operation.model_dump(mode="json"),
                "profile": "payments-pool-recycle-compensation.v1",
                "schema_version": 1,
                "target_key": material.target_key,
            }
        )

    def reconcile(
        self, material: AuthorizedActionMaterial, *, idempotency_key: str
    ) -> Reconciliation:
        self._require_pool_recycle(material)
        response = self._client.get(
            f"{self._base_url}/v1/admin/actions/{material.action_id}",
            headers={**self._headers(), "idempotency-key": idempotency_key},
        )
        self._raise_for_status(response)
        status = RecycleStatus.model_validate(response.json())
        observation = None
        if status.state_ref is not None and status.pool_generation is not None:
            observation = TargetObservation(status.state_ref, status.pool_generation)
        return Reconciliation(
            ReconciliationResult(status.result),
            observation,
            _datetime(status.reconciled_at),
        )

    def _headers(self) -> dict[str, str]:
        token = self._token_provider.token(audience=self._base_url)
        return {"authorization": f"Bearer {token}", "content-type": "application/json"}

    @staticmethod
    def _require_pool_recycle(material: AuthorizedActionMaterial) -> None:
        if material.action_type is not ActionType.PAYMENTS_POOL_RECYCLE:
            raise ConnectorContractError("payments connector received unsupported action type")

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as error:
            raise ConnectorContractError(
                f"payments admin returned HTTP {response.status_code}"
            ) from error


def _datetime(value: datetime) -> datetime:
    return value
