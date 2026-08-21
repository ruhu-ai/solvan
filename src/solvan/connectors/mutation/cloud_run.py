"""Typed Cloud Run v2 traffic rollback connector with revision preconditions."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal, Protocol
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ConfigDict, Field

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


class CloudRunConnectorError(RuntimeError):
    """Cloud Run request or response violated the rollback contract."""


class AccessTokenProvider(Protocol):
    def token(self, *, scopes: tuple[str, ...]) -> str: ...


class RollbackPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service_name: str
    known_good_revision: str
    percent: Literal[100]


class TrafficStatus(BaseModel):
    model_config = ConfigDict(extra="ignore")

    revision: str | None = None
    percent: int = 0


class CloudRunService(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    name: str
    etag: str
    traffic_statuses: list[TrafficStatus] = Field(default_factory=list, alias="trafficStatuses")


class CloudOperation(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    done: bool = False
    error: dict[str, Any] | None = None


class CloudRunRollbackConnector:
    def __init__(
        self,
        *,
        token_provider: AccessTokenProvider,
        client: httpx.Client,
        api_url: str = "https://run.googleapis.com",
        sleep: Callable[[float], None] = time.sleep,
        operation_poll_seconds: float = 2.0,
        maximum_operation_polls: int = 45,
    ) -> None:
        if operation_poll_seconds < 0 or maximum_operation_polls < 1:
            raise ValueError("Cloud Run operation polling bounds are invalid")
        self._token_provider = token_provider
        self._client = client
        self._api_url = api_url.rstrip("/")
        self._sleep = sleep
        self._operation_poll_seconds = operation_poll_seconds
        self._maximum_operation_polls = maximum_operation_polls

    def observe(self, material: AuthorizedActionMaterial) -> TargetObservation:
        payload = self._payload(material)
        service = self._get_service(payload.service_name)
        return TargetObservation(self._state_ref(service), self._active_revision(service))

    def dry_run(
        self, material: AuthorizedActionMaterial, *, before_state: TargetObservation
    ) -> PredictedEffect:
        payload = self._payload(material)
        if before_state.version != material.expected_target_version:
            raise CloudRunConnectorError("Cloud Run revision changed before dry run")
        return PredictedEffect.from_object(
            {
                "action_type": material.action_type.value,
                "from_revision": before_state.version,
                "profile": "cloud-run-traffic-replacement.v1",
                "schema_version": 1,
                "service_name": payload.service_name,
                "target_key": material.target_key,
                "traffic": [{"percent": payload.percent, "revision": payload.known_good_revision}],
            },
            connector_revision="cloud-run-rollback-connector.v1",
        )

    def mutate(self, material: AuthorizedActionMaterial, *, idempotency_key: str) -> MutationCall:
        payload = self._payload(material)
        service = self._get_service(payload.service_name)
        if self._active_revision(service) != material.expected_target_version:
            raise CloudRunConnectorError("Cloud Run revision changed before rollback")
        try:
            response = self._client.patch(
                self._service_url(payload.service_name),
                params={"updateMask": "traffic"},
                headers={**self._headers(), "x-solvan-idempotency-key": idempotency_key},
                json={
                    "name": payload.service_name,
                    "etag": service.etag,
                    "traffic": [
                        {
                            "type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",
                            "revision": payload.known_good_revision,
                            "percent": payload.percent,
                        }
                    ],
                },
            )
        except httpx.TimeoutException as error:
            raise AmbiguousMutation(None) from error
        self._raise_for_status(response)
        operation = CloudOperation.model_validate(response.json())
        self._await_operation(operation)
        return MutationCall(operation.name, datetime.now(UTC))

    def derive_undo(
        self, material: AuthorizedActionMaterial, *, before_state: TargetObservation
    ) -> UndoPlan:
        payload = self._payload(material)
        return UndoPlan.from_object(
            {
                "before_state_ref": before_state.state_ref,
                "expected_current_revision": payload.known_good_revision,
                "profile": "cloud-run-traffic-restoration.v1",
                "schema_version": 1,
                "service_name": payload.service_name,
                "target_key": material.target_key,
                "traffic": [{"percent": 100, "revision": before_state.version}],
            }
        )

    def reconcile(
        self, material: AuthorizedActionMaterial, *, idempotency_key: str
    ) -> Reconciliation:
        del idempotency_key
        payload = self._payload(material)
        service = self._get_service(payload.service_name)
        active_revision = self._active_revision(service)
        if active_revision == payload.known_good_revision:
            result = ReconciliationResult.EFFECT_CONFIRMED
        elif active_revision == material.expected_target_version:
            result = ReconciliationResult.NO_EFFECT_CONFIRMED
        else:
            result = ReconciliationResult.UNKNOWN
        return Reconciliation(
            result,
            TargetObservation(self._state_ref(service), active_revision),
            datetime.now(UTC),
        )

    def _get_service(self, service_name: str) -> CloudRunService:
        response = self._client.get(self._service_url(service_name), headers=self._headers())
        self._raise_for_status(response)
        return CloudRunService.model_validate(response.json())

    def _await_operation(self, operation: CloudOperation) -> None:
        current = operation
        for poll in range(self._maximum_operation_polls):
            if current.done:
                if current.error is not None:
                    raise CloudRunConnectorError("Cloud Run rollback operation failed")
                return
            if poll:
                self._sleep(self._operation_poll_seconds)
            try:
                response = self._client.get(
                    f"{self._api_url}/v2/{quote(current.name, safe='/')}",
                    headers=self._headers(),
                )
            except httpx.TimeoutException as error:
                raise AmbiguousMutation(current.name) from error
            self._raise_for_status(response)
            current = CloudOperation.model_validate(response.json())
        raise AmbiguousMutation(current.name)

    def _headers(self) -> dict[str, str]:
        token = self._token_provider.token(
            scopes=("https://www.googleapis.com/auth/cloud-platform",)
        )
        return {"authorization": f"Bearer {token}", "content-type": "application/json"}

    def _service_url(self, service_name: str) -> str:
        return f"{self._api_url}/v2/{quote(service_name, safe='/')}"

    @staticmethod
    def _payload(material: AuthorizedActionMaterial) -> RollbackPayload:
        if material.action_type is not ActionType.CLOUD_RUN_TRAFFIC_ROLLBACK:
            raise CloudRunConnectorError("Cloud Run connector received unsupported action type")
        return RollbackPayload.model_validate(material.payload_object())

    @staticmethod
    def _active_revision(service: CloudRunService) -> str:
        full_traffic = [
            status.revision
            for status in service.traffic_statuses
            if status.percent == 100 and status.revision is not None
        ]
        if len(full_traffic) != 1:
            raise CloudRunConnectorError("expected exactly one 100% Cloud Run revision")
        return full_traffic[0]

    @staticmethod
    def _state_ref(service: CloudRunService) -> str:
        return f"cloudrun://{service.name}?etag={quote(service.etag, safe='')}"

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as error:
            raise CloudRunConnectorError(
                f"Cloud Run API returned HTTP {response.status_code}"
            ) from error
