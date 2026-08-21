"""Closed client from the detector to the credential-bearing GCP reader."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

import httpx
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token

from solvan.application.detection import DetectionRule
from solvan.platform.cloud_monitoring import MetricObservation, ObservedResource
from solvan.platform.local_service_token import read_local_service_token


class DirectGcpDetectionClient:
    def observe(
        self, rule: DetectionRule, *, window_start: datetime, window_end: datetime
    ) -> MetricObservation:
        binding = rule.source_binding
        if binding is None:
            raise RuntimeError("detection rule has no exact source connection binding")
        resource_name = rule.query.get("resource_name")
        if not isinstance(resource_name, str) or not resource_name:
            raise ValueError("detection rule has no closed resource selector")
        body = {
            "schema_version": 1,
            "connection_id": binding.connection_id,
            "connection_epoch": binding.connection_epoch,
            "provider": "CLOUD_MONITORING",
            "authentication_mode": "GCP_SERVICE_ACCOUNT_IMPERSONATION",
            "solvan_delegator_principal": binding.solvan_delegator_principal,
            "customer_reader_principal": binding.customer_reader_principal,
            "token_lifetime_seconds": binding.token_lifetime_seconds,
            "resource_kind": "GCP_PROJECT",
            "resource_id": binding.external_project_id,
            "rule_id": rule.rule_id,
            "rule_version": rule.version,
            "signal_kind": rule.signal_kind,
            "resource_name": resource_name,
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
        }
        value = self._post(body)
        expected = (
            binding.connection_id,
            binding.connection_epoch,
            rule.rule_id,
            rule.version,
            binding.external_project_id,
        )
        observed = (
            value.get("connection_id"),
            value.get("connection_epoch"),
            value.get("rule_id"),
            value.get("rule_version"),
            value.get("observed_project_id"),
        )
        if observed != expected:
            raise RuntimeError("direct GCP reader response does not match the frozen request")
        request_ids = value.get("request_ids")
        labels = value.get("observed_labels")
        resource_type = value.get("observed_resource_type")
        observed_value = value.get("observed_value")
        if (
            not isinstance(request_ids, list)
            or any(not isinstance(item, str) for item in request_ids)
            or not isinstance(labels, dict)
            or any(
                not isinstance(key, str) or not isinstance(item, str)
                for key, item in labels.items()
            )
            or not isinstance(resource_type, str)
            or isinstance(observed_value, bool)
            or not isinstance(observed_value, int | float)
        ):
            raise RuntimeError("direct GCP reader returned malformed observation material")
        return MetricObservation(
            value=float(observed_value),
            request_ids=tuple(request_ids),
            resource=ObservedResource(
                project_id=binding.external_project_id,
                resource_type=resource_type,
                labels=tuple(sorted(labels.items())),
            ),
        )

    def _post(self, body: dict[str, object]) -> dict[str, object]:
        reader_url = os.environ.get("SOLVAN_DIRECT_GCP_READER_URL")
        reader_socket = os.environ.get("SOLVAN_LOCAL_DIRECT_GCP_READER_SOCKET")
        if bool(reader_url) == bool(reader_socket):
            raise RuntimeError("exactly one direct GCP reader transport must be configured")
        if reader_socket:
            socket_path = Path(reader_socket)
            if not socket_path.is_absolute() or socket_path.is_symlink():
                raise RuntimeError("local reader socket is unsafe")
            token = read_local_service_token()
            with httpx.Client(
                transport=httpx.HTTPTransport(uds=str(socket_path)),
                base_url="http://solvan-local-reader",
                timeout=35,
            ) as client:
                response = client.post(
                    "/internal/v1/detections:observe",
                    json=body,
                    headers={"Authorization": f"Bearer {token}"},
                )
        else:
            assert reader_url is not None
            if not reader_url.startswith("https://"):
                raise RuntimeError("deployed reader URL must use HTTPS")
            token = id_token.fetch_id_token(GoogleAuthRequest(), reader_url)  # type: ignore[no-untyped-call]
            response = httpx.post(
                f"{reader_url.rstrip('/')}/internal/v1/detections:observe",
                json=body,
                headers={"Authorization": f"Bearer {token}"},
                timeout=35,
            )
        response.raise_for_status()
        value = response.json()
        if not isinstance(value, dict):
            raise RuntimeError("direct GCP reader returned a non-object")
        return value
