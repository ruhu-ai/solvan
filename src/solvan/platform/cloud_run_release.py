"""Closed Cloud Run v2 revision-traffic adapter for governed release delivery."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from solvan.application.release_targets import ReleaseTargetObservation
from solvan.platform.google_rest import GoogleRestSession

_RESOURCE = re.compile(
    r"^projects/[a-z][a-z0-9-]{4,61}[a-z0-9]/locations/[a-z0-9-]+/"
    r"services/[a-z][a-z0-9-]{0,61}[a-z0-9]$"
)
_IMAGE = re.compile(r"^[a-z0-9.-]+/[a-z0-9_./-]+@sha256:[0-9a-f]{64}$")
_REVISION = re.compile(r"^[a-z][a-z0-9-]{0,61}[a-z0-9]$")


class CloudRunReleaseError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CloudRunOperation:
    name: str
    done: bool
    error_code: int | None
    error_message: str | None


class CloudRunReleaseClient:
    """Allow only one registered service and three fixed mutation shapes."""

    def __init__(
        self,
        *,
        session: GoogleRestSession,
        service_resource_name: str,
        runtime_service_account: str,
        container_name: str,
    ) -> None:
        if _RESOURCE.fullmatch(service_resource_name) is None:
            raise CloudRunReleaseError("Cloud Run service resource is invalid")
        if not runtime_service_account.endswith(".iam.gserviceaccount.com"):
            raise CloudRunReleaseError("Cloud Run runtime identity is invalid")
        if _REVISION.fullmatch(container_name) is None:
            raise CloudRunReleaseError("Cloud Run container name is invalid")
        self._session = session
        self._resource = service_resource_name
        self._runtime_identity = runtime_service_account
        self._container_name = container_name
        self._url = f"https://run.googleapis.com/v2/{service_resource_name}"

    def observe(self) -> ReleaseTargetObservation:
        response = self._session.get(self._url, timeout=30)
        response.raise_for_status()
        value = response.json()
        if not isinstance(value, dict) or value.get("name") != self._resource:
            raise CloudRunReleaseError("Cloud Run returned another service")
        template = value.get("template")
        containers = template.get("containers") if isinstance(template, dict) else None
        traffic_raw = value.get("traffic")
        if (
            not isinstance(containers, list)
            or len(containers) != 1
            or not isinstance(traffic_raw, list)
        ):
            raise CloudRunReleaseError("Cloud Run service projection is unsupported")
        container = containers[0]
        if not isinstance(container, dict):
            raise CloudRunReleaseError("Cloud Run container projection is malformed")
        runtime_identity = template.get("serviceAccount") if isinstance(template, dict) else None
        if (
            runtime_identity != self._runtime_identity
            or container.get("name") != self._container_name
        ):
            raise CloudRunReleaseError("Cloud Run registered runtime material changed")
        etag, generation = value.get("etag"), value.get("generation")
        image, latest = container.get("image"), value.get("latestReadyRevision")
        if (
            not isinstance(etag, str)
            or not etag
            or not isinstance(generation, str)
            or not generation.isdigit()
            or not isinstance(image, str)
            or not isinstance(latest, str)
        ):
            raise CloudRunReleaseError("Cloud Run service authority is incomplete")
        traffic: list[tuple[str, int]] = []
        for item in traffic_raw:
            revision = item.get("revision") if isinstance(item, dict) else None
            percent = item.get("percent") if isinstance(item, dict) else None
            if not isinstance(revision, str) or type(percent) is not int or not 0 < percent <= 100:
                raise CloudRunReleaseError("Cloud Run traffic projection is malformed")
            traffic.append((revision, percent))
        if sum(percent for _, percent in traffic) != 100:
            raise CloudRunReleaseError("Cloud Run traffic assignment is incomplete")
        return ReleaseTargetObservation(
            self._resource,
            etag,
            int(generation),
            runtime_identity,
            self._container_name,
            image,
            latest,
            tuple(sorted(traffic)),
        )

    def prepare_canary(
        self,
        *,
        expected: ReleaseTargetObservation,
        image: str,
        revision_name: str,
        canary_percent: int,
        predeploy_revision: str,
    ) -> CloudRunOperation:
        if (
            expected.resource_name != self._resource
            or _IMAGE.fullmatch(image) is None
            or _REVISION.fullmatch(revision_name) is None
            or _REVISION.fullmatch(predeploy_revision) is None
            or not 1 <= canary_percent < 100
        ):
            raise CloudRunReleaseError("Cloud Run canary material is invalid")
        body: dict[str, object] = {
            "name": self._resource,
            "etag": expected.etag,
            "template": {
                "revision": revision_name,
                "serviceAccount": self._runtime_identity,
                "containers": [{"name": self._container_name, "image": image}],
            },
            "traffic": [
                {
                    "type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",
                    "revision": revision_name,
                    "percent": canary_percent,
                },
                {
                    "type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",
                    "revision": predeploy_revision,
                    "percent": 100 - canary_percent,
                },
            ],
        }
        return self._patch(
            update_mask="template.revision,template.serviceAccount,template.containers,traffic",
            body=body,
        )

    def set_traffic(
        self,
        *,
        expected: ReleaseTargetObservation,
        assignments: tuple[tuple[str, int], ...],
    ) -> CloudRunOperation:
        if (
            expected.resource_name != self._resource
            or not assignments
            or sum(percent for _, percent in assignments) != 100
            or any(
                _REVISION.fullmatch(revision) is None or not 1 <= percent <= 100
                for revision, percent in assignments
            )
        ):
            raise CloudRunReleaseError("Cloud Run traffic mutation is invalid")
        return self._patch(
            update_mask="traffic",
            body={
                "name": self._resource,
                "etag": expected.etag,
                "traffic": [
                    {
                        "type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",
                        "revision": revision,
                        "percent": percent,
                    }
                    for revision, percent in assignments
                ],
            },
        )

    def operation(self, name: str) -> CloudRunOperation:
        if not name.startswith("projects/") or "/operations/" not in name:
            raise CloudRunReleaseError("Cloud Run operation name is invalid")
        response = self._session.get(
            f"https://run.googleapis.com/v2/{quote(name, safe='/')}", timeout=30
        )
        response.raise_for_status()
        return self._operation(response.json())

    def _patch(self, *, update_mask: str, body: dict[str, object]) -> CloudRunOperation:
        response = self._session.patch(
            self._url,
            params={"updateMask": update_mask},
            json=body,
            timeout=30,
        )
        response.raise_for_status()
        return self._operation(response.json())

    @staticmethod
    def _operation(value: Any) -> CloudRunOperation:
        if not isinstance(value, dict) or not isinstance(value.get("name"), str):
            raise CloudRunReleaseError("Cloud Run returned no operation authority")
        error = value.get("error")
        code = error.get("code") if isinstance(error, dict) else None
        message = error.get("message") if isinstance(error, dict) else None
        if (code is not None and type(code) is not int) or (
            message is not None and not isinstance(message, str)
        ):
            raise CloudRunReleaseError("Cloud Run operation error is malformed")
        return CloudRunOperation(
            name=str(value["name"]),
            done=value.get("done") is True,
            error_code=code,
            error_message=message[:500] if message else None,
        )
