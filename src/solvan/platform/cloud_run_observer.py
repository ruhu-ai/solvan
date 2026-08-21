"""Read-only Cloud Run service observation boundary for independent verification."""

from __future__ import annotations

import re
from typing import Any

from solvan.application.release_targets import ReleaseTargetObservation
from solvan.platform.google_rest import GoogleRestSession

_RESOURCE = re.compile(
    r"^projects/[a-z][a-z0-9-]{4,61}[a-z0-9]/locations/[a-z0-9-]+/"
    r"services/[a-z][a-z0-9-]{0,61}[a-z0-9]$"
)
_NAME = re.compile(r"^[a-z][a-z0-9-]{0,61}[a-z0-9]$")


class CloudRunObservationError(ValueError):
    pass


class CloudRunServiceObserver:
    """Expose one exact GET projection and no mutation method."""

    def __init__(
        self,
        *,
        session: GoogleRestSession,
        service_resource_name: str,
        runtime_service_account: str,
        container_name: str,
    ) -> None:
        if (
            _RESOURCE.fullmatch(service_resource_name) is None
            or not runtime_service_account.endswith(".iam.gserviceaccount.com")
            or _NAME.fullmatch(container_name) is None
        ):
            raise CloudRunObservationError("Cloud Run observation target is invalid")
        self._session = session
        self._resource = service_resource_name
        self._runtime_identity = runtime_service_account
        self._container_name = container_name

    def observe(self) -> ReleaseTargetObservation:
        response = self._session.get(f"https://run.googleapis.com/v2/{self._resource}", timeout=30)
        response.raise_for_status()
        value: Any = response.json()
        if not isinstance(value, dict) or value.get("name") != self._resource:
            raise CloudRunObservationError("Cloud Run returned another service")
        template = value.get("template")
        containers = template.get("containers") if isinstance(template, dict) else None
        traffic_raw = value.get("traffic")
        if (
            not isinstance(containers, list)
            or len(containers) != 1
            or not isinstance(traffic_raw, list)
        ):
            raise CloudRunObservationError("Cloud Run service projection is unsupported")
        container = containers[0]
        runtime_identity = template.get("serviceAccount") if isinstance(template, dict) else None
        if (
            not isinstance(container, dict)
            or runtime_identity != self._runtime_identity
            or container.get("name") != self._container_name
        ):
            raise CloudRunObservationError("Cloud Run registered runtime material changed")
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
            raise CloudRunObservationError("Cloud Run service authority is incomplete")
        traffic: list[tuple[str, int]] = []
        for item in traffic_raw:
            revision = item.get("revision") if isinstance(item, dict) else None
            percent = item.get("percent") if isinstance(item, dict) else None
            if not isinstance(revision, str) or type(percent) is not int or not 0 < percent <= 100:
                raise CloudRunObservationError("Cloud Run traffic projection is malformed")
            traffic.append((revision, percent))
        if sum(percent for _, percent in traffic) != 100:
            raise CloudRunObservationError("Cloud Run traffic assignment is incomplete")
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
