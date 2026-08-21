"""Provider-neutral release-target observation contract."""

from __future__ import annotations

from dataclasses import dataclass

from solvan.application.workspace_hashing import canonical_sha256


@dataclass(frozen=True, slots=True)
class ReleaseTargetObservation:
    resource_name: str
    etag: str
    generation: int
    runtime_service_account: str
    container_name: str
    image: str
    latest_ready_revision: str
    traffic: tuple[tuple[str, int], ...]

    @property
    def assignment_hash(self) -> str:
        return canonical_sha256(
            {
                "schema_version": 1,
                "resource_name": self.resource_name,
                "generation": self.generation,
                "latest_ready_revision": self.latest_ready_revision,
                "traffic": [list(item) for item in self.traffic],
            }
        )
