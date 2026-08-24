"""Fail-open, exact-scope Memory Bank hints for Evidence Agent requests."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg import Connection

from apps.coordinator.contracts import CoordinatorSettings
from solvan.application import (
    GovernedMemorySearchService,
    MemoryBankUnavailable,
    MemoryHint,
    MemoryReadGrant,
    MemorySearchQuery,
    RuntimeDispatch,
)
from solvan.domain import MemoryScope
from solvan.persistence.memory_store import PostgresMemoryStore
from solvan.platform.memory_bank import (
    GeminiMemoryBank,
    MemoryBankConfiguration,
    VertexMemoryAPI,
    resolve_engine_id,
)

_MEMORY_PURPOSE = "incident-patterns"


class EvidenceMemoryContextEnricher:
    """Construct reference-only context after platform search and SQL revalidation."""

    def __init__(
        self,
        *,
        settings: CoordinatorSettings,
        connection: Connection[Any],
        service: GovernedMemorySearchService | None = None,
    ) -> None:
        self._settings = settings
        self._connection = connection
        self._service = service

    def enrich(self, dispatch: RuntimeDispatch) -> dict[str, Any]:
        if dispatch.agent_key != "evidence-agent" or "memory_recall" in dispatch.context:
            return {}
        exact_scope = MemoryScope(
            dispatch.scope,
            _MEMORY_PURPOSE,
            self._settings.binding_for("evidence-agent").data_classification,
            self._settings.gcp_region,
        )
        now = datetime.now(UTC)
        objective = " ".join(
            value
            for value in (
                str(dispatch.context.get("incident_class", "")),
                str(dispatch.context.get("service_key", "")),
                "historical incident patterns",
            )
            if value
        )
        digest = hashlib.sha256(
            f"{dispatch.invocation_id}:{exact_scope.canonical_dict()}".encode()
        ).hexdigest()
        if self._service is None:
            try:
                self._service = self._service_for(self._settings, self._connection)
            except MemoryBankUnavailable:
                return self._envelope(exact_scope, ())
        hints = self._service.search(
            query=MemorySearchQuery(
                exact_scope=exact_scope,
                read_grant=MemoryReadGrant(
                    grant_ref=f"memory-read:sha256:{digest}",
                    audience="evidence-agent",
                    exact_scope=exact_scope,
                    expires_at=now + timedelta(minutes=2),
                ),
                objective=objective,
                maximum_results=5,
                token_budget=512,
                current_time_cutoff=now,
            )
        )
        return self._envelope(exact_scope, hints)

    @staticmethod
    def _envelope(exact_scope: MemoryScope, hints: tuple[MemoryHint, ...]) -> dict[str, Any]:
        return {
            "memory_recall": {
                "authority": "REFERENCE_ONLY_UNTRUSTED_HISTORICAL_CONTEXT",
                "exact_scope": exact_scope.canonical_dict(),
                "hints": [
                    {
                        "memory_resource": hint.memory_resource,
                        "memory_revision": hint.memory_revision,
                        "distance": hint.distance,
                        "fact_text": hint.fact_text,
                        "source_refs": list(hint.source_refs),
                        "trust_label": hint.trust_label,
                    }
                    for hint in hints
                ],
            }
        }

    @staticmethod
    def _service_for(
        settings: CoordinatorSettings, connection: Connection[Any]
    ) -> GovernedMemorySearchService:
        # Vertex names the deployed engine with the project number; accept
        # either spelling of this exact project/region and nothing else.
        try:
            engine_id = resolve_engine_id(
                settings.memory_bank_resource,
                project_id=settings.gcp_project_id,
                project_number=settings.gcp_project_number,
                location=settings.gcp_region,
            )
        except ValueError as error:
            raise RuntimeError(str(error)) from error
        config = MemoryBankConfiguration(
            settings.gcp_project_id,
            settings.gcp_region,
            engine_id,
            project_number=settings.gcp_project_number,
        )
        try:
            api = VertexMemoryAPI(
                project=settings.gcp_project_id,
                location=settings.gcp_region,
            )
        except Exception as error:
            raise MemoryBankUnavailable("Memory Bank client is unavailable") from error
        return GovernedMemorySearchService(
            search_port=GeminiMemoryBank(
                config=config,
                api=api,
            ),
            repository=PostgresMemoryStore(connection, scope=settings.scope),
        )
