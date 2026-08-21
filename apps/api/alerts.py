"""Private Cloud Monitoring alert ingress for specification 21."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Header, Request, Response, status
from psycopg.errors import UndefinedTable

from solvan.application.alert_ingress_parser import parse_source_qualification_push
from solvan.application.alert_triage import (
    AlertIngressError,
    AlertPolicyError,
    PubSubEnvelopeIdentity,
    canonicalize_cloud_monitoring_push,
    inspect_pubsub_envelope,
)
from solvan.domain import Scope
from solvan.persistence.alert_triage import AlertTriageRepository
from solvan.persistence.alert_triage_types import SourceQualificationDelivery
from solvan.platform.cloud_monitoring_alerts import (
    GooglePubSubPushIdentityVerifier,
    PushIdentityVerifier,
)


def alert_ingress_router(
    *,
    scope_provider: Callable[[], Scope],
    connect: Callable[[], Any],
    identity_verifier: PushIdentityVerifier | None = None,
) -> APIRouter:
    router = APIRouter()
    verifier = identity_verifier or GooglePubSubPushIdentityVerifier()

    @router.post("/api/internal/alert-sources/cloud-monitoring/pubsub-push/{connection_id}")
    async def cloud_monitoring_push(
        connection_id: str,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> Response:
        raw_body = await request.body()
        scope = scope_provider()
        qualification_delivery_id: str | None = None
        try:
            with connect() as connection, connection.transaction():
                repository = AlertTriageRepository(connection)
                binding = repository.source_binding(
                    scope=scope, connection_id=connection_id, require_qualified=False
                )
                try:
                    envelope, _message = inspect_pubsub_envelope(raw_body)
                except AlertIngressError:
                    digest = hashlib.sha256(raw_body).hexdigest()
                    envelope = PubSubEnvelopeIdentity(
                        message_id=f"invalid-{digest[:32]}",
                        subscription_name=binding.subscription_name,
                        publish_time=None,
                        envelope_hash=f"sha256:{digest}",
                    )
                identity = None
                try:
                    identity = verifier.verify(authorization=authorization, binding=binding)
                    try:
                        qualification_envelope, source_binding_id, configuration_digest = (
                            parse_source_qualification_push(raw_body)
                        )
                    except AlertIngressError:
                        # A normal provider alert is admitted only through the
                        # qualified binding; the preliminary lookup above is
                        # identity material for the separate proof path.
                        binding = repository.source_binding(
                            scope=scope, connection_id=connection_id, require_qualified=True
                        )
                        alert = canonicalize_cloud_monitoring_push(raw_body)
                        receipt = repository.record_committed_delivery(
                            binding=binding, identity=identity, alert=alert
                        )
                        if receipt.provider_generation_id is None:
                            raise AlertPolicyError(
                                "committed alert delivery has no provider generation"
                            ) from None
                        repository.project_provider_generation(
                            scope=scope,
                            provider_generation_id=receipt.provider_generation_id,
                        )
                    else:
                        if source_binding_id != binding.source_binding_id:
                            raise AlertIngressError("SOURCE_QUALIFICATION_BINDING_MISMATCH")
                        qualification_delivery_id = repository.qualify_source_binding(
                            scope=scope,
                            delivery=SourceQualificationDelivery(
                                source_binding_id=source_binding_id,
                                source_binding_epoch=binding.binding_epoch,
                                pubsub_message_id=qualification_envelope.message_id,
                                subscription_name=qualification_envelope.subscription_name,
                                authenticated_push_principal=identity.principal,
                                oidc_audience=identity.audience,
                                envelope_hash=qualification_envelope.envelope_hash,
                                configuration_digest=configuration_digest,
                            ),
                        )
                except AlertIngressError as error:
                    receipt = repository.record_refused_delivery(
                        binding=binding,
                        envelope=envelope,
                        reason_code=error.reason_code,
                        authenticated_identity=identity,
                    )
            if qualification_delivery_id is not None:
                return _opaque_response(
                    status_code=status.HTTP_204_NO_CONTENT,
                    accepted=True,
                    receipt_id=qualification_delivery_id,
                )
            # A response-selection event is a second transaction so COMMITTED
            # is durable before the application chooses an HTTP result. It is
            # not represented as a Pub/Sub broker acknowledgement.
            with connect() as response_connection, response_connection.transaction():
                AlertTriageRepository(response_connection).record_response_selected(
                    scope=scope, receipt=receipt, success=receipt.outcome == "COMMITTED"
                )
        except UndefinedTable:
            return _opaque_response(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                accepted=False,
                receipt_id=None,
            )
        except (AlertIngressError, AlertPolicyError):
            return _opaque_response(
                status_code=status.HTTP_409_CONFLICT,
                accepted=False,
                receipt_id=None,
            )
        if receipt.outcome != "COMMITTED":
            refused_status = (
                status.HTTP_401_UNAUTHORIZED
                if receipt.reason_code.startswith("PUSH_IDENTITY")
                else status.HTTP_400_BAD_REQUEST
            )
            return _opaque_response(
                status_code=refused_status,
                accepted=False,
                receipt_id=receipt.delivery_id,
            )
        return _opaque_response(
            status_code=status.HTTP_204_NO_CONTENT,
            accepted=True,
            receipt_id=receipt.delivery_id,
        )

    return router


def _opaque_response(*, status_code: int, accepted: bool, receipt_id: str | None) -> Response:
    headers = {"Cache-Control": "no-store"}
    if receipt_id is not None:
        headers["X-Solvan-Receipt-ID"] = receipt_id
    if status_code == status.HTTP_204_NO_CONTENT:
        return Response(status_code=status_code, headers=headers)
    return Response(
        content=json.dumps({"accepted": accepted}, separators=(",", ":")),
        status_code=status_code,
        media_type="application/json",
        headers=headers,
    )
