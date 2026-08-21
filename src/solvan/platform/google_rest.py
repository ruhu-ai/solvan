"""Small authenticated Google REST boundary shared by platform adapters."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, cast

import google.auth
from google.auth import impersonated_credentials
from google.auth.credentials import Credentials
from google.auth.transport.requests import AuthorizedSession

from solvan.platform.telemetry import (
    inject_trace_context,
    outbound_http_span,
    record_http_response,
)


class JsonResponse(Protocol):
    status_code: int
    headers: Mapping[str, str]
    content: bytes

    def raise_for_status(self) -> None: ...

    def json(self) -> Any: ...


class GoogleRestSession(Protocol):
    def request(self, method: str, url: str, **kwargs: Any) -> JsonResponse: ...

    def get(self, url: str, **kwargs: Any) -> JsonResponse: ...

    def post(self, url: str, **kwargs: Any) -> JsonResponse: ...

    def patch(self, url: str, **kwargs: Any) -> JsonResponse: ...

    def put(self, url: str, **kwargs: Any) -> JsonResponse: ...

    def delete(self, url: str, **kwargs: Any) -> JsonResponse: ...


class _RequestSession(Protocol):
    def request(self, method: str, url: str, **kwargs: Any) -> JsonResponse: ...


class TracePropagatingGoogleRestSession:
    """Inject active W3C context once at the authenticated REST boundary."""

    def __init__(self, delegate: _RequestSession) -> None:
        self._delegate = delegate

    def request(self, method: str, url: str, **kwargs: Any) -> JsonResponse:
        headers = kwargs.pop("headers", None)
        with outbound_http_span(method=method, url=url) as span:
            kwargs["headers"] = inject_trace_context(cast(Mapping[str, str] | None, headers))
            response = self._delegate.request(method, url, **kwargs)
            record_http_response(span, status_code=response.status_code)
            return response

    def get(self, url: str, **kwargs: Any) -> JsonResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> JsonResponse:
        return self.request("POST", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> JsonResponse:
        return self.request("PATCH", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> JsonResponse:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> JsonResponse:
        return self.request("DELETE", url, **kwargs)


def _service_account_email(principal: str) -> str:
    if not principal.startswith("serviceAccount:"):
        raise ValueError("a Google service account principal is required")
    return principal.removeprefix("serviceAccount:")


def authorized_session(
    *,
    delegator_principal: str | None = None,
    target_principal: str | None = None,
    lifetime_seconds: int | None = None,
    delegate_principals: tuple[str, ...] = (),
) -> GoogleRestSession:
    """Create a Google REST session.

    Direct customer reads are deliberately a distinct call shape. The token for
    the recorded customer reader service account is always minted by the exact
    recorded Solvan delegator: either the Cloud Run runtime identity is that
    delegator, or it reaches the reader only through a declared chain that ends
    at the delegator, which is the identity the customer's grant names. There is
    no environment-selected customer project, fallback source credential, or
    generic impersonation helper.
    """

    credentials, _project = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    return authorized_session_from_credentials(
        credentials,
        delegator_principal=delegator_principal,
        target_principal=target_principal,
        lifetime_seconds=lifetime_seconds,
        delegate_principals=delegate_principals,
    )


def authorized_session_from_credentials(
    credentials: Credentials,
    *,
    delegator_principal: str | None = None,
    target_principal: str | None = None,
    lifetime_seconds: int | None = None,
    delegate_principals: tuple[str, ...] = (),
) -> GoogleRestSession:
    """Create the same closed session from already-attested source credentials.

    This seam exists for the separate local reader entry point, which first
    mints the configured Solvan development identity from developer ADC. The
    deployed path still calls :func:`authorized_session` and therefore has no
    configuration-selected source credential.
    """

    supplied = (delegator_principal, target_principal, lifetime_seconds)
    if delegate_principals and not any(value is not None for value in supplied):
        raise ValueError("a delegation chain requires a complete impersonation binding")
    if any(value is not None for value in supplied):
        if not all(value is not None for value in supplied):
            raise ValueError("direct GCP authorization requires a complete impersonation binding")
        assert delegator_principal is not None
        assert target_principal is not None
        assert lifetime_seconds is not None
        source_email = getattr(credentials, "service_account_email", None)
        if not isinstance(source_email, str) or not source_email:
            raise RuntimeError("runtime credentials do not attest a service-account identity")
        delegator_email = _service_account_email(delegator_principal)
        delegates = [_service_account_email(value) for value in delegate_principals]
        if delegates:
            if delegates[-1] != delegator_email:
                raise RuntimeError("delegation chain does not end at the recorded Solvan delegator")
            if source_email == delegator_email:
                raise RuntimeError("the recorded Solvan delegator does not delegate to itself")
        elif source_email != delegator_email:
            raise RuntimeError("runtime identity does not match the recorded Solvan delegator")
        if not 1 <= lifetime_seconds <= 900:
            raise ValueError("direct GCP token lifetime must be between 1 and 900 seconds")
        credentials = impersonated_credentials.Credentials(  # type: ignore[no-untyped-call]
            source_credentials=credentials,
            target_principal=_service_account_email(target_principal),
            target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
            delegates=delegates or None,
            lifetime=lifetime_seconds,
        )
    delegate = cast(_RequestSession, AuthorizedSession(credentials))  # type: ignore[no-untyped-call]
    return TracePropagatingGoogleRestSession(delegate)
