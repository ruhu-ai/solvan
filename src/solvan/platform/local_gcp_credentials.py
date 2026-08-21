"""Short-lived Solvan development identity for local-connected GCP reads."""

from __future__ import annotations

import re

import google.auth
from google.auth import impersonated_credentials
from google.auth.credentials import Credentials
from google.auth.transport.requests import Request

_CLOUD_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


def development_credentials(*, service_account: str, refresh: bool = True) -> Credentials:
    """Mint the exact Solvan-owned development identity from developer ADC.

    A service-account key is refused. The source is either ordinary user/WIF
    ADC with no service-account identity, or an already impersonated credential
    for the exact requested account. Google IAM remains the authority deciding
    whether the developer may mint the short-lived token.
    """

    if (
        re.fullmatch(
            r"[a-z][a-z0-9-]{2,29}@[a-z][a-z0-9-]+\.iam\.gserviceaccount\.com",
            service_account,
        )
        is None
    ):
        raise ValueError("Solvan development identity is not a service-account email")
    source, _project = google.auth.default(scopes=[_CLOUD_SCOPE])
    source_email = getattr(source, "service_account_email", None)
    source_kind = type(source).__module__ + "." + type(source).__name__
    if source_email is not None and source_kind != (
        "google.auth.impersonated_credentials.Credentials"
    ):
        raise RuntimeError("service-account key or ambient workload ADC is not allowed locally")
    if source_email is not None and source_email != service_account:
        raise RuntimeError("ADC impersonates a different Solvan development identity")
    credentials: Credentials
    if source_email == service_account:
        credentials = source
    else:
        credentials = impersonated_credentials.Credentials(  # type: ignore[no-untyped-call]
            source_credentials=source,
            target_principal=service_account,
            target_scopes=[_CLOUD_SCOPE],
            lifetime=900,
        )
    if getattr(credentials, "service_account_email", None) != service_account:
        raise RuntimeError("development credentials do not attest the configured identity")
    if refresh:
        credentials.refresh(Request())  # type: ignore[no-untyped-call]
    return credentials
