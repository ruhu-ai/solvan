"""Redeeming an authorization code with an OpenID provider (spec 05 §4.2).

The only place Solvan talks to a token endpoint. It is separated from the routes
so the flow can be exercised without a network, and so the one place handling a
client secret is small enough to read in full.

Google is the only issuer of human identity for this product. `SOLVAN_TEST_ISSUER`
names the harness fixture the end-to-end suite signs in against, because the
alternative is a suite that injects a fabricated cookie and therefore never
exercises the callback, the nonce, or an expiry. The difference is *whom to
believe*, not *whether to check*: signature, issuer, audience and expiry are
verified either way, and the fixture is refused outright wherever Google Cloud
holds authority, so it cannot loosen a deployment.
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Any

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token

from solvan.application.oauth_login import (
    GOOGLE_AUTHORIZATION_ENDPOINT,
    GOOGLE_TOKEN_ENDPOINT,
    OAuthLoginError,
)

_TIMEOUT_SECONDS = 10


def _configured_issuer() -> str | None:
    """The harness fixture issuer, if one is named and this host may use it."""

    issuer = os.environ.get("SOLVAN_TEST_ISSUER", "").strip()
    if not issuer:
        return None
    if os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE") == "GOOGLE_CLOUD_IAM":
        # Narrowing, never widening: a deployment holding Google Cloud authority
        # uses Google, whatever configuration says.
        raise OAuthLoginError("a deployment cannot name a test identity issuer")
    return issuer.rstrip("/")


class GoogleAssertionVerifier:
    """Exchanges a code for an identity token and verifies it."""

    def __init__(self, *, client_secret_provider: Any = None) -> None:
        self._client_secret_provider = client_secret_provider or _client_secret

    def exchange(
        self, *, code: str, pkce_verifier: str, redirect_uri: str, audiences: tuple[str, ...]
    ) -> dict[str, Any]:
        client_id = audiences[0]
        issuer = _configured_issuer()
        if issuer is not None:
            return _exchange_with_issuer(
                issuer=issuer,
                code=code,
                pkce_verifier=pkce_verifier,
                redirect_uri=redirect_uri,
                client_id=client_id,
            )
        response = requests.post(
            GOOGLE_TOKEN_ENDPOINT,
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": self._client_secret_provider(),
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
                "code_verifier": pkce_verifier,
            },
            timeout=_TIMEOUT_SECONDS,
        )
        if response.status_code != 200:
            # The body can carry the code and the secret back; only the status
            # is safe to report.
            raise OAuthLoginError(
                f"the identity provider refused the authorization code ({response.status_code})"
            )
        token = response.json().get("id_token")
        if not isinstance(token, str) or not token:
            raise OAuthLoginError("the identity provider returned no identity token")
        # Verified against each accepted audience in turn, exactly as the
        # approval path does, so a rotation is one behaviour rather than two.
        for audience in audiences:
            try:
                claims: dict[str, Any] = id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
                    token, GoogleRequest(), audience=audience
                )
                return claims
            except (GoogleAuthError, ValueError):
                continue
        raise OAuthLoginError("the identity token was not minted for this deployment")


def _client_secret() -> str:
    """The confidential client's secret.

    A deployment sources this from Secret Manager under the environment's own
    project; it is never a downloaded key file on a development host.
    """

    secret = os.environ.get("SOLVAN_OAUTH_CLIENT_SECRET")
    if not secret:
        raise OAuthLoginError("no OAuth client secret is configured for this deployment")
    return secret


def _exchange_with_issuer(
    *, issuer: str, code: str, pkce_verifier: str, redirect_uri: str, client_id: str
) -> dict[str, Any]:
    """Redeem and verify against a discovered OpenID provider.

    The same checks Google's verifier performs, against the issuer's published
    keys: RS256 signature, issuer, audience, and expiry. Nothing is skipped
    because the provider is local.
    """

    discovery = requests.get(f"{issuer}/.well-known/openid-configuration", timeout=_TIMEOUT_SECONDS)
    if discovery.status_code != 200:
        raise OAuthLoginError("the configured identity issuer could not be discovered")
    document = discovery.json()
    if str(document.get("issuer", "")).rstrip("/") != issuer:
        raise OAuthLoginError("the issuer does not agree with its own discovery document")
    exchanged = requests.post(
        str(document["token_endpoint"]),
        data={
            "code": code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": pkce_verifier,
        },
        timeout=_TIMEOUT_SECONDS,
    )
    if exchanged.status_code != 200:
        raise OAuthLoginError(
            f"the identity provider refused the authorization code ({exchanged.status_code})"
        )
    token = exchanged.json().get("id_token")
    if not isinstance(token, str) or not token:
        raise OAuthLoginError("the identity provider returned no identity token")
    claims = _verified_claims(
        token=token, jwks_uri=str(document["jwks_uri"]), issuer=issuer, audience=client_id
    )
    return claims


def _verified_claims(*, token: str, jwks_uri: str, issuer: str, audience: str) -> dict[str, Any]:
    keys = requests.get(jwks_uri, timeout=_TIMEOUT_SECONDS)
    if keys.status_code != 200:
        raise OAuthLoginError("the identity issuer published no usable keys")
    header, payload, signature = _split(token)
    key = _public_key(keys.json(), key_id=header.get("kid"))
    try:
        key.verify(
            signature,
            f"{token.split('.')[0]}.{token.split('.')[1]}".encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as error:
        raise OAuthLoginError("the identity token signature is not valid") from error
    if str(payload.get("iss", "")).rstrip("/") != issuer:
        raise OAuthLoginError("the identity token names another issuer")
    if payload.get("aud") != audience:
        raise OAuthLoginError("the identity token was not minted for this deployment")
    if int(payload.get("exp", 0)) <= int(time.time()):
        raise OAuthLoginError("the identity token has expired")
    return payload


def _split(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    try:
        header_part, payload_part, signature_part = token.split(".")
        return (
            json.loads(_unpad(header_part)),
            json.loads(_unpad(payload_part)),
            _unpad(signature_part),
        )
    except (ValueError, json.JSONDecodeError) as error:
        raise OAuthLoginError("the identity token is not a well-formed assertion") from error


def _unpad(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _public_key(document: dict[str, Any], *, key_id: str | None) -> rsa.RSAPublicKey:
    for entry in document.get("keys", []):
        if key_id is not None and entry.get("kid") != key_id:
            continue
        if entry.get("kty") != "RSA":
            continue
        numbers = rsa.RSAPublicNumbers(
            e=int.from_bytes(_unpad(entry["e"]), "big"),
            n=int.from_bytes(_unpad(entry["n"]), "big"),
        )
        return numbers.public_key()
    raise OAuthLoginError("the identity issuer publishes no key for this token")


def authorization_endpoint() -> str:
    """Where to send the browser, for whichever issuer this host trusts.

    Verification was generalized before this was, so a development host
    exchanged codes with its local provider while sending people to Google —
    which answered, correctly, that it had never heard of the client.
    """

    issuer = _configured_issuer()
    if issuer is None:
        return GOOGLE_AUTHORIZATION_ENDPOINT
    discovery = requests.get(f"{issuer}/.well-known/openid-configuration", timeout=_TIMEOUT_SECONDS)
    if discovery.status_code != 200:
        raise OAuthLoginError("the configured identity issuer could not be discovered")
    document = discovery.json()
    # The same agreement check the token exchange performs. Without it this
    # returned whatever address the document named, and the browser was sent
    # there — a redirect target taken on the document's word alone. A provider
    # misconfigured to publish another address sent every sign-in to a port
    # nothing served; a document that could be tampered with would send them
    # somewhere worse.
    if str(document.get("issuer", "")).rstrip("/") != issuer:
        raise OAuthLoginError("the issuer does not agree with its own discovery document")
    return str(document["authorization_endpoint"])


def issuer_display_name() -> str:
    """What to call the provider on the sign-in screen.

    A button reading "Sign in with Google" that goes somewhere else is a false
    statement, however local the somewhere else is. This survives the move to a
    Google-only product for exactly that reason: while a host can still run
    against the harness fixture, a page that named Google unconditionally would
    be lying on precisely the hosts where it is easiest not to notice.
    """

    return "Google" if google_is_the_issuer() else "the test identity provider"


def google_is_the_issuer() -> bool:
    """Whether the trusted issuer is Google rather than the harness fixture.

    The one predicate behind both the audience shape a token must carry and the
    name the sign-in page prints. Derived from the resolved issuer rather than
    from configuration read a second time, so the two cannot disagree.
    """

    return _configured_issuer() is None
