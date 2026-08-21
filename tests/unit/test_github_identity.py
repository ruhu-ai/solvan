from __future__ import annotations

import base64
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from solvan.application.github_identity import (
    OAuthClientProfile,
    authorization_url,
    new_link_challenge,
)
from solvan.platform.github_user_oauth import GitHubUserOAuthClient, GitHubUserOAuthError
from solvan.platform.kms_envelope import KmsEnvelopeCipher


class _Response:
    def __init__(self, status_code: int, body: dict[str, Any]) -> None:
        self.status_code = status_code
        self._body = body
        self.content = str(body).encode()

    def json(self) -> dict[str, Any]:
        return self._body

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError("http failure")


class _OAuthTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def post(self, url: str, **kwargs: Any) -> _Response:
        self.calls.append(("POST", url, kwargs))
        return _Response(
            200, {"access_token": "t" * 32, "token_type": "bearer", "expires_in": 3600}
        )

    def get(self, url: str, **kwargs: Any) -> _Response:
        self.calls.append(("GET", url, kwargs))
        return _Response(200, {"node_id": "MDQ6VXNlcjE=", "login": "reviewer-one"})


def _profile() -> OAuthClientProfile:
    return OAuthClientProfile(
        id="gop_00000000000000000000000001",
        client_id="client-id",
        client_secret_ref="projects/proj1/secrets/oauth/versions/1",
        authorization_endpoint="https://github.com/login/oauth/authorize",
        token_endpoint="https://github.com/login/oauth/access_token",
        api_base_url="https://api.github.com",
        callback_uri="https://console.example/github/oauth/callback",
        protocol_version="github-app-user-to-server-v1",
        configuration_hash="sha256:" + "a" * 64,
    )


def test_authorization_url_contains_only_fixed_profile_and_fresh_pkce_material() -> None:
    challenge = new_link_challenge()
    value = urlparse(authorization_url(profile=_profile(), challenge=challenge))
    query = parse_qs(value.query)

    assert f"{value.scheme}://{value.netloc}{value.path}" == _profile().authorization_endpoint
    assert query == {
        "client_id": [_profile().client_id],
        "redirect_uri": [_profile().callback_uri],
        "state": [challenge.state],
        "code_challenge": [challenge.challenge],
        "code_challenge_method": ["S256"],
    }
    assert len(bytes.fromhex(challenge.state_hash.removeprefix("sha256:"))) == 32


def test_oauth_client_uses_token_only_for_the_fixed_current_user_read() -> None:
    transport = _OAuthTransport()
    client = GitHubUserOAuthClient(
        transport=transport,
        token_endpoint=_profile().token_endpoint,
        api_base_url=_profile().api_base_url,
    )

    identity = client.exchange_and_identify(
        client_id="client-id",
        client_secret="secret",
        callback_uri=_profile().callback_uri,
        code="one-time-code",
        verifier="v" * 64,
    )

    assert identity.node_id == "MDQ6VXNlcjE="
    assert [(method, url) for method, url, _kwargs in transport.calls] == [
        ("POST", _profile().token_endpoint),
        ("GET", "https://api.github.com/user"),
    ]
    assert transport.calls[1][2]["headers"]["Authorization"] == f"Bearer {'t' * 32}"


def test_oauth_client_refuses_nonexpiring_user_token() -> None:
    transport = _OAuthTransport()

    def nonexpiring(_url: str, **_kwargs: Any) -> _Response:
        return _Response(200, {"access_token": "t" * 32, "token_type": "bearer"})

    transport.post = nonexpiring  # type: ignore[method-assign]
    client = GitHubUserOAuthClient(
        transport=transport,
        token_endpoint=_profile().token_endpoint,
        api_base_url=_profile().api_base_url,
    )
    with pytest.raises(GitHubUserOAuthError, match="TOKEN_POSTURE"):
        client.exchange_and_identify(
            client_id="client-id",
            client_secret="secret",
            callback_uri=_profile().callback_uri,
            code="one-time-code",
            verifier="v" * 64,
        )


class _KmsSession:
    def __init__(self) -> None:
        self.requests: list[tuple[str, dict[str, Any]]] = []

    def post(self, url: str, **kwargs: Any) -> _Response:
        self.requests.append((url, kwargs))
        if url.endswith(":encrypt"):
            return _Response(
                200,
                {
                    "ciphertext": base64.b64encode(b"ciphertext").decode(),
                    "name": (
                        "projects/project1/locations/europe-west1/keyRings/ring/cryptoKeys/"
                        "key/cryptoKeyVersions/2"
                    ),
                },
            )
        return _Response(200, {"plaintext": base64.b64encode(b"verifier").decode()})


def test_kms_cipher_binds_pkce_to_aad_and_exact_key() -> None:
    session = _KmsSession()
    key = "projects/project1/locations/europe-west1/keyRings/ring/cryptoKeys/key"
    cipher = KmsEnvelopeCipher(key=key, session=session)  # type: ignore[arg-type]
    encrypted = cipher.encrypt(b"verifier", aad=b"transaction")
    assert (
        cipher.decrypt(encrypted.ciphertext, key_version=encrypted.key_version, aad=b"transaction")
        == b"verifier"
    )
    assert all(
        request["json"]["additionalAuthenticatedData"] == base64.b64encode(b"transaction").decode()
        for _url, request in session.requests
    )
