"""Fixed GitHub user-to-server OAuth calls used only by the identity broker."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol


class OAuthResponse(Protocol):
    status_code: int
    content: bytes

    def json(self) -> Any: ...


class OAuthTransport(Protocol):
    def post(self, url: str, **kwargs: Any) -> OAuthResponse: ...

    def get(self, url: str, **kwargs: Any) -> OAuthResponse: ...


class GitHubUserOAuthError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class GitHubUserIdentity:
    node_id: str
    login: str


class GitHubUserOAuthClient:
    def __init__(
        self, *, transport: OAuthTransport, token_endpoint: str, api_base_url: str
    ) -> None:
        if not token_endpoint.startswith("https://") or not api_base_url.startswith("https://"):
            raise ValueError("GitHub OAuth origins must use HTTPS")
        self._transport = transport
        self._token_endpoint = token_endpoint
        self._api_base_url = api_base_url.rstrip("/")

    def exchange_and_identify(
        self,
        *,
        client_id: str,
        client_secret: str,
        callback_uri: str,
        code: str,
        verifier: str,
    ) -> GitHubUserIdentity:
        if not code or len(code) > 1024 or not verifier or len(verifier) > 256:
            raise GitHubUserOAuthError("GITHUB_OAUTH_CALLBACK_MATERIAL_INVALID")
        response = self._transport.post(
            self._token_endpoint,
            headers={"Accept": "application/json"},
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": callback_uri,
                "code_verifier": verifier,
            },
            timeout=15,
            allow_redirects=False,
        )
        body = self._body(response, expected=200, maximum=32_768)
        token = body.get("access_token")
        token_type = body.get("token_type")
        expires_in = body.get("expires_in")
        valid_token = (
            isinstance(token, str)
            and 16 <= len(token) <= 4096
            and isinstance(token_type, str)
            and token_type.lower() == "bearer"
            and isinstance(expires_in, int)
            and 1 <= expires_in <= 28_800
        )
        body.clear()
        if not valid_token:
            raise GitHubUserOAuthError("GITHUB_OAUTH_TOKEN_POSTURE_REFUSED")
        assert isinstance(token, str)
        try:
            user_response = self._transport.get(
                f"{self._api_base_url}/user",
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=15,
                allow_redirects=False,
            )
            user = self._body(user_response, expected=200, maximum=32_768)
        finally:
            token = ""  # Minimize the lifetime of the only user credential in this process.
        node_id = user.get("node_id")
        login = user.get("login")
        if (
            not isinstance(node_id, str)
            or not 1 <= len(node_id) <= 255
            or not isinstance(login, str)
            or re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})?", login) is None
        ):
            raise GitHubUserOAuthError("GITHUB_OAUTH_USER_IDENTITY_INVALID")
        return GitHubUserIdentity(node_id=node_id, login=login)

    @staticmethod
    def _body(response: OAuthResponse, *, expected: int, maximum: int) -> dict[str, Any]:
        if response.status_code != expected or len(response.content) > maximum:
            raise GitHubUserOAuthError("GITHUB_OAUTH_PROVIDER_RESPONSE_REFUSED")
        body = response.json()
        if not isinstance(body, dict):
            raise GitHubUserOAuthError("GITHUB_OAUTH_PROVIDER_RESPONSE_INVALID")
        return body
