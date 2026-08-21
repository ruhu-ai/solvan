"""Authenticate as the GitHub App and keep one live installation token.

A GitHub installation token expires roughly an hour after GitHub issues it, so
an integration holding a pasted token is authenticated only until that hour runs
out. Authentication is therefore established from the App's own private key: an
RS256 App JWT is signed for each exchange, GitHub answers with an installation
token and the instant it dies, and the token is replaced before that instant
rather than after a release mutation has already failed on it.

Two rules keep the credentials out of everything this module produces. The
private key and every minted token travel in holders that cannot be printed,
formatted, or serialized, and a failed exchange is described by its HTTP status
alone: a GitHub response body is untrusted data and a refusal can quote the
request that produced it.

Every failure raises. A provider that answered a Secret Manager outage or a
refused exchange with a stale token would authenticate a production mutation
with a credential nobody has proven is current.
"""

from __future__ import annotations

import base64
import json
import re
import threading
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

#: GitHub refuses an App JWT whose `exp` is more than ten minutes ahead of its
#: own clock. Nine minutes leaves headroom instead of testing that ceiling on
#: every exchange.
_JWT_LIFETIME_SECONDS = 540
#: `iat` is backdated so a slightly fast local clock cannot produce a JWT GitHub
#: reads as issued in the future.
_JWT_BACKDATE_SECONDS = 60
#: An installation token is replaced this far ahead of its declared expiry, so a
#: request already in flight cannot outlive the credential it carries.
_REFRESH_MARGIN_SECONDS = 300
#: A ceiling, not an assumption about how long GitHub issues tokens for. A
#: response declaring a longer life would otherwise pin a dead token in cache.
_MAXIMUM_TOKEN_LIFETIME_SECONDS = 3_600
_MAXIMUM_TOKEN_BYTES = 4_096
_MAXIMUM_EXCHANGE_BYTES = 65_536

#: Either the numeric App ID or the `Iv…` client ID GitHub now documents for
#: `iss`. Anything else is a misconfiguration, not a credential.
_APP_ID = re.compile(r"^(?:[1-9][0-9]{0,19}|Iv[0-9A-Za-z]{6,62})$")


class GitHubAppAuthenticationError(RuntimeError):
    """GitHub App authentication failed. The message never carries a credential."""


class SecretResolver(Protocol):
    """Resolve a Secret Manager reference. Implemented by SecretManagerReader."""

    def access(self, resource: str, *, max_bytes: int = ...) -> bytes: ...


class InstallationTokenResponse(Protocol):
    status_code: int
    content: bytes

    def json(self) -> Any: ...


class InstallationTokenTransport(Protocol):
    def post(self, url: str, **kwargs: Any) -> InstallationTokenResponse: ...


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _base64url(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def _segment(claims: Mapping[str, object]) -> bytes:
    return _base64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))


class _AppSigningKey:
    """The App private key, whose one destination is an App JWT signature."""

    __slots__ = ("_key",)

    def __init__(self, material: bytes) -> None:
        try:
            key = serialization.load_pem_private_key(material, password=None)
        except (TypeError, ValueError, UnsupportedAlgorithm) as error:
            raise GitHubAppAuthenticationError(
                "the GitHub App private key is not a readable PEM private key"
            ) from error
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
            raise GitHubAppAuthenticationError(
                "the GitHub App private key must be an RSA key of at least 2048 bits"
            )
        self._key = key

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    def __repr__(self) -> str:
        return "<GitHubAppSigningKey redacted>"

    def __str__(self) -> str:
        return self.__repr__()


class InstallationToken:
    """A minted token that cannot be printed, formatted, or serialized."""

    __slots__ = ("_expires_at", "_value")

    def __init__(self, *, value: str, expires_at: datetime) -> None:
        if not value or len(value) > _MAXIMUM_TOKEN_BYTES:
            raise GitHubAppAuthenticationError(
                "GitHub returned an empty or oversized installation token"
            )
        if expires_at.tzinfo is None:
            raise GitHubAppAuthenticationError(
                "an installation token expiry must be an absolute instant"
            )
        self._value = value
        self._expires_at = expires_at

    @property
    def expires_at(self) -> datetime:
        return self._expires_at

    def present(self) -> str:
        """Hand the value to the one caller that must send it to GitHub."""

        return self._value

    def __repr__(self) -> str:
        return f"<InstallationToken redacted expires_at={self._expires_at.isoformat()}>"

    def __str__(self) -> str:
        return self.__repr__()


class StaticGitHubTokenProvider:
    """A fixed token for tests and local harnesses. Never a deployed path.

    A deployed service authenticates through `GitHubAppInstallationTokenProvider`
    because a fixed token dies within the hour with no way back. This exists so a
    test can exercise a client without an RSA private key.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def token(self, *, installation_id: int) -> str:
        del installation_id
        return self._value

    def __repr__(self) -> str:
        return "<StaticGitHubTokenProvider redacted>"

    def __str__(self) -> str:
        return self.__repr__()


class GitHubAppInstallationTokenProvider:
    """Mint installation tokens from the App key and refresh before they expire."""

    def __init__(
        self,
        *,
        transport: InstallationTokenTransport,
        secrets: SecretResolver,
        app_id_secret_ref: str,
        private_key_secret_ref: str,
        api_base_url: str = "https://api.github.com",
        refresh_margin_seconds: int = _REFRESH_MARGIN_SECONDS,
        now: Callable[[], datetime] = _utcnow,
    ) -> None:
        if not api_base_url.startswith("https://") or api_base_url.endswith("/"):
            raise ValueError("GitHub API base URL must be an HTTPS origin")
        if not app_id_secret_ref or not private_key_secret_ref:
            raise ValueError("GitHub App authentication requires both Secret Manager references")
        if not 0 < refresh_margin_seconds < _MAXIMUM_TOKEN_LIFETIME_SECONDS:
            raise ValueError("the installation token refresh margin is out of range")
        self._transport = transport
        self._secrets = secrets
        self._app_id_ref = app_id_secret_ref
        self._private_key_ref = private_key_secret_ref
        self._base = api_base_url
        self._margin = timedelta(seconds=refresh_margin_seconds)
        self._now = now
        self._identity: str | None = None
        self._key: _AppSigningKey | None = None
        self._tokens: dict[int, InstallationToken] = {}
        self._locks: dict[int, threading.Lock] = {}
        self._guard = threading.Lock()

    def token(self, *, installation_id: int) -> str:
        if installation_id <= 0:
            raise GitHubAppAuthenticationError("a positive GitHub installation id is required")
        live = self._live(installation_id)
        if live is None:
            # Serialized per installation so a burst of concurrent callers costs
            # GitHub one exchange, and re-checked inside the lock so the callers
            # that waited use what the first one minted.
            with self._exchange_lock(installation_id):
                live = self._live(installation_id)
                if live is None:
                    live = self._exchange(installation_id)
                    with self._guard:
                        self._tokens[installation_id] = live
        return live.present()

    def __repr__(self) -> str:
        return f"<GitHubAppInstallationTokenProvider installations={len(self._tokens)}>"

    def __str__(self) -> str:
        return self.__repr__()

    def _exchange_lock(self, installation_id: int) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(installation_id, threading.Lock())

    def _live(self, installation_id: int) -> InstallationToken | None:
        with self._guard:
            minted = self._tokens.get(installation_id)
        if minted is None or minted.expires_at - self._margin <= self._now():
            return None
        return minted

    def _app_id(self) -> str:
        with self._guard:
            cached = self._identity
        if cached is not None:
            return cached
        try:
            material = self._secrets.access(self._app_id_ref, max_bytes=256)
        except Exception as error:
            raise GitHubAppAuthenticationError(
                "the GitHub App identifier could not be read from Secret Manager"
            ) from error
        value = material.decode("utf-8", errors="ignore").strip()
        if not _APP_ID.fullmatch(value):
            raise GitHubAppAuthenticationError(
                "the configured GitHub App identifier is not a usable App or client ID"
            )
        with self._guard:
            self._identity = value
        return value

    def _signing_key(self) -> _AppSigningKey:
        with self._guard:
            cached = self._key
        if cached is not None:
            return cached
        try:
            material = self._secrets.access(self._private_key_ref, max_bytes=16_384)
        except Exception as error:
            raise GitHubAppAuthenticationError(
                "the GitHub App private key could not be read from Secret Manager"
            ) from error
        key = _AppSigningKey(material)
        with self._guard:
            self._key = key
        return key

    def _app_jwt(self) -> str:
        issued = int(self._now().timestamp()) - _JWT_BACKDATE_SECONDS
        payload = {
            "iat": issued,
            "exp": issued + _JWT_LIFETIME_SECONDS,
            "iss": self._app_id(),
        }
        signing_input = _segment({"alg": "RS256", "typ": "JWT"}) + b"." + _segment(payload)
        signature = _base64url(self._signing_key().sign(signing_input))
        return (signing_input + b"." + signature).decode("ascii")

    def _exchange(self, installation_id: int) -> InstallationToken:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._app_jwt()}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        url = f"{self._base}/app/installations/{installation_id}/access_tokens"
        try:
            response = self._transport.post(url, headers=headers, timeout=30, allow_redirects=False)
            status_code = int(response.status_code)
            content = response.content
        except Exception as error:
            raise GitHubAppAuthenticationError(
                "the GitHub installation token exchange could not be completed"
            ) from error
        if status_code != 201:
            raise GitHubAppAuthenticationError(
                f"GitHub refused the installation token exchange with HTTP {status_code}"
            )
        if len(content) > _MAXIMUM_EXCHANGE_BYTES:
            raise GitHubAppAuthenticationError(
                "the GitHub installation token response exceeds its bounded size"
            )
        try:
            body = response.json()
        except Exception as error:
            raise GitHubAppAuthenticationError(
                "the GitHub installation token response is not JSON"
            ) from error
        if not isinstance(body, dict):
            raise GitHubAppAuthenticationError(
                "the GitHub installation token response is not an object"
            )
        value = body.get("token")
        if not isinstance(value, str):
            raise GitHubAppAuthenticationError(
                "the GitHub installation token response carries no token"
            )
        return InstallationToken(value=value, expires_at=self._expiry(body.get("expires_at")))

    def _expiry(self, declared: object) -> datetime:
        if not isinstance(declared, str) or not declared:
            raise GitHubAppAuthenticationError(
                "the GitHub installation token response declares no expiry"
            )
        try:
            expires_at = datetime.fromisoformat(declared.replace("Z", "+00:00"))
        except ValueError as error:
            raise GitHubAppAuthenticationError(
                "the GitHub installation token expiry is not an ISO 8601 instant"
            ) from error
        if expires_at.tzinfo is None:
            raise GitHubAppAuthenticationError(
                "the GitHub installation token expiry is not an absolute instant"
            )
        now = self._now()
        if expires_at <= now:
            raise GitHubAppAuthenticationError(
                "GitHub returned an installation token that has already expired"
            )
        return min(expires_at, now + timedelta(seconds=_MAXIMUM_TOKEN_LIFETIME_SECONDS))
