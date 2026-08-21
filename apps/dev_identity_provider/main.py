"""A local OpenID provider for development, and only for development.

Signing in locally must exercise the real sign-in path — signature, issuer,
audience, nonce, and PKCE — or it proves nothing about the code that runs in a
deployment. The alternative usually reached for is a switch that skips
verification when a variable is set, which is precisely what specification 05
forbids: no configuration value may downgrade an identity control.

So this is not a bypass. It is a genuine OpenID provider that mints RS256
identity tokens and publishes a JWKS, and Solvan verifies them exactly as it
verifies Google's. What differs is which issuer a deployment trusts, which is
configuration of *whom* to believe rather than *whether* to check.

It holds its state in memory, signs with a key generated at startup, and admits
whichever development identities it is configured with. It must never be
reachable from a deployment: `tools/check_architecture.py` refuses to let the
production composition import it, and the API refuses a non-Google issuer
wherever Google Cloud holds authority.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlencode

from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter, FastAPI, Form, Header, HTTPException, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field

_TOKEN_LIFETIME_SECONDS = 3600
_CODE_LIFETIME_SECONDS = 300


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


@dataclass(frozen=True, slots=True)
class DevelopmentIdentity:
    """One person a developer may sign in as."""

    subject: str
    email: str
    name: str
    hosted_domain: str


@dataclass
class _PendingCode:
    identity: DevelopmentIdentity
    client_id: str
    redirect_uri: str
    nonce: str
    code_challenge: str
    authenticated_at: int
    issued_at: float = field(default_factory=time.time)


class _StepUpMessage(BaseModel):
    """One production-shaped message accepted by the local mailbox fixture."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    to_address: str = Field(min_length=3, max_length=320)
    code: str = Field(pattern=r"^[0-9]{8}$")
    step_up_id: str = Field(min_length=1, max_length=128)
    operation: str = Field(min_length=1, max_length=128)


def _identities() -> tuple[DevelopmentIdentity, ...]:
    """Who may be signed in as, from configuration rather than invention."""

    declared = os.environ.get("SOLVAN_DEV_IDENTITIES", "")
    parsed: list[DevelopmentIdentity] = []
    for entry in declared.split(","):
        email = entry.strip().lower()
        if not email or "@" not in email:
            continue
        local, domain = email.split("@", 1)
        parsed.append(
            DevelopmentIdentity(
                # Stable across restarts: a subject that changed each run would
                # mint a new actor every time and lose its role bindings, which
                # is the very failure the subject key exists to prevent.
                subject=f"dev-{hashlib.sha256(email.encode()).hexdigest()[:20]}",
                email=email,
                name=local.replace(".", " ").title(),
                hosted_domain=domain,
            )
        )
    return tuple(parsed)


def create_app() -> FastAPI:
    app = FastAPI(title="Solvan development identity provider", version="0.1.0")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_id = secrets.token_hex(8)
    # The one variable the API also reads, so the issuer this provider publishes
    # and the issuer the API trusts cannot disagree. It carried a second name
    # and a hardcoded port default, and the default was another worktree
    # service's port: the API discovered this provider correctly while the
    # document it served advertised a dead address, and the browser was sent
    # there. Every port here is derived from the worktree's path, so there is no
    # default worth guessing.
    issuer = os.environ.get("SOLVAN_TEST_ISSUER", "").strip()
    # Mailbox-only mode serves a local host whose sign-in is real Google: the
    # step-up code needs a delivery address the harness can read, and nothing
    # here may mint an identity on that path. No issuer is published and the
    # sign-in endpoints below are not mounted at all.
    mailbox_only = os.environ.get("SOLVAN_STEP_UP_MAILBOX_ONLY", "") == "1"
    if not issuer and not mailbox_only:
        raise RuntimeError(
            "SOLVAN_TEST_ISSUER is required: it is the address this provider publishes "
            "as its issuer and the one the API verifies assertions against"
        )
    if issuer and mailbox_only:
        raise RuntimeError("a mailbox-only instance publishes no issuer")
    codes: dict[str, _PendingCode] = {}
    step_up_messages: dict[str, _StepUpMessage] = {}
    router = APIRouter()

    def require_step_up_sink(authorization: str) -> None:
        expected = os.environ.get("SOLVAN_TEST_STEP_UP_SINK_TOKEN", "")
        supplied = authorization.removeprefix("Bearer ")
        if len(expected.encode("utf-8")) < 32 or not secrets.compare_digest(supplied, expected):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "test mailbox bearer was refused")

    @router.get("/.well-known/openid-configuration")
    def discovery() -> dict[str, Any]:
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": f"{issuer}/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"],
        }

    @router.get("/.well-known/jwks.json")
    def jwks() -> dict[str, Any]:
        numbers = private_key.public_key().public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": key_id,
                    "n": _b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                    "e": _b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
                }
            ]
        }

    @router.get("/authorize", response_class=HTMLResponse)
    def authorize(
        client_id: str,
        redirect_uri: str,
        state: str,
        nonce: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
        scope: str = "",
        response_type: str = "code",
        access_type: str = "online",
        hd: str = "",
    ) -> HTMLResponse:
        """An account picker, so signing in locally is an actual interaction."""

        if code_challenge_method != "S256":
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "only S256 is supported")
        available = _identities()
        if not available:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "no development identities are configured; set SOLVAN_DEV_IDENTITIES",
            )
        choices = "".join(
            f'<button name="subject" value="{person.subject}" type="submit">'
            f"<strong>{person.name}</strong><span>{person.email}</span></button>"
            for person in available
        )
        return HTMLResponse(_page(choices, client_id, redirect_uri, state, nonce, code_challenge))

    @router.post("/authorize")
    def choose(
        subject: str = Form(...),
        client_id: str = Form(...),
        redirect_uri: str = Form(...),
        state: str = Form(...),
        nonce: str = Form(...),
        code_challenge: str = Form(...),
    ) -> Response:
        person = next((item for item in _identities() if item.subject == subject), None)
        if person is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "unknown development identity")
        code = secrets.token_urlsafe(24)
        codes[code] = _PendingCode(
            identity=person,
            client_id=client_id,
            redirect_uri=redirect_uri,
            nonce=nonce,
            code_challenge=code_challenge,
            # Always now: a step-up asks for a fresh authentication, and this is
            # the moment the person actually chose an identity.
            authenticated_at=int(time.time()),
        )
        return RedirectResponse(
            f"{redirect_uri}?{urlencode({'code': code, 'state': state})}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @router.post("/token")
    def token(
        code: str = Form(...),
        client_id: str = Form(...),
        redirect_uri: str = Form(...),
        grant_type: str = Form(...),
        code_verifier: str = Form(...),
        client_secret: str = Form(default=""),
    ) -> dict[str, Any]:
        pending = codes.pop(code, None)
        if pending is None or grant_type != "authorization_code":
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "unknown authorization code")
        if time.time() - pending.issued_at > _CODE_LIFETIME_SECONDS:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "the authorization code expired")
        if pending.client_id != client_id or pending.redirect_uri != redirect_uri:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "the code was issued for another client"
            )
        expected = _b64(hashlib.sha256(code_verifier.encode("ascii")).digest())
        if not secrets.compare_digest(expected, pending.code_challenge):
            # PKCE is verified rather than accepted, so the local flow fails the
            # same way a real one would when a code is intercepted.
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "the PKCE verifier does not match")
        issued_at = int(time.time())
        claims = {
            "iss": issuer,
            "aud": client_id,
            "sub": pending.identity.subject,
            "email": pending.identity.email,
            "email_verified": True,
            "hd": pending.identity.hosted_domain,
            "name": pending.identity.name,
            "nonce": pending.nonce,
            "iat": issued_at,
            "exp": issued_at + _TOKEN_LIFETIME_SECONDS,
            "auth_time": pending.authenticated_at,
        }
        return {
            "token_type": "Bearer",
            "expires_in": _TOKEN_LIFETIME_SECONDS,
            "id_token": _sign(claims, private_key, key_id),
        }

    @router.post("/operator-step-up-messages")
    def receive_step_up_message(
        message: _StepUpMessage,
        authorization: str = Header(default=""),
        idempotency_key: str = Header(default=""),
    ) -> dict[str, str]:
        """Accept test mail only from the paired loopback API process."""

        require_step_up_sink(authorization)
        if not idempotency_key or idempotency_key != message.step_up_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "idempotency binding is invalid")
        existing = step_up_messages.get(idempotency_key)
        if existing is not None and existing != message:
            raise HTTPException(status.HTTP_409_CONFLICT, "idempotency key changed material")
        step_up_messages[idempotency_key] = message
        return {"message_id": idempotency_key}

    @router.get("/operator-step-up-messages/latest")
    def latest_step_up_message(
        address: str,
        authorization: str = Header(default=""),
    ) -> dict[str, str]:
        """Let the local browser harness read what a real mailbox would hold."""

        require_step_up_sink(authorization)
        matching = [
            message
            for message in step_up_messages.values()
            if message.to_address.casefold() == address.casefold()
        ]
        if not matching:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no test message is available")
        latest = matching[-1]
        return {
            "code": latest.code,
            "step_up_id": latest.step_up_id,
            "operation": latest.operation,
        }

    if issuer:
        app.include_router(router)
    else:
        # Mailbox-only mode: the sign-in routes are never mounted, so this
        # process cannot mint an identity on a path whose sign-in is real
        # Google. The decorators above still declare every route, which keeps
        # the static challenge-coverage gate looking at what exists.
        mailbox = APIRouter()
        mailbox.routes.extend(
            route
            for route in router.routes
            if getattr(route, "path", "").startswith("/operator-step-up-messages")
        )
        app.include_router(mailbox)
    return app


_STYLE = "".join(
    [
        "body{font:15px/1.5 system-ui;background:#f4f5f7;display:grid;",
        "place-items:center;min-height:100vh;margin:0}",
        "form{background:#fff;padding:28px;border-radius:12px;",
        "width:min(420px,92vw);box-shadow:0 1px 3px rgba(0,0,0,.12)}",
        "h1{font-size:19px;margin:0 0 4px}p{color:#555;margin:0 0 18px}",
        "button{display:grid;width:100%;text-align:left;padding:12px 14px;",
        "margin-bottom:8px;border:1px solid #d6d9de;border-radius:8px;",
        "background:#fff;cursor:pointer;font:inherit}",
        "button:hover{border-color:#3b6cf5}span{color:#666;font-size:13px}",
        "em{display:block;margin-top:14px;color:#8a6d1f;font-size:12.5px;",
        "font-style:normal}",
    ]
)


def _page(
    choices: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    nonce: str,
    code_challenge: str,
) -> str:
    """The account picker, so signing in locally is a real interaction."""

    heading = "Development sign-in"
    lead = "Choose the identity to sign in as."
    hidden = "".join(
        f'<input type="hidden" name="{name}" value="{value}">'
        for name, value in (
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", code_challenge),
        )
    )
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        f"<title>Development sign-in</title><style>{_STYLE}</style></head><body>"
        f'<form method="post" action="/authorize"><h1>{heading}</h1><p>{lead}</p>'
        f"{choices}{hidden}"
        "<em>Local development provider. These identities exist only on this "
        "machine and carry no authority anywhere else.</em></form></body></html>"
    )


def _sign(claims: dict[str, Any], private_key: rsa.RSAPrivateKey, key_id: str) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    header = _b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": key_id}).encode())
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64(signature)}"


app = create_app()
