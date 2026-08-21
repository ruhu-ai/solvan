"""Who holds access to this environment, and who may be offered it (spec 05 §4.2).

Onboarding is invitation-based: a verified Google account at an admitted domain
is *eligible*, and an explicit grant is what admits it. Until now the grant
existed only as a table and a redemption path — the sole writer was the local
bootstrap script, so admitting a colleague to a deployment meant an operator
writing SQL against Cloud SQL by hand.

This is the surface that authors it. Nothing here decides identity; it decides
who an already-verified identity is allowed to become, which is why every
mutation spends a one-use challenge bound to the exact grant being made.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request, status
from psycopg import Connection
from psycopg.rows import dict_row
from pydantic import BaseModel, ConfigDict, Field

from apps.api.session_authorization import SESSION_COOKIE, spend_challenge
from solvan.application.action_challenge import material_digest
from solvan.application.oauth_login import credential_hash
from solvan.domain import Scope
from solvan.domain.identifiers import new_identifier
from solvan.persistence.operator_identity_store import OperatorIdentityStore
from solvan.persistence.operator_session_store import OperatorSessionStore

#: How long an offer stands. An invitation that never expires is a standing
#: grant to whoever eventually controls that address.
INVITATION_LIFETIME = timedelta(days=14)

ROLES = ("OPERATOR", "APPROVER", "ADMIN")


def invitation_material(*, email: str, role: str) -> str:
    """The exact grant a challenge authorizes, as both sides compute it.

    The console builds this string to request the step-up and the API rebuilds
    it to spend the challenge, so re-authenticating for "invite someone as
    OPERATOR" cannot be redirected into "invite someone as ADMIN" by a page
    changed while the operator was away at the provider.
    """

    return f"invitation:v1:{email.strip().lower()}:{role}"


class InvitationCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    schema_version: Literal[1]
    # Shape only. Whether the address may be admitted is decided against the
    # admitted domains, not by this pattern.
    email: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    role: Literal["OPERATOR", "APPROVER", "ADMIN"]


def _now() -> datetime:
    return datetime.now(UTC)


def operator_administration_router(
    *,
    connect: Callable[[], Connection[Any]],
    scope_provider: Callable[[], Scope],
    admitted_domains_provider: Callable[[Scope], frozenset[str]],
) -> APIRouter:
    router = APIRouter()

    def _administrator(connection: Connection[Any], request: Request, scope: Scope) -> str:
        """The signed-in actor, refused unless they hold ADMIN right now.

        Read per request rather than from the session, so removing somebody's
        administration takes effect immediately rather than at their next
        sign-in.
        """

        credential = request.cookies.get(SESSION_COOKIE)
        if not credential:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no session")
        now = _now()
        live = OperatorSessionStore(connection).touch(
            credential_hash=credential_hash(credential), now=now
        )
        if live is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "no session")
        roles = OperatorIdentityStore(connection).roles(
            scope=scope, actor_id=live.actor_id, now=now
        )
        if "ADMIN" not in roles:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Administering access to this environment requires ADMIN.",
            )
        return live.actor_id

    @router.get("/api/admin/operators")
    def roster(request: Request) -> dict[str, Any]:
        """Everyone who holds access here, and every offer still standing."""

        scope = scope_provider()
        now = _now()
        with connect() as connection, connection.transaction():
            _administrator(connection, request, scope)
            with connection.cursor(row_factory=dict_row) as cursor:
                cursor.execute(
                    """SELECT m.actor_id,
                              a.status,
                              array_agg(m.role ORDER BY m.role) AS roles,
                              max(i.last_seen_at) AS last_seen_at,
                              min(i.email) AS email
                         FROM solvan_identity.actor_memberships m
                         JOIN solvan_identity.actors a ON a.actor_id = m.actor_id
                    LEFT JOIN solvan_identity.external_identities i ON i.actor_id = m.actor_id
                        WHERE m.organization_id=%(organization_id)s
                          AND m.project_id=%(project_id)s
                          AND m.environment_id=%(environment_id)s
                          AND (m.expires_at IS NULL OR m.expires_at > %(now)s)
                     GROUP BY m.actor_id, a.status
                     ORDER BY min(i.email) NULLS LAST""",
                    {**scope.canonical_dict(), "now": now},
                )
                members = cursor.fetchall()
                cursor.execute(
                    """SELECT id, email, role, created_at, expires_at
                         FROM solvan_identity.actor_invitations
                        WHERE organization_id=%(organization_id)s
                          AND project_id=%(project_id)s
                          AND environment_id=%(environment_id)s
                          AND consumed_at IS NULL
                          AND expires_at > %(now)s
                     ORDER BY created_at DESC""",
                    {**scope.canonical_dict(), "now": now},
                )
                invitations = cursor.fetchall()
        return {
            "schema_version": 1,
            "admitted_domains": sorted(admitted_domains_provider(scope)),
            "members": [
                {
                    "actor_id": str(row["actor_id"]),
                    "email": None if row["email"] is None else str(row["email"]),
                    "status": str(row["status"]),
                    "roles": [str(role) for role in row["roles"]],
                    "last_seen_at": (
                        None if row["last_seen_at"] is None else row["last_seen_at"].isoformat()
                    ),
                }
                for row in members
            ],
            "invitations": [
                {
                    "id": str(row["id"]),
                    "email": str(row["email"]),
                    "role": str(row["role"]),
                    "created_at": row["created_at"].isoformat(),
                    "expires_at": row["expires_at"].isoformat(),
                }
                for row in invitations
            ],
            "notice": (
                "An invitation is an offer, not an account. It grants its role only when "
                "the person signs in with a verified Google account at that address."
            ),
        }

    @router.post("/api/admin/operators/invitations", status_code=status.HTTP_201_CREATED)
    def invite(request: Request, command: InvitationCommand) -> dict[str, Any]:
        """Offer one role to one address, spending a challenge bound to both."""

        scope = scope_provider()
        now = _now()
        email = command.email.strip().lower()
        domain = email.split("@", 1)[1]
        admitted = admitted_domains_provider(scope)
        if domain not in admitted:
            # Refused here rather than at redemption, where the person meets a
            # correct refusal for a mistake the administrator made.
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"{domain} is not an admitted domain for this environment. "
                f"Admitted: {', '.join(sorted(admitted)) or 'none'}.",
            )
        with connect() as connection, connection.transaction():
            # Authorization, the one-use grant, and the record it authorizes all
            # commit together: spending the challenge without writing the
            # invitation burns the re-authentication and grants nothing, and
            # writing it without spending leaves the challenge replayable.
            consumed = spend_challenge(
                connection,
                request,
                scope=scope,
                operation="role.grant",
                material_digest=material_digest(
                    invitation_material(email=email, role=command.role)
                ),
                now=now,
            )
            invitation_id = new_identifier("inv")
            with connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO solvan_identity.actor_invitations
                         (id,organization_id,project_id,environment_id,email,admitted_domain,
                          role,invited_by_actor_id,created_at,expires_at)
                       VALUES (%(id)s,%(organization_id)s,%(project_id)s,%(environment_id)s,
                          %(email)s,%(domain)s,%(role)s,%(inviter)s,%(now)s,%(expires_at)s)
                       ON CONFLICT DO NOTHING""",
                    {
                        **scope.canonical_dict(),
                        "id": invitation_id,
                        "email": email,
                        "domain": domain,
                        "role": command.role,
                        "inviter": consumed.actor_id,
                        "now": now,
                        "expires_at": now + INVITATION_LIFETIME,
                    },
                )
                if cursor.rowcount != 1:
                    # The partial unique index allows one open offer per address
                    # and role. Saying so beats a constraint name.
                    raise HTTPException(
                        status.HTTP_409_CONFLICT,
                        f"{email} already has an open invitation as {command.role}.",
                    )
                _record(
                    cursor,
                    scope=scope,
                    stream_id=invitation_id,
                    event_type="OperatorInvitationCreated",
                    actor_id=consumed.actor_id,
                    material=invitation_material(email=email, role=command.role),
                )
        return {
            "schema_version": 1,
            "id": invitation_id,
            "email": email,
            "role": command.role,
            "expires_at": (now + INVITATION_LIFETIME).isoformat(),
        }

    @router.delete("/api/admin/operators/invitations/{invitation_id}")
    def revoke(request: Request, invitation_id: str) -> dict[str, str]:
        """Withdraw an offer that has not been taken up.

        The row is removed rather than marked, and the audit event is what
        remains. An invitation is an offer rather than a history of something
        that happened, and the index that allows one open offer per address and
        role does not read an expiry — so marking it would leave the address
        permanently un-invitable after a typo.
        """

        scope = scope_provider()
        now = _now()
        with connect() as connection, connection.transaction():
            with connection.cursor(row_factory=dict_row) as lookup:
                lookup.execute(
                    """SELECT email, role FROM solvan_identity.actor_invitations
                        WHERE id=%(id)s AND organization_id=%(organization_id)s
                          AND project_id=%(project_id)s AND environment_id=%(environment_id)s
                          AND consumed_at IS NULL
                          FOR UPDATE""",
                    {**scope.canonical_dict(), "id": invitation_id},
                )
                open_invitation = lookup.fetchone()
            if open_invitation is None:
                raise HTTPException(
                    status.HTTP_404_NOT_FOUND, "no open invitation with that identifier"
                )
            material = invitation_material(
                email=str(open_invitation["email"]), role=str(open_invitation["role"])
            )
            consumed = spend_challenge(
                connection,
                request,
                scope=scope,
                operation="role.grant",
                material_digest=material_digest(material),
                now=now,
            )
            with connection.cursor() as cursor:
                cursor.execute(
                    """DELETE FROM solvan_identity.actor_invitations
                        WHERE id=%s AND consumed_at IS NULL""",
                    (invitation_id,),
                )
                if cursor.rowcount != 1:
                    raise HTTPException(
                        status.HTTP_409_CONFLICT, "the invitation was redeemed concurrently"
                    )
                _record(
                    cursor,
                    scope=scope,
                    stream_id=invitation_id,
                    event_type="OperatorInvitationRevoked",
                    actor_id=consumed.actor_id,
                    material=material,
                )
        return {"status": "revoked", "id": invitation_id}

    return router


def _record(
    cursor: Any, *, scope: Scope, stream_id: str, event_type: str, actor_id: str, material: str
) -> None:
    """One durable record of a change to who may reach this environment."""

    cursor.execute(
        """INSERT INTO solvan.audit_events
             (organization_id,project_id,environment_id,id,stream_type,stream_id,
              event_type,actor_principal,payload_hash)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(audit_id)s,
              'OPERATOR_ACCESS',%(stream_id)s,%(event_type)s,%(principal)s,%(payload_hash)s)""",
        {
            **scope.canonical_dict(),
            "audit_id": new_identifier("aud"),
            "stream_id": stream_id,
            "event_type": event_type,
            "principal": f"actor:{actor_id}",
            "payload_hash": material_digest(material),
        },
    )


__all__ = [
    "INVITATION_LIFETIME",
    "ROLES",
    "InvitationCommand",
    "invitation_material",
    "material_digest",
    "operator_administration_router",
]
