"""Durable actors, memberships, and invitations (specification 05 §4.2).

Resolution is deliberately narrow: an assertion identifies an actor, and that is
all this store will say. What the actor may do is a separate read against a
separate table, taken per operation, so a role change or revocation takes effect
at once rather than at next sign-in.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from solvan.application.operator_identity import (
    OperatorIdentityError,
    ResolvedAssertion,
)
from solvan.domain import Scope
from solvan.domain.identifiers import new_identifier


class OperatorIdentityStore:
    """All reads and writes are scope-bound where the record carries a scope."""

    def __init__(self, connection: Connection[Any]) -> None:
        self._connection = connection

    def resolve_actor(self, assertion: ResolvedAssertion, *, now: datetime) -> str:
        """Return the actor this external identity belongs to, creating it once.

        First sight mints an actor. Every later sight refreshes the current
        attributes and returns the same actor, so a rename is an attribute
        change rather than a new person with no roles.
        """

        provider, issuer, subject = assertion.external_key
        with self._connection.cursor(row_factory=dict_row) as cursor:
            # Serialize concurrent first sign-ins of the same identity so two
            # requests cannot mint two actors for one person.
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"solvan-actor:{provider}:{issuer}:{subject}",),
            )
            cursor.execute(
                """SELECT actor_id FROM solvan_identity.external_identities
                    WHERE provider=%s AND canonical_issuer=%s AND subject=%s""",
                (provider, issuer, subject),
            )
            existing = cursor.fetchone()
            if existing is not None:
                actor_id = str(existing["actor_id"])
                # A suspended actor is refused at the door. The column existed
                # and nothing consulted it, so suspending someone did nothing.
                cursor.execute(
                    "SELECT status FROM solvan_identity.actors WHERE actor_id=%s",
                    (actor_id,),
                )
                status = cursor.fetchone()
                if status is None or str(status["status"]) != "ACTIVE":
                    raise OperatorIdentityError("this identity is suspended")
                cursor.execute(
                    """UPDATE solvan_identity.external_identities
                          SET email=%s, hosted_domain=%s, last_seen_at=%s
                        WHERE provider=%s AND canonical_issuer=%s AND subject=%s""",
                    (
                        assertion.email,
                        assertion.hosted_domain,
                        now,
                        provider,
                        issuer,
                        subject,
                    ),
                )
                return actor_id
            actor_id = new_identifier("act")
            cursor.execute(
                "INSERT INTO solvan_identity.actors(actor_id, created_at) VALUES (%s, %s)",
                (actor_id, now),
            )
            cursor.execute(
                """INSERT INTO solvan_identity.external_identities
                     (provider, canonical_issuer, subject, actor_id, email,
                      hosted_domain, first_seen_at, last_seen_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    provider,
                    issuer,
                    subject,
                    actor_id,
                    assertion.email,
                    assertion.hosted_domain,
                    now,
                    now,
                ),
            )
            return actor_id

    def roles(self, *, scope: Scope, actor_id: str, now: datetime) -> frozenset[str]:
        """Live roles in one exact scope.

        Read per operation rather than cached in a session, so a revoked or
        expired grant stops admitting immediately instead of at next sign-in.
        """

        with self._connection.cursor() as cursor:
            cursor.execute(
                """SELECT role FROM solvan_identity.actor_memberships
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND actor_id=%(actor_id)s
                      AND (expires_at IS NULL OR expires_at > %(now)s)""",
                {**scope.canonical_dict(), "actor_id": actor_id, "now": now},
            )
            return frozenset(str(row[0]) for row in cursor.fetchall())

    def _project_legacy_binding(
        self, *, scope: Scope, actor_id: str, email: str, role: str, granted_by: str, now: datetime
    ) -> None:
        """Mirror a membership into the email-keyed table the routes still read.

        A bridge, and deliberately a narrow one. Sign-in admits on
        `solvan_identity.actor_memberships`; roughly twenty routes still
        authorize against `solvan.actor_role_bindings`, keyed on
        `user:{email}`. Without this an invited person signs in successfully and
        is authorized for nothing, which is the worse of the two failures: it
        looks like the invitation worked.

        The projection is written here, inside the store, so that creating a
        membership and mirroring it cannot come apart —
        `tests/unit/test_membership_projection_confinement.py` fails if any
        other module writes a membership directly. Divergence is what would make
        this dangerous: a membership removed elsewhere while its binding stood
        would leave authority nobody can see.

        Removal condition: delete this method, and its callers, when the routes
        resolve roles from the session's actor rather than from an email. It is
        not a second source of truth — it is the first one, projected.
        """

        self._connection.execute(
            """INSERT INTO solvan.actor_role_bindings
                 (organization_id,project_id,environment_id,principal,role,granted_by,granted_at)
               VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                       %(principal)s,%(role)s,%(granted_by)s,%(now)s)
               ON CONFLICT DO NOTHING""",
            {
                **scope.canonical_dict(),
                "principal": f"user:{email.strip().lower()}",
                "role": role,
                "granted_by": f"actor:{granted_by}",
                "now": now,
            },
        )

    def claim_founding_administrator(
        self,
        *,
        scope: Scope,
        actor_id: str,
        email: str,
        founding_email: str,
        now: datetime,
    ) -> bool:
        """Grant ADMIN to the one configured founding account, once, and only ever once.

        Onboarding is invitation-based, and an invitation requires an
        administrator to author it. A new environment therefore has nobody who
        can admit anybody: the first administrator cannot be invited, because
        there is no one to invite them.

        This closes that and nothing else. It is refused unless the scope holds
        no administrator at all, so it is a way to start an environment rather
        than a way into one. Once anybody holds ADMIN — including this account —
        it can never grant again, so it cannot be used to regain access after a
        removal, and reconfiguring it later grants nothing.

        The email is compared against a verified assertion the caller has
        already checked against the admitted domains; it is never taken from a
        request. Returns whether the grant was made.
        """

        if not founding_email or email.strip().lower() != founding_email.strip().lower():
            return False
        with self._connection.cursor() as cursor:
            # Serialize concurrent first sign-ins so two accounts cannot each
            # observe an empty administrator set and both be granted.
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"solvan-founding-admin:{scope.canonical_dict()}",),
            )
            cursor.execute(
                """SELECT 1 FROM solvan_identity.actor_memberships
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND role='ADMIN'
                      AND (expires_at IS NULL OR expires_at > %(now)s)
                    LIMIT 1""",
                {**scope.canonical_dict(), "now": now},
            )
            if cursor.fetchone() is not None:
                return False
            cursor.execute(
                """INSERT INTO solvan_identity.actor_memberships
                     (organization_id, project_id, environment_id, actor_id, role,
                      granted_by_actor_id, granted_at)
                   VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                           %(actor_id)s,'ADMIN',%(actor_id)s,%(now)s)
                   ON CONFLICT DO NOTHING""",
                {**scope.canonical_dict(), "actor_id": actor_id, "now": now},
            )
            # Self-granted, and recorded as such. Naming anyone else would put a
            # grant in the audit that they did not make.
            if cursor.rowcount != 1:
                return False
        self._project_legacy_binding(
            scope=scope,
            actor_id=actor_id,
            email=email,
            role="ADMIN",
            granted_by=actor_id,
            now=now,
        )
        return True

    def redeem_invitation(
        self,
        *,
        scope: Scope,
        actor_id: str,
        email: str,
        hosted_domain: str,
        now: datetime,
    ) -> frozenset[str]:
        """Consume every open, unexpired invitation for this address.

        Every one, not the oldest. An invitation names a single role, so an
        administrator granting somebody both OPERATOR and ADMIN authors two —
        and redeeming one per sign-in gave them the first role, then the second
        only if they signed out and back in. Nobody would discover that except
        by being mystified, so a person invited to two roles now holds both the
        moment they arrive.

        Consumption and the grant are one statement pair inside the caller's
        transaction: an invitation consumed without its membership would spend
        the grant and confer nothing, and a membership without consumption would
        leave the invitation claimable again.

        Returns the roles granted, empty when nothing was open. An expired
        invitation is not redeemed and is not an error: it is simply no longer
        a grant.
        """

        granted: set[str] = set()
        with self._connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT id, role, admitted_domain, invited_by_actor_id
                     FROM solvan_identity.actor_invitations
                    WHERE organization_id=%(organization_id)s
                      AND project_id=%(project_id)s
                      AND environment_id=%(environment_id)s
                      AND email=%(email)s
                      AND consumed_at IS NULL
                      AND expires_at > %(now)s
                    ORDER BY created_at
                    FOR UPDATE""",
                {**scope.canonical_dict(), "email": email, "now": now},
            )
            invitations = cursor.fetchall()
            for invitation in invitations:
                if str(invitation["admitted_domain"]) != hosted_domain:
                    # The invitation was authored for a different organization
                    # domain than the one this assertion proves.
                    raise OperatorIdentityError(
                        "the invitation was issued for another admitted domain"
                    )
                role = str(invitation["role"])
                cursor.execute(
                    """UPDATE solvan_identity.actor_invitations
                          SET consumed_at=%s, consumed_by_actor_id=%s
                        WHERE id=%s AND consumed_at IS NULL""",
                    (now, actor_id, invitation["id"]),
                )
                if cursor.rowcount != 1:
                    raise OperatorIdentityError("the invitation was consumed concurrently")
                cursor.execute(
                    """INSERT INTO solvan_identity.actor_memberships
                         (organization_id, project_id, environment_id, actor_id, role,
                          granted_by_actor_id, granted_at)
                       VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                               %(actor_id)s,%(role)s,%(granted_by)s,%(now)s)
                       ON CONFLICT DO NOTHING""",
                    {
                        **scope.canonical_dict(),
                        "actor_id": actor_id,
                        "role": role,
                        # The inviter granted this, not the newcomer. Recording
                        # the invitee would have the audit say they granted
                        # themselves.
                        "granted_by": invitation["invited_by_actor_id"],
                        "now": now,
                    },
                )
                self._project_legacy_binding(
                    scope=scope,
                    actor_id=actor_id,
                    email=email,
                    role=role,
                    granted_by=str(invitation["invited_by_actor_id"]),
                    now=now,
                )
                granted.add(role)
        return frozenset(granted)
