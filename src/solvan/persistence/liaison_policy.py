"""The policy epoch: one number that says whose authority a cursor assumed.

A catch-up cursor is a promise to resume where a reader left off. That promise
is only safe while the authority it was minted under still holds — otherwise a
principal whose role was revoked mid-conversation keeps receiving deltas about
records they may no longer see, and nothing in the cursor says anything changed.

The epoch is derived rather than announced. Each turn digests the principal's
live authority; when the digest moves, the epoch advances, and every cursor
minted under the old one is superseded. Nothing has to remember to bump it,
which is the point: a control that depends on every future writer remembering
to call it is a control that eventually fails open.

Specification 14 §17.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from psycopg import Connection

from solvan.domain import Scope


def authority_digest(connection: Connection[Any], *, scope: Scope, principal: str) -> str:
    """A stable fingerprint of everything that decides what this reader sees.

    This global epoch covers scope-wide authorization inputs. Exact-thread
    membership is deliberately excluded: every thread operation already binds
    and revalidates its own ``membership_epoch``. Including all memberships in
    this digest would let joining an unrelated conversation revoke an accepted
    turn in another conversation. An expired role binding is absent by
    construction, so expiry still advances the epoch without a scheduled job.
    """

    roles = connection.execute(
        """SELECT role FROM solvan.actor_role_bindings
           WHERE organization_id = %(organization_id)s
             AND project_id = %(project_id)s
             AND environment_id = %(environment_id)s
             AND principal = %(principal)s
             AND (expires_at IS NULL OR expires_at > now())
           ORDER BY role""",
        {**scope.canonical_dict(), "principal": principal},
    ).fetchall()
    material = json.dumps(
        {"roles": [str(row[0]) for row in roles]},
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{hashlib.sha256(material.encode()).hexdigest()}"


def current_policy_epoch(connection: Connection[Any], *, scope: Scope, principal: str) -> int:
    """This principal's epoch now, advancing it if their authority moved.

    The upsert compares digests inside one statement, so two turns racing for
    the same principal cannot both decide they are the one to advance it.
    """

    digest = authority_digest(connection, scope=scope, principal=principal)
    row = connection.execute(
        """INSERT INTO solvan_liaison.liaison_policy_epochs (
              organization_id, project_id, environment_id, principal,
              epoch, authority_digest)
           VALUES (%(organization_id)s, %(project_id)s, %(environment_id)s,
              %(principal)s, 1, %(digest)s)
           ON CONFLICT (organization_id, project_id, environment_id, principal)
           DO UPDATE SET
             epoch = solvan_liaison.liaison_policy_epochs.epoch
                     + (solvan_liaison.liaison_policy_epochs.authority_digest
                        IS DISTINCT FROM EXCLUDED.authority_digest)::int,
             authority_digest = EXCLUDED.authority_digest,
             updated_at = now()
           RETURNING epoch""",
        {**scope.canonical_dict(), "principal": principal, "digest": digest},
    ).fetchone()
    return int(row[0]) if row else 1
