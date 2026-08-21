"""Audience-bound grants for direct conversational projection reads."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from solvan.domain import Scope, new_identifier
from solvan.persistence.liaison_policy import current_policy_epoch


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(payload.encode()).hexdigest()}"


@dataclass(frozen=True, slots=True)
class ProjectionReadGrant:
    id: str
    principal: str
    operation_id: str
    anchor_label: str
    entity_set_digest: str
    policy_epoch: int
    request_hash: str
    issued_at: datetime
    expires_at: datetime


def mint_projection_read_grant(
    connection: Any,
    *,
    scope: Scope,
    principal: str,
    purpose: str,
    classification_ceiling: str,
    method: str,
    operation_id: str,
    anchor_label: str,
    authorized_records: Iterable[tuple[str, str]],
    membership_epoch: int | None = None,
    ttl_seconds: int = 60,
) -> ProjectionReadGrant:
    """Derive a short-lived request grant from current server-side authority."""

    if not principal or not operation_id or not anchor_label:
        raise ValueError("projection read grant inputs are incomplete")
    records = sorted({(str(kind), str(identifier)) for kind, identifier in authorized_records})
    entity_set_digest = _digest(records)
    policy_epoch = current_policy_epoch(connection, scope=scope, principal=principal)
    issued_at = datetime.now(UTC)
    if ttl_seconds < 1 or ttl_seconds > 660:
        raise ValueError("projection read grant TTL is outside its closed bound")
    expires_at = issued_at + timedelta(seconds=ttl_seconds)
    material = {
        "scope": scope.canonical_dict(),
        "principal": principal,
        "purpose": purpose,
        "classification_ceiling": classification_ceiling,
        "method": method,
        "operation_id": operation_id,
        "anchor_label": anchor_label,
        "entity_set_digest": entity_set_digest,
        "membership_epoch": membership_epoch,
        "policy_epoch": policy_epoch,
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    return ProjectionReadGrant(
        id=new_identifier("grt"),
        principal=principal,
        operation_id=operation_id,
        anchor_label=anchor_label,
        entity_set_digest=entity_set_digest,
        policy_epoch=policy_epoch,
        request_hash=_digest(material),
        issued_at=issued_at,
        expires_at=expires_at,
    )


def record_projection_read(
    connection: Any,
    *,
    scope: Scope,
    grant: ProjectionReadGrant,
    purpose: str,
    classification_ceiling: str,
    method: str,
    membership_epoch: int | None = None,
) -> None:
    """Append the immutable receipt after the bounded read succeeds."""

    connection.execute(
        """INSERT INTO solvan_liaison.liaison_grant_receipts (
              organization_id,project_id,environment_id,id,grant_kind,principal,
              operation_id,anchor_label,entity_set_digest,purpose,classification_ceiling,
              membership_epoch,audience,allowed_projection_methods,grant_digest,
              request_hash,policy_epoch,issued_at,expires_at,consumed_at,audit_ref)
           VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,%(id)s,
              'PROJECTION_READ',%(principal)s,%(operation_id)s,%(anchor_label)s,
              %(entity_set_digest)s,%(purpose)s,%(classification_ceiling)s,
              %(membership_epoch)s,'PROJECTION_API',ARRAY[%(method)s],%(grant_digest)s,
              %(request_hash)s,%(policy_epoch)s,%(issued_at)s,%(expires_at)s,now(),%(audit_ref)s)""",
        {
            **scope.canonical_dict(),
            "id": grant.id,
            "principal": grant.principal,
            "operation_id": grant.operation_id,
            "anchor_label": grant.anchor_label,
            "entity_set_digest": grant.entity_set_digest,
            "purpose": purpose,
            "classification_ceiling": classification_ceiling,
            "membership_epoch": membership_epoch,
            "method": method,
            "grant_digest": _digest(
                {
                    "id": grant.id,
                    "request_hash": grant.request_hash,
                    "audience": "PROJECTION_API",
                }
            ),
            "request_hash": grant.request_hash,
            "policy_epoch": grant.policy_epoch,
            "issued_at": grant.issued_at,
            "expires_at": grant.expires_at,
            "audit_ref": f"audit:{grant.id}",
        },
    )


@contextmanager
def projection_read(
    connection: Any,
    *,
    scope: Scope,
    principal: str,
    purpose: str,
    classification_ceiling: str,
    method: str,
    operation_id: str,
    anchor_label: str,
    authorized_records: Iterable[tuple[str, str]],
    membership_epoch: int | None = None,
    ttl_seconds: int = 60,
) -> Iterator[ProjectionReadGrant]:
    """Fence one direct read and append its receipt only on successful exit."""

    grant = mint_projection_read_grant(
        connection,
        scope=scope,
        principal=principal,
        purpose=purpose,
        classification_ceiling=classification_ceiling,
        method=method,
        operation_id=operation_id,
        anchor_label=anchor_label,
        authorized_records=authorized_records,
        membership_epoch=membership_epoch,
        ttl_seconds=ttl_seconds,
    )
    yield grant
    record_projection_read(
        connection,
        scope=scope,
        grant=grant,
        purpose=purpose,
        classification_ceiling=classification_ceiling,
        method=method,
        membership_epoch=membership_epoch,
    )
