"""Grant one verified Google principal authority over the local dev scope."""

from __future__ import annotations

import os
import re

from solvan.domain import Scope
from solvan.platform.database import connect_database


def main() -> None:
    if os.environ.get("SOLVAN_LOCAL_CONNECTED_GCP") != "true":
        raise SystemExit("local connected GCP mode is required")
    principal = os.environ.get("SOLVAN_LOCAL_ADMIN_PRINCIPAL", "")
    if re.fullmatch(r"user:[^@\s]+@[^@\s]+", principal) is None:
        raise SystemExit("SOLVAN_LOCAL_ADMIN_PRINCIPAL must be an exact Google user principal")
    scope = Scope(
        os.environ["SOLVAN_ORGANIZATION_ID"],
        os.environ["SOLVAN_SCOPE_PROJECT_ID"],
        os.environ["SOLVAN_ENVIRONMENT_ID"],
    )
    with connect_database() as connection, connection.transaction():
        connection.execute(
            """INSERT INTO solvan.actor_role_bindings
              (organization_id,project_id,environment_id,principal,role,granted_by)
              VALUES (%(organization_id)s,%(project_id)s,%(environment_id)s,
                      %(principal)s,'ADMIN',%(principal)s)
              ON CONFLICT (organization_id,project_id,environment_id,principal,role)
              DO UPDATE SET granted_by=EXCLUDED.granted_by,granted_at=now(),expires_at=NULL""",
            {**scope.canonical_dict(), "principal": principal},
        )
    print(f"Local-connected administrator: {principal}")


if __name__ == "__main__":
    main()
