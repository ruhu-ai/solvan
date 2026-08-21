"""One writer for memberships, so the projection beside them cannot come apart.

Sign-in admits on `solvan_identity.actor_memberships`; roughly twenty routes
still authorize against the email-keyed `solvan.actor_role_bindings`. Until
those routes resolve roles from the session's actor, `OperatorIdentityStore`
mirrors every membership it grants into the table they read.

That bridge is only safe while it is maintained in one place. A membership
written somewhere else would be invisible to the routes; a membership *removed*
somewhere else would leave a binding standing, which is authority nobody can
see. This confines both to the store.
"""

from __future__ import annotations

import re
from pathlib import Path

REPOSITORY = Path(__file__).parents[2]
STORE = REPOSITORY / "src" / "solvan" / "persistence" / "operator_identity_store.py"

#: Writes against the membership table, in any statement shape.
WRITE = re.compile(
    r"(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+solvan_identity\.actor_memberships",
    re.IGNORECASE,
)


def _sources() -> list[Path]:
    roots = [REPOSITORY / "src" / "solvan", REPOSITORY / "apps", REPOSITORY / "tools"]
    return [
        path
        for root in roots
        if root.is_dir()
        for path in root.rglob("*.py")
        if "__pycache__" not in path.parts
    ]


def test_only_the_identity_store_writes_a_membership() -> None:
    """Anywhere else and the projection the routes read silently stops matching."""

    offenders = sorted(
        str(path.relative_to(REPOSITORY))
        for path in _sources()
        if path != STORE and WRITE.search(path.read_text(encoding="utf-8"))
    )

    assert offenders == [], (
        "These modules write actor_memberships directly, so a membership they grant or "
        "remove is not mirrored into solvan.actor_role_bindings and the routes will "
        "disagree with sign-in: " + ", ".join(offenders)
    )


def test_the_store_still_projects_every_membership_it_grants() -> None:
    """The bridge is load-bearing, so its absence must fail here rather than in production.

    Both membership-creating paths — redeeming an invitation and the founding
    administrator claim — must project. A path that grants without projecting
    admits somebody who is then authorized for nothing.
    """

    source = STORE.read_text(encoding="utf-8")
    granting = [
        block
        for block in source.split("\n    def ")
        if "INSERT INTO solvan_identity.actor_memberships" in block
    ]

    assert granting, "no membership grant found; this gate is checking nothing"
    for block in granting:
        name = block.split("(", 1)[0]
        assert "_project_legacy_binding" in block, (
            f"{name} grants a membership without projecting it into the table the "
            "routes read, so the person it admits is authorized for nothing"
        )
