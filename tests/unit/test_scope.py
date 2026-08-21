import pytest

from solvan.domain import IdentifierError, Scope


def test_scope_digest_is_stable_and_order_independent() -> None:
    value = Scope(
        organization_id="org_00000000000000000000000000",
        project_id="prj_00000000000000000000000000",
        environment_id="env_00000000000000000000000000",
    )

    assert value.canonical_dict() == {
        "environment_id": "env_00000000000000000000000000",
        "organization_id": "org_00000000000000000000000000",
        "project_id": "prj_00000000000000000000000000",
    }
    assert (
        value.digest() == "sha256:31a686bb838b757a8d6179bbaf068f92226d386af98abcac57bc5a8573a4f205"
    )


def test_scope_rejects_cross_type_identifiers() -> None:
    with pytest.raises(IdentifierError, match="does not match org"):
        Scope(
            organization_id="prj_00000000000000000000000000",
            project_id="prj_00000000000000000000000000",
            environment_id="env_00000000000000000000000000",
        )
