"""The console reads built-in pack content only through the governed projection."""

import pytest
from fastapi import HTTPException

from apps.api.fleet_operability import first_party_pack_files


def test_pack_files_serve_skill_md_first_with_frontmatter() -> None:
    files = first_party_pack_files("reliability.triage-latency")
    assert files[0]["name"] == "SKILL.md"
    assert files[0]["content"].startswith("---\nname: triage-latency")
    names = {item["name"] for item in files}
    assert {"PROVENANCE.yaml", "REFERENCES.md"} <= names


def test_traversal_shaped_keys_are_refused() -> None:
    for key in ("../secrets", "a.b/../../x", "reliability.__proto__", "RELIABILITY.TRIAGE"):
        with pytest.raises(HTTPException) as caught:
            first_party_pack_files(key)
        assert caught.value.status_code == 404


def test_unknown_pack_is_refused() -> None:
    with pytest.raises(HTTPException) as caught:
        first_party_pack_files("reliability.does-not-exist")
    assert caught.value.status_code == 404
