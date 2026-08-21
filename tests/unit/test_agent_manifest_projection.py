"""The Agents tab renders manifest facts only under a verified digest pin.

A principal registered from an edited or replaced manifest must withhold its
declared facts rather than present stale ones, and a broken manifest file
must degrade the cards, never the snapshot.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from apps.api.agent_manifest_projection import MANIFEST_PATH, agent_manifest_facts
from solvan.application.workspace_hashing import canonical_sha256

_ENTRY = """schema_version: 1
manifest_version: 2026-01-01.1
platform:
  framework: google-adk
  framework_version: 2.7.1
  model_resource: gemini-3.6-flash
agents:
  - agent_key: evidence-agent
    display_name: Evidence Agent
    owner_department: sre-platform
    discoverable_by: [sre, security]
    lifecycle: DRAFT
    approval_status: PENDING_DEPLOYMENT_EVIDENCE
    permission_ceiling: READ_PRODUCTION_TELEMETRY
"""


def _write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "agent-manifests.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def test_entry_pinned_principal_gets_verified_facts(tmp_path: Path) -> None:
    path = _write(tmp_path, _ENTRY)
    import yaml

    entry = yaml.safe_load(_ENTRY)["agents"][0]
    facts = agent_manifest_facts({"evidence-agent": canonical_sha256(entry)}, manifest_path=path)[
        "evidence-agent"
    ]
    assert facts is not None
    assert facts["owner_department"] == "sre-platform"
    assert facts["discoverable_departments"] == ["sre", "security"]
    assert facts["framework"] == "google-adk 2.7.1"
    assert facts["model"] == "gemini-3.6-flash"
    assert facts["lifecycle"] == "DRAFT"
    assert facts["manifest_version"] == "2026-01-01.1"


def test_file_pinned_principal_gets_verified_facts(tmp_path: Path) -> None:
    path = _write(tmp_path, _ENTRY)
    file_hash = f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
    facts = agent_manifest_facts({"evidence-agent": file_hash}, manifest_path=path)
    assert facts["evidence-agent"] is not None


def test_superseded_pin_withholds_facts(tmp_path: Path) -> None:
    path = _write(tmp_path, _ENTRY.replace("sre-platform", "another-department"))
    import yaml

    stale_entry = yaml.safe_load(_ENTRY)["agents"][0]
    facts = agent_manifest_facts(
        {"evidence-agent": canonical_sha256(stale_entry)}, manifest_path=path
    )
    assert facts["evidence-agent"] is None


def test_unknown_principal_and_broken_manifest_withhold_facts(tmp_path: Path) -> None:
    path = _write(tmp_path, _ENTRY)
    assert agent_manifest_facts({"no-such-agent": "sha256:" + "0" * 64}, manifest_path=path) == {
        "no-such-agent": None
    }
    broken = _write(tmp_path, ":: not yaml ::[")
    assert agent_manifest_facts({"evidence-agent": "sha256:" + "0" * 64}, manifest_path=broken) == {
        "evidence-agent": None
    }


def test_checked_in_manifest_is_where_the_projection_reads() -> None:
    """The default path is the artifact release publication hashes."""

    assert MANIFEST_PATH.name == "agent-manifests.yaml"
    assert MANIFEST_PATH.parent.name == "artifacts"
    assert MANIFEST_PATH.is_file()
