"""A connected deployment authenticates its reads, not only its writes.

Two definitions of "connected" existed. The approval path treated a locally
connected development host as connected and demanded a verified Google identity;
the reader path tested only the deployed authority mode. The same host therefore
authenticated its writes and answered its reads as a fixture, while reaching
real customer telemetry.

Governing record: specification 05 §4.2, non-production identities.
"""

from __future__ import annotations

import pytest

from solvan.platform.deployment_authority import (
    FIXTURE_READER_PRINCIPAL,
    connected_to_google_cloud,
    is_fixture_principal,
)


def test_a_deployed_environment_is_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOLVAN_PLATFORM_AUTHORITY_MODE", "GOOGLE_CLOUD_IAM")
    monkeypatch.delenv("SOLVAN_LOCAL_CONNECTED_GCP", raising=False)
    assert connected_to_google_cloud()


def test_a_locally_connected_host_is_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    """The case the reader path used to miss.

    `scripts/start-cloud-dev` sets this and reaches real Google Cloud. Testing
    only the deployed authority mode left it authenticating writes and serving
    reads under nobody's identity.
    """

    monkeypatch.delenv("SOLVAN_PLATFORM_AUTHORITY_MODE", raising=False)
    monkeypatch.setenv("SOLVAN_LOCAL_CONNECTED_GCP", "true")
    assert connected_to_google_cloud()


def test_a_hermetic_harness_is_not_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOLVAN_PLATFORM_AUTHORITY_MODE", raising=False)
    monkeypatch.delenv("SOLVAN_LOCAL_CONNECTED_GCP", raising=False)
    assert not connected_to_google_cloud()


@pytest.mark.parametrize("value", ["", "false", "TRUE", "yes", "1"])
def test_only_an_exact_marker_makes_a_deployment_connected(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """Absence and near-misses yield a harness, never a connected deployment.

    The failure direction matters: a misspelled marker must produce something
    that reaches nothing, not something that reaches everything without an
    identity.
    """

    monkeypatch.delenv("SOLVAN_PLATFORM_AUTHORITY_MODE", raising=False)
    monkeypatch.setenv("SOLVAN_LOCAL_CONNECTED_GCP", value)
    assert not connected_to_google_cloud()


def test_the_fixture_reader_is_not_shaped_like_a_person() -> None:
    """Every human principal is `user:`-prefixed; this one can never be one."""

    assert not FIXTURE_READER_PRINCIPAL.startswith("user:")
    assert is_fixture_principal(FIXTURE_READER_PRINCIPAL)
    assert not is_fixture_principal("user:operator@example.com")


def test_the_reader_path_demands_identity_wherever_the_approval_path_does(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The two paths now share one definition rather than two.

    Asserted against the source, because the defect was that a second copy of
    the condition drifted from the first.
    """

    from pathlib import Path

    source = Path("apps/api/main.py").read_text(encoding="utf-8")
    reader = source[source.index("def _reader_principal") : source.index("def _read_scope")]
    assert "connected_to_google_cloud()" in reader
    assert "GOOGLE_CLOUD_IAM" not in reader
