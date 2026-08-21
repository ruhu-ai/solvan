from __future__ import annotations

import pytest

from solvan.agents import private_service_auth


def test_private_service_headers_mints_for_exact_configured_audience(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOLVAN_TEST_AUDIENCE", "https://private.example")
    calls: list[str] = []
    monkeypatch.setattr(
        private_service_auth.id_token,
        "fetch_id_token",
        lambda request, audience: calls.append(audience) or "signed-token",
    )

    headers = private_service_auth.private_service_headers(audience_variable="SOLVAN_TEST_AUDIENCE")
    assert headers == {"Authorization": "Bearer signed-token"}
    assert calls == ["https://private.example"]


@pytest.mark.parametrize("value", [None, "http://unsafe.example"])
def test_private_service_headers_refuses_missing_or_non_https_audience(
    monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    if value is None:
        monkeypatch.delenv("SOLVAN_TEST_AUDIENCE", raising=False)
    else:
        monkeypatch.setenv("SOLVAN_TEST_AUDIENCE", value)
    with pytest.raises(RuntimeError, match="HTTPS service audience"):
        private_service_auth.private_service_headers(audience_variable="SOLVAN_TEST_AUDIENCE")
