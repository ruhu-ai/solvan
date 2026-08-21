from __future__ import annotations

from pathlib import Path

from apps.api import human_identity, main


def test_approval_principal_uses_dedicated_human_token_boundary(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("SOLVAN_PLATFORM_AUTHORITY_MODE", "GOOGLE_CLOUD_IAM")
    monkeypatch.setenv("SOLVAN_APPROVAL_AUDIENCE", "111111111111-abc123.apps.googleusercontent.com")
    monkeypatch.setattr(
        human_identity.id_token,
        "verify_oauth2_token",
        lambda token, request, audience: {
            "email": "Approver@Example.com",
            "email_verified": True,
        },
    )
    assert main._approval_principal("Bearer one-time-human-token") == ("user:approver@example.com")


def test_console_keeps_workload_and_human_tokens_separate() -> None:
    source = (Path(__file__).parents[2] / "apps" / "console" / "server.mjs").read_text(
        encoding="utf-8"
    )
    assert "const token = await identityToken();" in source
    assert 'proxyHeaders["X-Solvan-Approval-Token"] = approvalToken' in source
    assert "const token = approvalToken ?? await identityToken();" not in source
