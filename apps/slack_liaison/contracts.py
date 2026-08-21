"""Configuration and small typed receipts for the Slack Liaison adapter."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from solvan.domain import Scope

_TEAM = re.compile(r"^T[A-Z0-9]{2,30}$")


@dataclass(frozen=True, slots=True)
class SlackInstallation:
    team_id: str
    scope: Scope
    signing_secret_ref: str
    bot_token_ref: str
    payload_bucket: str
    console_base_url: str
    worker_audience: str
    worker_service_account: str

    def __post_init__(self) -> None:
        if not _TEAM.fullmatch(self.team_id):
            raise ValueError("Slack team id is invalid")
        if not self.signing_secret_ref or not self.bot_token_ref:
            raise ValueError("Slack Secret Manager references are required")
        if not self.payload_bucket or "/" in self.payload_bucket:
            raise ValueError("Slack payload bucket is invalid")
        if not self.console_base_url.startswith("https://"):
            raise ValueError("Slack console URL must use HTTPS")
        if not self.worker_audience.startswith("https://"):
            raise ValueError("Slack worker audience must use HTTPS")
        if "@" not in self.worker_service_account:
            raise ValueError("Slack worker service account is invalid")


@dataclass(frozen=True, slots=True)
class SlackIngressReceipt:
    status: str
    event_id: str | None = None
    created: bool = False


@dataclass(frozen=True, slots=True)
class SlackWorkReceipt:
    status: str
    event_id: str | None = None
    delivery_id: str | None = None


def installation_from_environment() -> SlackInstallation:
    required = {
        name: os.environ.get(name, "").strip()
        for name in (
            "SOLVAN_SLACK_TEAM_ID",
            "SOLVAN_ORGANIZATION_ID",
            "SOLVAN_PROJECT_ID",
            "SOLVAN_ENVIRONMENT_ID",
            "SOLVAN_SLACK_SIGNING_SECRET_REF",
            "SOLVAN_SLACK_BOT_TOKEN_REF",
            "SOLVAN_LIAISON_PAYLOAD_BUCKET",
            "SOLVAN_CONSOLE_BASE_URL",
            "SOLVAN_SLACK_LIAISON_AUDIENCE",
            "SOLVAN_SLACK_LIAISON_SERVICE_ACCOUNT",
        )
    }
    missing = sorted(name for name, value in required.items() if not value)
    if missing:
        raise RuntimeError(f"Slack Liaison configuration is incomplete: {', '.join(missing)}")
    return SlackInstallation(
        team_id=required["SOLVAN_SLACK_TEAM_ID"],
        scope=Scope(
            required["SOLVAN_ORGANIZATION_ID"],
            required["SOLVAN_PROJECT_ID"],
            required["SOLVAN_ENVIRONMENT_ID"],
        ),
        signing_secret_ref=required["SOLVAN_SLACK_SIGNING_SECRET_REF"],
        bot_token_ref=required["SOLVAN_SLACK_BOT_TOKEN_REF"],
        payload_bucket=required["SOLVAN_LIAISON_PAYLOAD_BUCKET"],
        console_base_url=required["SOLVAN_CONSOLE_BASE_URL"].rstrip("/"),
        worker_audience=required["SOLVAN_SLACK_LIAISON_AUDIENCE"],
        worker_service_account=required["SOLVAN_SLACK_LIAISON_SERVICE_ACCOUNT"],
    )
