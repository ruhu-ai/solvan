"""Shared response and transition contracts for connection administration."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RegistrationResponse(BaseModel):
    id: str
    created: bool


class ConnectionEpochCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    expected_epoch: int = Field(ge=1)
    reason: str = Field(min_length=8, max_length=500)


class ConnectionEpochResponse(BaseModel):
    connection_id: str
    connection_epoch: int
    status: Literal["PENDING", "REVOKED"]
