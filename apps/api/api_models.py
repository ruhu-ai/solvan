"""Typed request and response models shared by the API composition root."""

from pydantic import BaseModel, ConfigDict, Field


class HarnessStatus(BaseModel):
    product: str
    version: str
    environment: str
    authority: str
    worktree_id: str
    phase: str
    api_status: str


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    action_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reason: str = Field(min_length=1, max_length=500)


class ApprovalResponse(BaseModel):
    approval_id: str
    action_id: str
    action_digest: str
    workflow_version: int
    created: bool
