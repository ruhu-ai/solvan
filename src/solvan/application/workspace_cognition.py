"""Typed, proposed-only cognition retained by a logical workspace."""

from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.domain import validate_identifier


class _CognitionModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class WorkspaceHypothesisProposal(_CognitionModel):
    hypothesis_key: str = Field(pattern=r"^[a-z][a-z0-9._-]{2,127}$")
    statement: str = Field(min_length=1, max_length=16_000)
    supporting_citations: tuple[str, ...] = Field(min_length=1)
    contradicting_citations: tuple[str, ...]
    leading: bool

    @model_validator(mode="after")
    def validate_citations(self) -> Self:
        support = set(self.supporting_citations)
        contradictions = set(self.contradicting_citations)
        if len(support) != len(self.supporting_citations) or len(contradictions) != len(
            self.contradicting_citations
        ):
            raise ValueError("hypothesis citations must be unique")
        if support & contradictions:
            raise ValueError("one citation cannot both support and contradict a hypothesis")
        return self


class WorkspaceCognitionArtifact(_CognitionModel):
    """Durable cognition bound to one run; never an adjudicated fact."""

    schema_version: int = Field(default=1, ge=1, le=1)
    trust_class: str = Field(pattern=r"^PROPOSED$")
    workspace_id: str
    workspace_generation: int = Field(ge=1)
    agent_run_id: str
    confirmed_fast_lane_cause_id: str
    mechanism: str = Field(min_length=1, max_length=32_000)
    hypotheses: tuple[WorkspaceHypothesisProposal, ...] = Field(min_length=2)
    reproduction_command: str = Field(min_length=1, max_length=4_000)
    citations: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_cognition(self) -> Self:
        for value, prefix in (
            (self.workspace_id, "wsp"),
            (self.agent_run_id, "run"),
            (self.confirmed_fast_lane_cause_id, "hyp"),
        ):
            validate_identifier(value, expected_prefix=prefix)
        if len(set(self.citations)) != len(self.citations):
            raise ValueError("cognition citations must be unique")
        if sum(item.leading for item in self.hypotheses) != 1:
            raise ValueError("cognition requires exactly one leading hypothesis")
        if not any(item.contradicting_citations for item in self.hypotheses):
            raise ValueError("cognition requires explicit contradiction evidence")
        cited = set(self.citations)
        hypothesis_citations = {
            citation
            for hypothesis in self.hypotheses
            for citation in (
                *hypothesis.supporting_citations,
                *hypothesis.contradicting_citations,
            )
        }
        if not hypothesis_citations <= cited:
            raise ValueError("hypothesis evidence must be present in cognition citations")
        return self
