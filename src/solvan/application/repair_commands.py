"""Administrator-registered, literal no-egress repair command definitions."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from solvan.application.workspace_candidate import CatalogCommand, valid_repository_selector
from solvan.application.workspace_hashing import canonical_sha256


class RepairCommandDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    repository_binding_id: str = Field(pattern=r"^ghr_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
    command_kind: Literal["REPRODUCTION", "REGRESSION"]
    argv: tuple[str, ...] = Field(min_length=1, max_length=32)
    working_directory: str = Field(min_length=1, max_length=256)
    declared_inputs: tuple[str, ...] = Field(min_length=1, max_length=64)
    declared_outputs: tuple[str, ...] = Field(default=(), max_length=64)
    timeout_ms: int = Field(ge=1, le=120_000)
    cpu_millis: int = Field(ge=1, le=1_000)
    memory_mib: int = Field(ge=16, le=1_024)
    output_byte_limit: int = Field(ge=1, le=131_072)
    network_mode: Literal["NONE"] = "NONE"

    @model_validator(mode="after")
    def validate_literal_command(self) -> Self:
        CatalogCommand(
            command_id="rcc_contract",
            argv=self.argv,
            working_directory=self.working_directory,
            timeout_ms=self.timeout_ms,
            cpu_millis=self.cpu_millis,
            memory_mib=self.memory_mib,
            output_byte_limit=self.output_byte_limit,
            network_mode=self.network_mode,
        )
        for label, selectors in (
            ("input", self.declared_inputs),
            ("output", self.declared_outputs),
        ):
            if len(selectors) != len(set(selectors)) or not all(
                valid_repository_selector(selector) for selector in selectors
            ):
                raise ValueError(f"declared {label} selectors are malformed")
        return self

    @property
    def command_hash(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))

    @property
    def declared_inputs_hash(self) -> str:
        return canonical_sha256(list(self.declared_inputs))

    @property
    def declared_outputs_hash(self) -> str:
        return canonical_sha256(list(self.declared_outputs))

    @property
    def catalog_hash(self) -> str:
        return canonical_sha256(
            {
                "schema_version": 1,
                "definition_kind": "REPAIR_COMMAND",
                "command_hash": self.command_hash,
                "declared_inputs_hash": self.declared_inputs_hash,
                "declared_outputs_hash": self.declared_outputs_hash,
            }
        )
