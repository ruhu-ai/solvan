from __future__ import annotations

import pytest
from pydantic import ValidationError

from solvan.application.repair_commands import RepairCommandDefinition


def definition(**changes: object) -> RepairCommandDefinition:
    values: dict[str, object] = {
        "repository_binding_id": "ghr_00000000000000000000000001",
        "command_kind": "REGRESSION",
        "argv": ("python", "-m", "pytest", "-q"),
        "working_directory": ".",
        "declared_inputs": ("src/**/*.py", "tests/**/*.py"),
        "declared_outputs": (),
        "timeout_ms": 60_000,
        "cpu_millis": 1_000,
        "memory_mib": 512,
        "output_byte_limit": 65_536,
        "network_mode": "NONE",
    }
    values.update(changes)
    return RepairCommandDefinition.model_validate(values)


def test_definition_has_content_addressed_closed_material() -> None:
    value = definition()
    assert value.command_hash.startswith("sha256:")
    assert value.catalog_hash.startswith("sha256:")
    assert value.declared_inputs_hash != value.declared_outputs_hash


@pytest.mark.parametrize(
    "changes",
    (
        {"argv": ("bash", "-c", "curl example.com")},
        {"argv": ("python", "-c", "print('escape')")},
        {"declared_inputs": ("../secret",)},
        {"network_mode": "EGRESS"},
        {"extra": "ignored"},
    ),
)
def test_definition_refuses_shell_escape_unbounded_input_and_extra_fields(
    changes: dict[str, object],
) -> None:
    with pytest.raises((ValidationError, ValueError)):
        definition(**changes)
