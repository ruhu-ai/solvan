from pathlib import Path
from typing import Any

import yaml

from tools import check_architecture


def config(root: Path) -> dict[str, Any]:
    configuration: dict[str, Any] = {
        "layers": {
            "domain": {"path": "src/solvan/domain", "may_import": ["domain"]},
            "application": {
                "path": "src/solvan/application",
                "may_import": ["application", "domain"],
            },
        },
        "forbidden_imports": {"src/solvan/domain": ["fastapi"]},
        "mutation_connector_allowed_roots": ["apps/actuator"],
        "file_size_limits": {"python": 3, "typescript": 3, "tsx": 3, "css": 3},
        "exceptions_file": "config/architecture-exceptions.yaml",
    }
    exception_path = root / "config/architecture-exceptions.yaml"
    exception_path.parent.mkdir(parents=True)
    exception_path.write_text(
        yaml.safe_dump({"schema_version": 1, "exceptions": []}),
        encoding="utf-8",
    )
    return configuration


def write(root: Path, relative: str, source: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def test_forbidden_dependency_and_layer_edge_are_rejected(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(check_architecture, "ROOT", tmp_path)
    write(
        tmp_path,
        "src/solvan/domain/bad.py",
        "import fastapi\nfrom solvan.application import commands\n",
    )
    rules = {finding.rule for finding in check_architecture.check_python(config(tmp_path))}
    assert {"ARCH001", "ARCH002"} <= rules


def test_mutation_import_and_print_are_rejected(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(check_architecture, "ROOT", tmp_path)
    write(
        tmp_path,
        "apps/api/bad.py",
        "from solvan.connectors.mutation import execute\nprint(execute)\n",
    )
    rules = {finding.rule for finding in check_architecture.check_python(config(tmp_path))}
    assert {"ARCH003", "TASTE001"} <= rules


def test_a_sibling_of_the_actuator_root_does_not_inherit_mutation_rights(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    """`apps/actuator` is a directory, not a string prefix.

    A bare `startswith` handed every future `apps/actuator*` directory the one
    capability the repository confines to a single composition root.
    """

    monkeypatch.setattr(check_architecture, "ROOT", tmp_path)
    write(
        tmp_path,
        "apps/actuator_probe/sneaky.py",
        "from solvan.connectors.mutation import execute\n",
    )
    write(
        tmp_path,
        "apps/actuator/legitimate.py",
        "from solvan.connectors.mutation import execute\n",
    )
    findings = check_architecture.check_python(config(tmp_path))
    offenders = {
        finding.path.relative_to(tmp_path).as_posix()
        for finding in findings
        if finding.rule == "ARCH003"
    }
    assert offenders == {"apps/actuator_probe/sneaky.py"}


def test_the_customer_resident_relay_cannot_import_the_actuator() -> None:
    """Rule 8 covers the executable that ships, not only the control plane."""

    rules = check_architecture.load_yaml(check_architecture.ROOT / "config/architecture-rules.yaml")
    forbidden = rules["forbidden_imports"]
    assert "apps.actuator" in forbidden["apps/solvant_relay"]
    assert "solvan.connectors.mutation" in forbidden["apps/solvant_relay"]
    assert "apps.solvant_relay" in forbidden["apps/actuator"]


def test_file_growth_ceiling_requires_an_owned_exception(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(check_architecture, "ROOT", tmp_path)
    write(tmp_path, "src/solvan/domain/large.py", "# one\n# two\n# three\n# four\n")
    findings = check_architecture.check_file_sizes(config(tmp_path))
    assert [finding.rule for finding in findings] == ["SIZE001"]
    assert "removal condition" in findings[0].remediation


def test_nested_locked_environment_is_not_scanned_as_first_party(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(check_architecture, "ROOT", tmp_path)
    write(
        tmp_path,
        "apps/provider/.venv/lib/python3.12/site-packages/vendor.py",
        "print('vendor')\n# two\n# three\n# four\n",
    )
    configuration = config(tmp_path)
    assert check_architecture.check_python(configuration) == []
    assert check_architecture.check_file_sizes(configuration) == []
