"""Mechanically enforce the dependency and repository taste rules."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRECTORY_NAMES = frozenset({".venv", "__pycache__"})


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    rule: str
    message: str
    remediation: str

    def render(self) -> str:
        relative = self.path.relative_to(ROOT)
        return f"{relative}:{self.line}: [{self.rule}] {self.message}\n  Fix: {self.remediation}"


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: expected a YAML mapping")
    return value


def python_imports(path: Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend((node.lineno, alias.name) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append((node.lineno, node.module))
    return imports


def layer_for(path: Path, layers: dict[str, Any]) -> str | None:
    relative = path.relative_to(ROOT).as_posix()
    for name, rule in layers.items():
        if relative == rule["path"] or relative.startswith(f"{rule['path']}/"):
            return str(name)
    return None


def solvan_import_layer(module: str) -> str | None:
    parts = module.split(".")
    if len(parts) >= 2 and parts[0] == "solvan":
        return parts[1]
    return None


def is_first_party_path(path: Path) -> bool:
    return not EXCLUDED_DIRECTORY_NAMES.intersection(path.relative_to(ROOT).parts)


def check_python(config: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    layers = config["layers"]
    forbidden: dict[str, list[str]] = config["forbidden_imports"]
    # Matched on path boundaries, never as a bare string prefix: `apps/actuator`
    # must not hand mutation-connector rights to a future `apps/actuator_probe/`.
    allowed_mutation_roots = tuple(config["mutation_connector_allowed_roots"])
    files = sorted(
        path
        for path in (*ROOT.glob("src/**/*.py"), *ROOT.glob("apps/**/*.py"))
        if is_first_party_path(path)
    )
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        source_layer = layer_for(path, layers)
        imports = python_imports(path)
        for line, module in imports:
            target_layer = solvan_import_layer(module)
            if source_layer and target_layer:
                allowed = set(layers[source_layer]["may_import"])
                if target_layer not in allowed:
                    findings.append(
                        Finding(
                            path,
                            line,
                            "ARCH001",
                            (
                                f"{source_layer} imports forbidden Solvan layer "
                                f"{target_layer} via {module}"
                            ),
                            f"depend only on {sorted(allowed)} or introduce an application port",
                        )
                    )
            for prefix, banned_modules in forbidden.items():
                if relative == prefix or relative.startswith(f"{prefix}/"):
                    for banned in banned_modules:
                        if module == banned or module.startswith(f"{banned}."):
                            findings.append(
                                Finding(
                                    path,
                                    line,
                                    "ARCH002",
                                    f"{module} is forbidden below {prefix}",
                                    "move the integration to an adapter and depend on a typed port",
                                )
                            )
            if module.startswith("solvan.connectors.mutation") and not any(
                relative == root or relative.startswith(f"{root}/")
                for root in allowed_mutation_roots
            ):
                findings.append(
                    Finding(
                        path,
                        line,
                        "ARCH003",
                        "a mutation connector is imported outside the actuator composition root",
                        "invoke the private actuator with an authorized action ID",
                    )
                )
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "print"
            ):
                findings.append(
                    Finding(
                        path,
                        node.lineno,
                        "TASTE001",
                        "print() is forbidden in product code",
                        "emit a structured log event without prompt, secret, or PII content",
                    )
                )
    return findings


def check_file_sizes(config: dict[str, Any]) -> list[Finding]:
    limits: dict[str, int] = config["file_size_limits"]
    suffixes = {".py": "python", ".ts": "typescript", ".tsx": "tsx", ".css": "css"}
    exceptions = load_yaml(ROOT / config["exceptions_file"])["exceptions"]
    findings: list[Finding] = []
    today = date.today()
    excepted: dict[str, Any] = {}
    exceptions_path = ROOT / config["exceptions_file"]
    for item in exceptions:
        # The dates were previously decorative: nothing read `expires`, so an
        # exception outlived its removal condition indefinitely. An expired or
        # undated exception grants nothing.
        expires = item.get("expires")
        if not isinstance(expires, date):
            findings.append(
                Finding(
                    exceptions_path,
                    1,
                    "SIZE002",
                    f"size exception for {item['path']} has no parsable `expires` date",
                    "give the exception an owner, an ISO expiry date and a removal condition",
                )
            )
            continue
        if expires < today:
            findings.append(
                Finding(
                    exceptions_path,
                    1,
                    "SIZE003",
                    f"size exception for {item['path']} expired on {expires.isoformat()}",
                    "split the file by responsibility, or renew the exception with a new "
                    "owner, date and removal condition in a reviewed commit",
                )
            )
            continue
        excepted[item["path"]] = item
    for base in (ROOT / "src", ROOT / "apps"):
        for path in base.rglob("*"):
            kind = suffixes.get(path.suffix)
            if not path.is_file() or not kind or not is_first_party_path(path):
                continue
            count = len(path.read_text(encoding="utf-8").splitlines())
            limit = limits[kind]
            relative = path.relative_to(ROOT).as_posix()
            if count > limit and relative not in excepted:
                findings.append(
                    Finding(
                        path,
                        limit + 1,
                        "SIZE001",
                        f"{count} lines exceeds the {kind} ceiling of {limit}",
                        (
                            "split by responsibility or add a dated, owned exception "
                            "with a removal condition"
                        ),
                    )
                )
    return findings


def main() -> None:
    config = load_yaml(ROOT / "config/architecture-rules.yaml")
    findings = [*check_python(config), *check_file_sizes(config)]
    if findings:
        print("\n".join(finding.render() for finding in findings))
        raise SystemExit(f"Architecture check failed with {len(findings)} finding(s)")
    print("Architecture check passed")


if __name__ == "__main__":
    main()
