"""h42pki.core stays pure: no ORM, web framework or upper layer (ADR-0002)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import h42pki.core

CORE_DIR = Path(h42pki.core.__file__).parent
FORBIDDEN = ("tortoise", "fastapi", "starlette", "h42pki.models", "h42pki.services", "h42pki.api")
CORE_FILES = sorted(CORE_DIR.rglob("*.py"))


def _is_forbidden(module: str) -> bool:
    return any(module == name or module.startswith(f"{name}.") for name in FORBIDDEN)


def _imported_modules(path: Path) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
    return modules


@pytest.mark.parametrize(
    "path", CORE_FILES, ids=[str(path.relative_to(CORE_DIR)) for path in CORE_FILES]
)
def test_core_module_has_no_forbidden_import(path: Path) -> None:
    forbidden = sorted(module for module in _imported_modules(path) if _is_forbidden(module))

    assert forbidden == []


def test_importing_core_loads_no_forbidden_module() -> None:
    """Transitive check: import every core module in a fresh interpreter."""
    modules = [
        "h42pki.core." + ".".join(path.relative_to(CORE_DIR).with_suffix("").parts)
        for path in CORE_FILES
        if path.stem != "__init__"
    ]
    code = "\n".join(
        [
            "import importlib, sys",
            f"for name in {modules!r}:",
            "    importlib.import_module(name)",
            "print(' '.join(sorted(sys.modules)))",
        ]
    )
    result = subprocess.run(  # noqa: S603 - fixed interpreter and code
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )

    assert "h42pki.core.issuance" in result.stdout.split()
    assert [module for module in result.stdout.split() if _is_forbidden(module)] == []
