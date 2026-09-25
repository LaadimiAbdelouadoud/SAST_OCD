"""Project file discovery and source reading."""

from __future__ import annotations

from pathlib import Path

_SKIP_DIRS = {"__pycache__", ".venv", "venv", ".git", "node_modules", ".tox", "dist", "build"}


def discover_files(root: Path) -> list[Path]:
    """Walk *root* recursively and return all .py files, skipping common non-source dirs."""
    results: list[Path] = []
    for path in root.rglob("*.py"):
        if not any(part in _SKIP_DIRS for part in path.parts):
            results.append(path)
    return sorted(results)


def read_source(path: Path) -> str:
    """Read *path* as UTF-8 text; fall back to latin-1 on decode errors."""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1")
