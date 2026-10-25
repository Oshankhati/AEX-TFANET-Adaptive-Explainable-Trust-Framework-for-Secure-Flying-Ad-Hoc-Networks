"""Project path helpers."""

from __future__ import annotations

from pathlib import Path


def project_root(start: Path | None = None) -> Path:
    """Return the repository root (directory that contains pyproject.toml)."""

    cursor = (start or Path(__file__).resolve()).absolute()
    if cursor.is_file():
        cursor = cursor.parent
    for candidate in (cursor, *cursor.parents):
        if (candidate / "pyproject.toml").is_file() and (candidate / "config.yaml").is_file():
            return candidate
    raise FileNotFoundError(
        "Could not locate AEX-TFANET project root (expected pyproject.toml and config.yaml)."
    )
