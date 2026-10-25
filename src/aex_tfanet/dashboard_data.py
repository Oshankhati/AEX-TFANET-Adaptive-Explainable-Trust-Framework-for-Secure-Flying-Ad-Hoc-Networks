"""Read-only, path-confined access to saved dashboard artifacts."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd


class ArtifactError(ValueError):
    """An artifact is missing, malformed, or outside the selected results root."""


def confined_path(results_root: Path, run_dir: Path, relative: str) -> Path:
    """Resolve a run artifact while preventing traversal outside results/run."""
    root = Path(results_root).resolve()
    run = Path(run_dir).resolve()
    if not run.is_relative_to(root):
        raise ArtifactError("Selected experiment is outside the configured results directory.")
    if run == root:
        raise ArtifactError("Invalid experiment directory.")
    target = (run / relative).resolve()
    if not target.is_relative_to(run):
        raise ArtifactError("Artifact path is outside the selected experiment.")
    return target


def discover_experiments(results_root: Path) -> list[Path]:
    """Find saved simulation runs and return newest first, confined to root."""
    root = Path(results_root).resolve()
    if not root.is_dir():
        return []
    found: dict[str, Path] = {}
    for summary in root.rglob("simulation/summary.json"):
        run = summary.parent.parent.resolve()
        if run.is_relative_to(root) and summary.is_file():
            found[str(run)] = run
    return sorted(found.values(), key=lambda path: path.stat().st_mtime, reverse=True)


def read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ArtifactError(f"Required JSON artifact is missing: {path.name}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"Could not read {path.name}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ArtifactError(f"{path.name} must contain a JSON object.")
    return payload


def read_csv(path: Path, *, usecols: list[str] | None = None) -> pd.DataFrame:
    if not path.is_file():
        raise ArtifactError(f"Required CSV artifact is missing: {path.name}")
    try:
        frame = pd.read_csv(path, usecols=usecols)
    except (OSError, UnicodeError, pd.errors.ParserError, ValueError) as exc:
        raise ArtifactError(f"Could not read {path.name}: {exc}") from exc
    return frame


def artifact_inventory(run_dir: Path) -> list[dict[str, Any]]:
    """List files relative to the run; never follows symlinked files outward."""
    run = Path(run_dir).resolve()
    items = []
    for path in sorted(run.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        resolved = path.resolve()
        if resolved.is_relative_to(run):
            items.append({"artifact": str(path.relative_to(run)), "bytes": path.stat().st_size})
    return items
