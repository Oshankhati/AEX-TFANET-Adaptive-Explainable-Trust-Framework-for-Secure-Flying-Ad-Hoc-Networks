"""Launch the optional Streamlit research dashboard."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from aex_tfanet.exceptions import EnvironmentError
from aex_tfanet.utils.paths import project_root


def launch_dashboard(results_directory: Path | None = None) -> int:
    try:
        import streamlit  # noqa: F401
    except Exception as exc:
        raise EnvironmentError("Streamlit is unavailable. Install the optional dashboard dependency with `python -m pip install -r requirements-optional.txt`.") from exc
    app = project_root() / "dashboard" / "app.py"
    environment = os.environ.copy()
    if results_directory is not None:
        environment["AEX_TFANET_RESULTS"] = str(Path(results_directory).resolve())
    return subprocess.call(
        [sys.executable, "-m", "streamlit", "run", str(app), "--server.address=127.0.0.1", "--server.headless=true"],
        env=environment,
    )


__all__ = ["launch_dashboard"]
