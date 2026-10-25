from __future__ import annotations

import json

from aex_tfanet.pipeline.runner import run_experiment_scaffold
from aex_tfanet.utils.paths import project_root


def test_experiment_scaffold_writes_status_not_metrics() -> None:
    overlay = project_root() / "experiments" / "configs" / "normal.yaml"
    out = run_experiment_scaffold(overlay)
    assert (out / "config.yaml").is_file()
    assert (out / "environment.json").is_file()
    assert (out / "STATUS.txt").is_file()
    status = (out / "STATUS.txt").read_text(encoding="utf-8")
    assert "not implemented" in status.lower()
    env = json.loads((out / "environment.json").read_text(encoding="utf-8"))
    assert "ns3_available" in env
    assert not (out / "metrics.csv").exists()
