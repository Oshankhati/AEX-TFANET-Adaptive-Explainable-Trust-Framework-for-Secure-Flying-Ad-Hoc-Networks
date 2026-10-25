"""Full end-to-end: simulation -> trust -> detection -> routing -> metrics."""

from __future__ import annotations

from aex_tfanet.cli import main
import json


def test_full_pipeline(tmp_path) -> None:
    output = tmp_path / "full_run"
    assert main(["experiment", "--config", "experiments/configs/normal.yaml",
                 "--output", str(output)]) == 0
    assert all((output / path).is_file() for path in (
        "simulation/summary.json", "simulation/route_decisions.csv", "trust/trust_scores.csv",
        "detection/detection_metrics.json", "metrics/metrics.json", "figures/trust_over_time.png",
        "ml/ml_status.json", "xai/xai_status.json", "manifest.json",
    ))
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["prediction_labels_available_to_detector"] is False
    assert manifest["simulator"] == "Simplified Python FANET Model — NOT NS-3"
    assert manifest["ml"]["status"] == "Not evaluated. No trained ML model was provided."
    assert manifest["xai"]["shap_status"] == "Not evaluated. ML model unavailable."
    assert "ML/XAI status" in (output / "STATUS.txt").read_text(encoding="utf-8")
