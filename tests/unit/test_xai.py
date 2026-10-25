import csv
import json
import sys
import types

import numpy as np

from aex_tfanet.ml import FEATURE_COLUMNS, train_evaluate
from aex_tfanet.xai import run_explanations


def test_shap_uses_saved_model_feature_order_and_real_heldout_rows(tmp_path, monkeypatch):
    rows = []
    for seed in range(8):
        for label in (0, 1):
            row = {feature: 0.0 for feature in FEATURE_COLUMNS}
            row.update({"seed": seed, "scenario": "packet_drop", "node_id": label + 1,
                        "timestamp": 10.0, "run_id": f"seed{seed}", "label_malicious": label})
            row["packets_dropped"] = float(label * 5 + seed % 2)
            row["forwarding_ratio"] = float(1 - label)
            rows.append(row)

    model_dir = tmp_path / "ml"
    model_dir.mkdir()
    metrics = train_evaluate(rows, model_dir, random_state=3, test_size=0.25)
    with (model_dir / "node_features.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    class Explainer:
        def __init__(self, model):
            self.model = model

        def shap_values(self, values):
            result = np.zeros((len(values), len(FEATURE_COLUMNS), 2))
            result[:, 3, 1] = -0.75
            result[:, 1, 1] = 0.20
            return result

    monkeypatch.setitem(sys.modules, "shap", types.SimpleNamespace(TreeExplainer=Explainer))
    status = run_explanations(model_dir, tmp_path / "xai")

    assert status["shap_status"].startswith("Available")
    assert status["local_example"]["seed"] in metrics["test_seeds"]
    with (tmp_path / "xai" / "local_shap_explanation.csv").open(encoding="utf-8") as stream:
        explanation = list(csv.DictReader(stream))
    assert explanation[0]["feature"] == "packets_dropped"
    assert float(explanation[0]["shap_value_for_malicious_class"]) == -0.75
    assert [row["feature"] for row in explanation] == sorted(
        FEATURE_COLUMNS, key=lambda name: abs(float(next(item["shap_value_for_malicious_class"] for item in explanation if item["feature"] == name))), reverse=True
    )
    saved = json.loads((tmp_path / "xai" / "xai_status.json").read_text(encoding="utf-8"))
    assert saved["global_importance_explanation_sample"] <= 512
