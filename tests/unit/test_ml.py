import json

from aex_tfanet.ml import FEATURE_COLUMNS, train_evaluate


def test_training_uses_seed_group_split_and_saves_artifacts(tmp_path):
    rows = []
    for seed in range(8):
        for label in (0, 1):
            row = {feature: 0.0 for feature in FEATURE_COLUMNS}
            row.update({"seed": seed, "scenario": "train", "node_id": label + 1,
                        "timestamp": 1.0, "run_id": f"seed{seed}", "label_malicious": label})
            row["packets_dropped"] = float(label * 10)
            row["forwarding_ratio"] = float(1 - label)
            rows.append(row)

    metrics = train_evaluate(rows, tmp_path, random_state=7, test_size=0.25)

    assert not set(metrics["train_seeds"]) & set(metrics["test_seeds"])
    assert "seed" not in metrics["feature_names"]
    assert "scenario" not in metrics["feature_names"]
    assert 0 <= metrics["roc_auc_malicious"] <= 1
    assert 0 <= metrics["average_precision_malicious"] <= 1
    assert metrics["per_class"]["benign"]["support"] + metrics["per_class"]["malicious"]["support"] == metrics["test_rows"]
    assert (tmp_path / "model.joblib").is_file()
    assert (tmp_path / "feature_importance.csv").is_file()
    saved = json.loads((tmp_path / "ml_metrics.json").read_text(encoding="utf-8"))
    assert saved["confusion_matrix_labels_0_1"] == metrics["confusion_matrix_labels_0_1"]
