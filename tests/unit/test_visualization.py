import csv
import json

from aex_tfanet.visualization import plot_confusion_matrix, plot_shap_importance, plot_trust_history


def test_visualization_helpers_write_figures_from_actual_csv_json(tmp_path):
    trust = tmp_path / "trust.csv"
    with trust.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["timestamp", "target_id", "final_trust"])
        writer.writeheader()
        writer.writerows([
            {"timestamp": 0, "target_id": 1, "final_trust": 0.8},
            {"timestamp": 1, "target_id": 1, "final_trust": 0.6},
            {"timestamp": 0, "target_id": 2, "final_trust": 0.9},
        ])
    outputs = plot_trust_history(trust, tmp_path / "figures")
    assert len(outputs) == 2
    assert all(path.is_file() and path.stat().st_size > 0 for path in outputs)

    metrics = tmp_path / "metrics.json"
    metrics.write_text(json.dumps({"confusion_matrix": {
        "actual_positive": {"predicted_positive": 1, "predicted_negative": 2},
        "actual_negative": {"predicted_positive": 3, "predicted_negative": 4},
    }}), encoding="utf-8")
    assert plot_confusion_matrix(metrics, tmp_path / "figures" / "confusion.png").is_file()

    shap = tmp_path / "shap.csv"
    with shap.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["feature", "mean_absolute_shap_value"])
        writer.writeheader(); writer.writerow({"feature": "forwarding_ratio", "mean_absolute_shap_value": .2})
    assert plot_shap_importance(shap, tmp_path / "figures" / "shap.png").is_file()
