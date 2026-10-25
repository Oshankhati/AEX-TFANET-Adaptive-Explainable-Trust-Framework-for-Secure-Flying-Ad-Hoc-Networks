"""SHAP explanations for the trained model, with explicit availability status."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np


def run_explanations(ml_dir: Path, output_dir: Path) -> dict[str, Any]:
    ml_dir, output_dir = Path(ml_dir), Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    metrics = json.loads((ml_dir / "ml_metrics.json").read_text(encoding="utf-8"))
    try:
        import shap  # type: ignore
    except Exception as exc:
        result = {
            "shap_status": "Unavailable in current environment.",
            "reason": f"SHAP import failed: {type(exc).__name__}: {exc}",
            "local_shap_explanation": "Not evaluated.",
            "global_shap_importance": "Not evaluated.",
            "fallback": "feature_importance.csv contains Random Forest impurity importance; it is not SHAP and has no signed local contributions.",
            "lime_status": "Unavailable in current environment.",
        }
        (output_dir / "xai_status.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return result

    feature_names = list(metrics["feature_names"])
    test_rows: list[dict[str, str]] = []
    with (ml_dir / "test_predictions.csv").open(encoding="utf-8-sig", newline="") as stream:
        test_rows = list(csv.DictReader(stream))
    if not test_rows:
        raise ValueError("No held-out test predictions are available for SHAP")
    feature_rows: list[dict[str, str]] = []
    with (ml_dir / "node_features.csv").open(encoding="utf-8-sig", newline="") as stream:
        feature_rows = list(csv.DictReader(stream))
    feature_index = {
        (int(row["seed"]), row["scenario"], int(row["node_id"]), float(row["timestamp"])): row
        for row in feature_rows
    }
    target = next((row for row in test_rows if row["label_malicious"] == "1" and row["prediction_malicious"] == "1"), None)
    if target is None:
        target = next((row for row in test_rows if row["prediction_malicious"] == "1"), test_rows[0])
    key = (int(target["seed"]), target["scenario"], int(target["node_id"]), float(target["timestamp"]))
    source_row = feature_index[key]
    local_matrix = np.asarray([[float(source_row[name]) if source_row[name] else np.nan for name in feature_names]])
    model = joblib.load(ml_dir / "model.joblib")
    imputer = model.named_steps["imputer"]
    classifier = model.named_steps["classifier"]
    transformed = imputer.transform(local_matrix)
    try:
        explainer = shap.TreeExplainer(classifier)
        sv = explainer.shap_values(transformed)
        if isinstance(sv, list):
            contribution = np.asarray(sv[1])[0]
        else:
            array = np.asarray(sv)
            contribution = array[0, :, 1] if array.ndim == 3 and array.shape[-1] > 1 else array[0]
        if len(contribution) != len(feature_names):
            raise ValueError("SHAP output feature dimension does not match the trained feature schema")
        explanation_rows = [
            {"feature": name, "value": float(local_matrix[0, idx]), "shap_value_for_malicious_class": float(contribution[idx])}
            for idx, name in enumerate(feature_names)
        ]
        explanation_rows.sort(key=lambda row: abs(row["shap_value_for_malicious_class"]), reverse=True)
        with (output_dir / "local_shap_explanation.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(explanation_rows[0]))
            writer.writeheader(); writer.writerows(explanation_rows)

        heldout = [row for row in feature_rows if int(row["seed"]) in set(metrics["test_seeds"])]
        sample_count = min(512, len(heldout))
        sample_indices = np.linspace(0, len(heldout) - 1, num=sample_count, dtype=int)
        heldout_sample = [heldout[index] for index in sample_indices]
        X = np.asarray([[float(row[name]) if row[name] else np.nan for name in feature_names] for row in heldout_sample])
        X_transformed = imputer.transform(X)
        global_values = explainer.shap_values(X_transformed)
        if isinstance(global_values, list):
            positive = np.asarray(global_values[1])
        else:
            array = np.asarray(global_values)
            positive = array[:, :, 1] if array.ndim == 3 and array.shape[-1] > 1 else array
        importance = np.mean(np.abs(positive), axis=0)
        global_rows = [{"feature": name, "mean_absolute_shap_value": float(value)}
                       for name, value in sorted(zip(feature_names, importance), key=lambda pair: pair[1], reverse=True)]
        with (output_dir / "global_shap_importance.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=["feature", "mean_absolute_shap_value"])
            writer.writeheader(); writer.writerows(global_rows)
        result = {
            "shap_status": "Available; computed from the trained Random Forest on held-out test rows.",
            "local_example": {"seed": key[0], "scenario": key[1], "node_id": key[2], "timestamp": key[3],
                              "ground_truth_malicious": int(target["label_malicious"]),
                              "model_prediction_malicious": int(target["prediction_malicious"])},
            "local_explanation_file": "local_shap_explanation.csv",
            "global_importance_file": "global_shap_importance.csv",
            "global_importance_rows": len(heldout),
            "global_importance_explanation_sample": sample_count,
            "global_importance_sample_method": "Evenly spaced rows from the held-out seed set; deterministic sampling for bounded explanation runtime.",
            "lime_status": "Not implemented.",
        }
    except Exception as exc:
        result = {
            "shap_status": "Unavailable in current environment.",
            "reason": f"SHAP execution failed: {type(exc).__name__}: {exc}",
            "local_shap_explanation": "Not evaluated.",
            "global_shap_importance": "Not evaluated.",
            "fallback": "feature_importance.csv contains Random Forest impurity importance; it is not SHAP and has no signed local contributions.",
            "lime_status": "Not implemented.",
        }
    (output_dir / "xai_status.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return result


def explain_run_predictions(model_path: Path, ml_metrics_path: Path, predictions_csv: Path,
                            output_dir: Path) -> dict[str, Any]:
    """Explain the highest-scoring observed UAV prediction from one full run."""
    output_dir = Path(output_dir); output_dir.mkdir(parents=True, exist_ok=True)
    try:
        import shap  # type: ignore
    except Exception as exc:
        result = {"shap_status": "Unavailable in current environment.", "reason": f"{type(exc).__name__}: {exc}",
                  "local_explanation": "Not evaluated."}
        (output_dir / "run_xai_status.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return result
    with Path(ml_metrics_path).open(encoding="utf-8") as stream:
        feature_names = json.load(stream)["feature_names"]
    with Path(predictions_csv).open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    if not rows:
        raise ValueError("Run ML prediction rows are empty")
    row = max(rows, key=lambda item: float(item["probability_malicious"]))
    model = joblib.load(model_path)
    raw = np.asarray([[float(row[name]) if row.get(name, "") else np.nan for name in feature_names]])
    transformed = model.named_steps["imputer"].transform(raw)
    explainer = shap.TreeExplainer(model.named_steps["classifier"])
    values = explainer.shap_values(transformed)
    contribution = np.asarray(values[1])[0] if isinstance(values, list) else (
        np.asarray(values)[0, :, 1] if np.asarray(values).ndim == 3 else np.asarray(values)[0]
    )
    details = [{"feature": name, "value": float(raw[0, idx]),
                "shap_value_for_malicious_class": float(contribution[idx])}
               for idx, name in enumerate(feature_names)]
    details.sort(key=lambda item: abs(item["shap_value_for_malicious_class"]), reverse=True)
    with (output_dir / "run_local_shap.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(details[0])); writer.writeheader(); writer.writerows(details)
    result = {
        "shap_status": "Available; local explanation calculated from this run's trained-model prediction.",
        "node_id": int(row["node_id"]), "timestamp": float(row["timestamp"]),
        "prediction_malicious": int(row["prediction_malicious"]),
        "probability_malicious": float(row["probability_malicious"]),
        "local_explanation_file": "run_local_shap.csv",
    }
    (output_dir / "run_xai_status.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return result


__all__ = ["explain_run_predictions", "run_explanations"]
