"""Leakage-aware offline ML over causal per-UAV feature snapshots."""
from __future__ import annotations

import csv
import json
import statistics
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline

FEATURE_COLUMNS = [
    "forwarding_ratio", "delivery_ratio", "packets_forwarded", "packets_dropped",
    "neighbor_count", "mobility_mps", "link_stability", "direct_trust",
    "indirect_trust", "historical_trust", "final_trust", "trust_observations",
]


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            raise ValueError(f"CSV is missing a header: {path}")
        rows = list(reader)
    if not rows:
        raise ValueError(f"CSV contains no rows: {path}")
    return rows


def build_temporal_dataset(validation_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Extract causal features; attach labels only after feature rows are formed."""
    validation_dir = Path(validation_dir)
    manifest = _rows(validation_dir / "experiment_manifest.csv")
    dataset: list[dict[str, Any]] = []
    for entry in manifest:
        run_dir = Path(entry["run_directory"])
        if not run_dir.is_absolute():
            run_dir = validation_dir / run_dir
        simulation_dir = run_dir / "simulation"
        uav_rows = _rows(simulation_dir / "uav_events.csv")
        trust_rows = _rows(run_dir / "trust" / "trust_scores.csv")
        by_time_node: dict[tuple[float, int], dict[str, float]] = {}
        for row in uav_rows:
            stamp, node = float(row["timestamp"]), int(row["uav_id"])
            by_time_node[(stamp, node)] = {
                "forwarding_ratio": float(row["forwarding_ratio"]),
                "delivery_ratio": float(row["delivery_ratio"]),
                "packets_forwarded": float(row["packets_forwarded"]),
                "packets_dropped": float(row["packets_dropped"]),
                "neighbor_count": float(row["neighbors"]),
                "mobility_mps": float(row["mobility_mps"]),
                "link_stability": float(row["link_stability"]),
            }
        trust_by_stamp_node: dict[tuple[float, int], list[dict[str, float]]] = {}
        for row in trust_rows:
            key = (float(row["timestamp"]), int(row["target_id"]))
            trust_by_stamp_node.setdefault(key, []).append({
                "direct_trust": float(row["direct_trust"]),
                "indirect_trust": float(row["indirect_trust"]) if row["indirect_trust"] else float("nan"),
                "historical_trust": float(row["historical_trust"]),
                "final_trust": float(row["final_trust"]),
                "trust_observations": float(row["packets_observed"]),
            })
        # Carry forward only already-observed trust records. The current UAV
        # telemetry rows are cumulative up to their own timestamp.
        latest: dict[int, dict[str, float]] = {}
        features_only: list[dict[str, Any]] = []
        timestamps = sorted({stamp for stamp, _ in by_time_node})
        node_ids = sorted({node for _, node in by_time_node})
        for stamp in timestamps:
            for node in node_ids:
                trust_values = trust_by_stamp_node.get((stamp, node), [])
                if trust_values:
                    latest[node] = {
                        key: (statistics.fmean(value[key] for value in trust_values if np.isfinite(value[key]))
                              if any(np.isfinite(value[key]) for value in trust_values) else float("nan"))
                        for key in trust_values[0]
                    }
                record = {**by_time_node[(stamp, node)], **latest.get(node, {})}
                record.setdefault("trust_observations", 0.0)
                dataset_id = f"seed_{entry['seed']}::{entry['scenario']}::{node}"
                features_only.append({
                    **{feature: record.get(feature, float("nan")) for feature in FEATURE_COLUMNS},
                    "seed": int(entry["seed"]), "scenario": entry["scenario"],
                    "node_id": node, "timestamp": stamp, "run_id": dataset_id,
                })
        # Ground-truth labels are read after feature extraction; they are kept
        # in a separate target field and never included in FEATURE_COLUMNS.
        summary = json.loads((simulation_dir / "summary.json").read_text(encoding="utf-8"))
        malicious = {int(node) for node in summary.get("malicious_nodes", [])}
        for record in features_only:
            record["label_malicious"] = int(record["node_id"] in malicious)
        dataset.extend(features_only)
    if not dataset:
        raise ValueError("No temporal feature rows were extracted")
    return dataset, list(FEATURE_COLUMNS)


def train_evaluate(dataset: list[dict[str, Any]], output_dir: Path, *, random_state: int = 42,
                   test_size: float = 0.2) -> dict[str, Any]:
    """Train a random forest with seed-group holdout to prevent frame leakage."""
    output_dir = Path(output_dir); output_dir.mkdir(parents=True, exist_ok=True)
    if not dataset:
        raise ValueError("ML dataset is empty")
    feature_names = list(FEATURE_COLUMNS)
    X = np.asarray([[row.get(name, np.nan) for name in feature_names] for row in dataset], dtype=float)
    y = np.asarray([int(row["label_malicious"]) for row in dataset], dtype=int)
    groups = np.asarray([int(row["seed"]) for row in dataset], dtype=int)
    if len(np.unique(y)) < 2:
        raise ValueError("ML requires both benign and malicious training labels")
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_idx, test_idx = next(splitter.split(X, y, groups))
    train_groups = [int(value) for value in sorted(set(groups[train_idx]))]
    test_groups = [int(value) for value in sorted(set(groups[test_idx]))]
    if set(train_groups) & set(test_groups):
        raise RuntimeError("Grouped seed split leaked a seed between training and test")
    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
        ("classifier", RandomForestClassifier(
            n_estimators=200, min_samples_leaf=3, class_weight="balanced_subsample",
            random_state=random_state, n_jobs=-1,
        )),
    ])
    pipeline.fit(X[train_idx], y[train_idx])
    prediction = pipeline.predict(X[test_idx])
    probabilities = pipeline.predict_proba(X[test_idx])[:, list(pipeline.named_steps["classifier"].classes_).index(1)]
    matrix = confusion_matrix(y[test_idx], prediction, labels=[0, 1]).tolist()
    class_metrics = {}
    for label, name in ((0, "benign"), (1, "malicious")):
        class_metrics[name] = {
            "precision": float(precision_score(y[test_idx], prediction, pos_label=label, zero_division=0)),
            "recall": float(recall_score(y[test_idx], prediction, pos_label=label, zero_division=0)),
            "f1": float(f1_score(y[test_idx], prediction, pos_label=label, zero_division=0)),
            "support": int(np.sum(y[test_idx] == label)),
        }
    metrics = {
        "accuracy": float(accuracy_score(y[test_idx], prediction)),
        "precision_malicious": float(precision_score(y[test_idx], prediction, zero_division=0)),
        "recall_malicious": float(recall_score(y[test_idx], prediction, zero_division=0)),
        "f1_malicious": float(f1_score(y[test_idx], prediction, zero_division=0)),
        "roc_auc_malicious": float(roc_auc_score(y[test_idx], probabilities)) if len(np.unique(y[test_idx])) == 2 else None,
        "average_precision_malicious": float(average_precision_score(y[test_idx], probabilities)) if len(np.unique(y[test_idx])) == 2 else None,
        "per_class": class_metrics,
        "macro_f1": float(f1_score(y[test_idx], prediction, average="macro", zero_division=0)),
        "confusion_matrix_labels_0_1": matrix,
        "train_rows": int(len(train_idx)), "test_rows": int(len(test_idx)),
        "train_seeds": train_groups, "test_seeds": test_groups,
        "feature_names": feature_names,
        "target": "malicious node ground-truth label, evaluation/training only",
        "features_exclude": ["attack_probability", "attack_type", "malicious_node_id", "scenario", "seed", "timestamp", "ground_truth_label"],
        "split": "GroupShuffleSplit by simulation seed; all temporal frames from a seed stay in one partition.",
        "scope": "Retrospective run snapshots; each feature row uses telemetry and trust available up to that timestamp.",
        "model": "RandomForestClassifier(n_estimators=200, min_samples_leaf=3, class_weight=balanced_subsample)",
        "preprocessing": "Median imputation fitted on training rows only.",
        "random_state": random_state,
    }
    joblib.dump(pipeline, output_dir / "model.joblib")
    feature_importance = pipeline.named_steps["classifier"].feature_importances_
    importance_rows = [{"feature": name, "random_forest_impurity_importance": float(value)}
                       for name, value in sorted(zip(feature_names, feature_importance), key=lambda pair: pair[1], reverse=True)]
    with (output_dir / "feature_importance.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["feature", "random_forest_impurity_importance"])
        writer.writeheader(); writer.writerows(importance_rows)
    with (output_dir / "test_predictions.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["seed", "scenario", "node_id", "timestamp", "label_malicious", "prediction_malicious", "probability_malicious"])
        writer.writeheader()
        for index, pred, probability in zip(test_idx, prediction, probabilities):
            row = dataset[int(index)]
            writer.writerow({key: row[key] for key in ("seed", "scenario", "node_id", "timestamp", "label_malicious")}
                             | {"prediction_malicious": int(pred), "probability_malicious": float(probability)})
    (output_dir / "ml_metrics.json").write_text(json.dumps(metrics, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return metrics


def run_ml(validation_dir: Path, output_dir: Path, *, random_state: int = 42) -> dict[str, Any]:
    dataset, _ = build_temporal_dataset(validation_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "node_features.csv").open("w", encoding="utf-8", newline="") as stream:
        columns = FEATURE_COLUMNS + ["seed", "scenario", "node_id", "timestamp", "run_id", "label_malicious"]
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader(); writer.writerows(dataset)
    return train_evaluate(dataset, output_dir, random_state=random_state)


def predict_simulation(model_path: Path, simulation_dir: Path, trust_csv: Path,
                       output_dir: Path) -> dict[str, Any]:
    """Predict at the last observed run timestamp, then evaluate labels afterward."""
    output_dir = Path(output_dir); output_dir.mkdir(parents=True, exist_ok=True)
    model = joblib.load(model_path)
    node_rows = _rows(Path(simulation_dir) / "uav_events.csv")
    latest_uav: dict[int, dict[str, str]] = {}
    for row in node_rows:
        node = int(row["uav_id"])
        if node not in latest_uav or float(row["timestamp"]) > float(latest_uav[node]["timestamp"]):
            latest_uav[node] = row
    trust_rows = _rows(Path(trust_csv))
    by_target: dict[int, list[dict[str, str]]] = {}
    for row in trust_rows:
        by_target.setdefault(int(row["target_id"]), []).append(row)
    features = []
    for node, telemetry in sorted(latest_uav.items()):
        related = by_target.get(node, [])
        latest_stamp = max((float(row["timestamp"]) for row in related), default=None)
        trust_at_latest = [row for row in related if latest_stamp is not None and float(row["timestamp"]) == latest_stamp]
        record = {
            "forwarding_ratio": float(telemetry["forwarding_ratio"]),
            "delivery_ratio": float(telemetry["delivery_ratio"]),
            "packets_forwarded": float(telemetry["packets_forwarded"]),
            "packets_dropped": float(telemetry["packets_dropped"]),
            "neighbor_count": float(telemetry["neighbors"]),
            "mobility_mps": float(telemetry["mobility_mps"]),
            "link_stability": float(telemetry["link_stability"]),
            "direct_trust": _mean_optional(trust_at_latest, "direct_trust"),
            "indirect_trust": _mean_optional(trust_at_latest, "indirect_trust"),
            "historical_trust": _mean_optional(trust_at_latest, "historical_trust"),
            "final_trust": _mean_optional(trust_at_latest, "final_trust"),
            "trust_observations": _mean_optional(trust_at_latest, "packets_observed"),
        }
        features.append({"node_id": node, "timestamp": float(telemetry["timestamp"]), **record})
    X = np.asarray([[row.get(name, np.nan) for name in FEATURE_COLUMNS] for row in features], dtype=float)
    predicted = model.predict(X).astype(int)
    positive_index = list(model.named_steps["classifier"].classes_).index(1)
    probability = model.predict_proba(X)[:, positive_index]
    prediction_rows = [{"node_id": row["node_id"], "timestamp": row["timestamp"],
                        "prediction_malicious": int(label), "probability_malicious": float(prob),
                        **{name: row[name] for name in FEATURE_COLUMNS}}
                       for row, label, prob in zip(features, predicted, probability)]
    _write_rows(output_dir / "ml_predictions.csv", prediction_rows)
    # The prediction artifact exists before labels are loaded for evaluation.
    summary = json.loads((Path(simulation_dir) / "summary.json").read_text(encoding="utf-8"))
    malicious = {int(node) for node in summary.get("malicious_nodes", [])}
    actual = np.asarray([int(row["node_id"] in malicious) for row in prediction_rows], dtype=int)
    confusion = confusion_matrix(actual, predicted, labels=[0, 1]).tolist()
    from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
    result = {
        "evaluation_unit": "one final causal feature snapshot per UAV",
        "predictions_written_before_ground_truth_load": True,
        "ground_truth_source": "simulation summary; evaluation only",
        "accuracy": float(accuracy_score(actual, predicted)),
        "precision_malicious": float(precision_score(actual, predicted, zero_division=0)),
        "recall_malicious": float(recall_score(actual, predicted, zero_division=0)) if actual.sum() else None,
        "f1_malicious": float(f1_score(actual, predicted, zero_division=0)) if actual.sum() else None,
        "confusion_matrix_labels_0_1": confusion,
        "prediction_count": len(prediction_rows),
        "model_path": str(Path(model_path).resolve()),
    }
    (output_dir / "ml_run_metrics.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return result


def _mean_optional(rows: list[dict[str, str]], name: str) -> float:
    values = [float(row[name]) for row in rows if row.get(name, "") not in (None, "")]
    return statistics.fmean(values) if values else float("nan")


def _write_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]) if rows else ["node_id"])
        writer.writeheader(); writer.writerows(rows)


__all__ = ["FEATURE_COLUMNS", "build_temporal_dataset", "predict_simulation", "run_ml", "train_evaluate"]
