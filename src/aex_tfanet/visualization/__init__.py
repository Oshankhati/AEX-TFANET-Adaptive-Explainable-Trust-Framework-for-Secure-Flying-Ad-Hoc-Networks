"""Publication-style figures derived from saved experimental outputs."""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def plot_trust_history(trust_csv: Path, output_dir: Path) -> list[Path]:
    rows = _read_csv(trust_csv)
    output_dir = Path(output_dir); output_dir.mkdir(parents=True, exist_ok=True)
    by_node_time: dict[tuple[int, float], list[float]] = defaultdict(list)
    for row in rows:
        by_node_time[(int(row["target_id"]), float(row["timestamp"]))].append(float(row["final_trust"]))
    nodes = sorted({node for node, _ in by_node_time})
    times = sorted({stamp for _, stamp in by_node_time})
    paths = []
    fig, ax = plt.subplots(figsize=(9, 5))
    for node in nodes:
        points = [(stamp, sum(by_node_time[(node, stamp)]) / len(by_node_time[(node, stamp)]))
                  for stamp in times if (node, stamp) in by_node_time]
        if points:
            ax.plot([point[0] for point in points], [point[1] for point in points], label=f"UAV {node}")
    ax.set_title("Observed relational trust over simulation time")
    ax.set_xlabel("Simulation time (s)"); ax.set_ylabel("Mean latest trust (unitless, 0–1)")
    ax.grid(alpha=.25); ax.legend(title="Target node", ncol=2)
    fig.text(.01, .01, f"Source: {Path(trust_csv).name}; mean over available observer-target trust rows.", fontsize=8)
    fig.tight_layout(); path = output_dir / "trust_over_time.png"; fig.savefig(path, dpi=160); plt.close(fig); paths.append(path)

    latest = {node: sum(values) / len(values) for (node, stamp), values in by_node_time.items()
              if stamp == max(t for n, t in by_node_time if n == node)}
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar([str(node) for node in sorted(latest)], [latest[node] for node in sorted(latest)], color="#2563eb")
    ax.set_title("Latest observed trust by UAV"); ax.set_xlabel("UAV ID"); ax.set_ylabel("Mean latest relational trust (0–1)")
    ax.set_ylim(0, 1); ax.grid(axis="y", alpha=.25)
    fig.text(.01, .01, f"Source: {Path(trust_csv).name}; latest available timestamp per UAV.", fontsize=8)
    fig.tight_layout(); path = output_dir / "latest_trust_by_uav.png"; fig.savefig(path, dpi=160); plt.close(fig); paths.append(path)
    return paths


def plot_confusion_matrix(metrics_json: Path, output_path: Path) -> Path:
    metrics = json.loads(Path(metrics_json).read_text(encoding="utf-8"))
    if "confusion_matrix" in metrics:
        matrix = metrics["confusion_matrix"]
        values = [[matrix["actual_negative"]["predicted_negative"], matrix["actual_negative"]["predicted_positive"]],
                  [matrix["actual_positive"]["predicted_negative"], matrix["actual_positive"]["predicted_positive"]]]
    else:
        values = metrics["confusion_matrix_labels_0_1"]
    fig, ax = plt.subplots(figsize=(5.5, 4.5))
    image = ax.imshow(values, cmap="Blues")
    ax.set_xticks([0, 1], ["Predicted benign", "Predicted malicious"])
    ax.set_yticks([0, 1], ["Actual benign", "Actual malicious"])
    for y, row in enumerate(values):
        for x, value in enumerate(row):
            ax.text(x, y, str(value), ha="center", va="center", color="black")
    ax.set_title("Benign / malicious confusion matrix")
    fig.colorbar(image, ax=ax, label="Node count")
    fig.text(.01, .01, f"Source: {Path(metrics_json).name}; held-out label evaluation.", fontsize=8)
    fig.tight_layout(); output_path = Path(output_path); output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=160); plt.close(fig)
    return output_path


def plot_model_feature_importance(importance_csv: Path, output_path: Path) -> Path:
    rows = _read_csv(importance_csv)
    value_column = next((name for name in rows[0] if name.endswith("importance")), None)
    if value_column is None:
        raise ValueError("Feature importance CSV has no importance column")
    rows.sort(key=lambda row: float(row[value_column]))
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.barh([row["feature"] for row in rows], [float(row[value_column]) for row in rows], color="#2563eb")
    ax.set_title("Random Forest impurity feature importance")
    ax.set_xlabel("Impurity importance (unitless; not SHAP)"); ax.set_ylabel("Input feature")
    fig.text(.01, .01, f"Source: {Path(importance_csv).name}; trained Random Forest model.", fontsize=8)
    fig.tight_layout(); output_path = Path(output_path); output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=160); plt.close(fig)
    return output_path


def plot_local_shap(explanation_csv: Path, output_path: Path) -> Path:
    rows = _read_csv(explanation_csv)
    rows.sort(key=lambda row: float(row["shap_value_for_malicious_class"]))
    fig, ax = plt.subplots(figsize=(8, 5))
    values = [float(row["shap_value_for_malicious_class"]) for row in rows]
    ax.barh([row["feature"] for row in rows], values,
            color=["#b42318" if value < 0 else "#0f766e" for value in values])
    ax.axvline(0, color="#334155", linewidth=.8)
    ax.set_title("Local SHAP contributions for the malicious class")
    ax.set_xlabel("Signed SHAP value (model output scale)"); ax.set_ylabel("Input feature")
    fig.text(.01, .01, f"Source: {Path(explanation_csv).name}; actual model explanation.", fontsize=8)
    fig.tight_layout(); output_path = Path(output_path); output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=160); plt.close(fig)
    return output_path


def plot_shap_importance(importance_csv: Path, output_path: Path) -> Path:
    rows = _read_csv(importance_csv)
    rows.sort(key=lambda row: float(row["mean_absolute_shap_value"]))
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.barh([row["feature"] for row in rows], [float(row["mean_absolute_shap_value"]) for row in rows], color="#0f766e")
    ax.set_title("Global SHAP importance on held-out snapshots")
    ax.set_xlabel("Mean absolute SHAP value for malicious class (model output scale)")
    ax.set_ylabel("Observed model feature")
    fig.text(.01, .01, f"Source: {Path(importance_csv).name}; actual trained Random Forest model.", fontsize=8)
    fig.tight_layout(); output_path = Path(output_path); output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=160); plt.close(fig)
    return output_path


def _read_csv(path: Path) -> list[dict[str, str]]:
    with Path(path).open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            raise ValueError(f"CSV header is missing: {path}")
        rows = list(reader)
    if not rows:
        raise ValueError(f"CSV contains no data: {path}")
    return rows


__all__ = ["plot_confusion_matrix", "plot_local_shap", "plot_model_feature_importance", "plot_shap_importance", "plot_trust_history"]
