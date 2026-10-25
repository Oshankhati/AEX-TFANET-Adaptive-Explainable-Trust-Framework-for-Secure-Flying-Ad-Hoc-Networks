"""Single-run end-to-end experiment orchestration over the modular components."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from aex_tfanet.analysis import evaluate_experiment
from aex_tfanet.detection import detect_behavior, evaluate_nodes, write_detection_results
from aex_tfanet.ml import predict_simulation
from aex_tfanet.simulation.fanet import run_simulation
from aex_tfanet.trust.engine import write_trust_results
from aex_tfanet.utils.config import load_config, load_yaml
from aex_tfanet.utils.paths import project_root
from aex_tfanet.visualization import plot_confusion_matrix, plot_local_shap, plot_trust_history
from aex_tfanet.xai import explain_run_predictions


def run_full_experiment(config_path: Path | None = None, output_dir: Path | None = None,
                        ml_model: Path | None = None) -> Path:
    """Run simulation → trust → detection → routing → ML/XAI → metrics/figures."""
    root = project_root()
    config_path = Path(config_path) if config_path else None
    cfg = load_config(overlay=config_path) if config_path and config_path.name != "config.yaml" else load_config(config_path)
    if output_dir is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        output_dir = cfg.experiments.output_directory / f"experiment_{stamp}"
    output_dir = Path(output_dir).resolve()
    raw_config = load_yaml(config_path) if config_path else load_yaml(root / "config.yaml")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"Experiment output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    saved_config = yaml.safe_dump(raw_config, sort_keys=False, allow_unicode=True)
    (output_dir / "config.yaml").write_text(saved_config, encoding="utf-8")

    run_simulation(config_path, "python", output_dir)
    simulation_dir = output_dir / "simulation"
    trust_dir = output_dir / "trust"
    trust_summary = write_trust_results(simulation_dir, trust_dir, cfg)
    predictions = detect_behavior(simulation_dir, trust_dir / "trust_scores.csv", cfg.detection)
    simulation_summary = json.loads((simulation_dir / "summary.json").read_text(encoding="utf-8"))
    malicious = {int(node) for node in simulation_summary.get("malicious_nodes", [])}
    detection_metrics = evaluate_nodes(predictions, malicious)
    detection_summary = write_detection_results(predictions, output_dir / "detection", detection_metrics, cfg.detection)
    metrics = evaluate_experiment(output_dir, output_dir / "metrics")
    figures_dir = output_dir / "figures"; figures_dir.mkdir()
    generated_figures = [str(path.relative_to(output_dir)) for path in plot_trust_history(trust_dir / "trust_scores.csv", figures_dir)]
    generated_figures.append(str(plot_confusion_matrix(output_dir / "detection" / "detection_metrics.json", figures_dir / "detection_confusion_matrix.png").relative_to(output_dir)))

    model_path = Path(ml_model) if ml_model is not None else None
    if model_path is not None and model_path.is_file():
        ml_result = predict_simulation(model_path, simulation_dir, trust_dir / "trust_scores.csv", output_dir / "ml")
        training_metrics = model_path.parent / "ml_metrics.json"
        if training_metrics.is_file():
            xai_result = explain_run_predictions(model_path, training_metrics, output_dir / "ml/ml_predictions.csv", output_dir / "xai")
            local_shap = output_dir / "xai/run_local_shap.csv"
            if local_shap.is_file():
                generated_figures.append(str(plot_local_shap(local_shap, figures_dir / "run_local_shap.png").relative_to(output_dir)))
        else:
            xai_result = {"shap_status": "Not evaluated. Training feature metadata is missing."}
    else:
        ml_result = {
            "status": "Not evaluated. No trained ML model was provided.",
            "model_path": str(model_path) if model_path is not None else None,
        }
        xai_result = {"shap_status": "Not evaluated. ML model unavailable."}
        (output_dir / "ml").mkdir()
        (output_dir / "ml/ml_status.json").write_text(json.dumps(ml_result, indent=2) + "\n", encoding="utf-8")
        (output_dir / "xai").mkdir()
        (output_dir / "xai/xai_status.json").write_text(json.dumps(xai_result, indent=2) + "\n", encoding="utf-8")
    (output_dir / "figures/figure_manifest.json").write_text(json.dumps({"figures": generated_figures}, indent=2) + "\n", encoding="utf-8")
    manifest: dict[str, Any] = {
        "experiment_id": output_dir.name,
        "simulator": simulation_summary["backend"],
        "random_seed": simulation_summary["random_seed"],
        "routing_mode": simulation_summary.get("routing_mode"),
        "attack_type": simulation_summary.get("attack_type"),
        "attack_probability": simulation_summary.get("drop_probability"),
        "prediction_labels_available_to_detector": False,
        "trust_score_observations": trust_summary.get("number_of_score_observations"),
        "detection": detection_summary,
        "performance_metrics": metrics,
        "ml": ml_result,
        "xai": xai_result,
        "figures": generated_figures,
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    (output_dir / "STATUS.txt").write_text(
        "Complete single-run pipeline finished: simulation, trust, detection, route decisions, ML/XAI status, metrics, and figures.\n",
        encoding="utf-8",
    )
    return output_dir
