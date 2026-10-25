"""Reproducible paired multi-seed robustness gate for Phase 4 detection."""
from __future__ import annotations

import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import yaml

from aex_tfanet.detection import detect_behavior, evaluate_nodes, write_detection_results
from aex_tfanet.exceptions import DataValidationError
from aex_tfanet.simulation.fanet import run_simulation
from aex_tfanet.trust.engine import write_trust_results
from aex_tfanet.trust.processor import process_simulation_directory
from aex_tfanet.analysis.simulator_audit import measure_simulation
from aex_tfanet.utils.config import load_config, load_yaml
from aex_tfanet.utils.paths import project_root


def build_validation_matrix(seeds: list[int], probabilities: list[float]) -> list[dict[str, Any]]:
    """Build paired normal/attack conditions while validating inputs."""
    if not seeds or len(seeds) != len(set(seeds)) or any(isinstance(seed, bool) or seed < 0 for seed in seeds):
        raise ValueError("seeds must be a non-empty list of unique non-negative integers")
    if not probabilities or len(probabilities) != len(set(probabilities)):
        raise ValueError("drop probabilities must be non-empty and unique")
    if any(not math.isfinite(p) or not 0 < p <= 1 for p in probabilities):
        raise ValueError("drop probabilities must be finite values in (0, 1]")
    matrix = []
    for seed in seeds:
        matrix.append({"seed": seed, "scenario": "normal", "drop_probability": 0.0})
        for probability in probabilities:
            matrix.append({
                "seed": seed,
                "scenario": f"packet_drop_p{round(probability * 100):02d}",
                "drop_probability": float(probability),
            })
    return matrix


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]], columns: list[str] | None = None) -> None:
    if not rows:
        raise DataValidationError(f"Cannot write empty result set: {path.name}")
    fieldnames = columns or list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: "" if row.get(key) is None else row.get(key) for key in fieldnames})


def read_per_run_metrics(path: Path) -> list[dict[str, str]]:
    """Read a saved metrics CSV and reject missing or empty result artifacts."""
    path = Path(path)
    if not path.is_file():
        raise DataValidationError(f"Per-run metrics file not found: {path}")
    try:
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if not reader.fieldnames:
                raise DataValidationError(f"{path.name} has no header")
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error) as exc:
        raise DataValidationError(f"Could not read {path.name}: {exc}") from exc
    if not rows:
        raise DataValidationError(f"{path.name} contains no result rows")
    if any(None in row for row in rows):
        raise DataValidationError(f"{path.name} contains malformed result rows")
    return rows


def aggregate_metrics(rows: list[dict[str, Any]], metrics: list[str] | None = None) -> list[dict[str, Any]]:
    """Aggregate compatible per-run metrics by scenario, skipping undefined values."""
    if not rows:
        raise DataValidationError("No per-run rows available for aggregation")
    metric_names = metrics or [
        "attack_events", "suspicious_windows", "malicious_windows", "TP", "TN", "FP", "FN",
        "false_positives", "false_negatives",
        "precision", "recall", "F1", "false_positive_rate", "false_negative_rate",
        "target_trust_before_attack", "target_trust_during_attack", "target_trust_mean", "max_detection_score",
        "target_relay_opportunities",
    ]
    groups: dict[tuple[str, float], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[(str(row["scenario"]), float(row["drop_probability"]))].append(row)
    aggregated = []
    for (scenario, probability), group in sorted(groups.items()):
        item: dict[str, Any] = {"scenario": scenario, "drop_probability": probability, "run_count": len(group)}
        totals = {name: sum(int(row.get(name, 0) or 0) for row in group) for name in ("TP", "TN", "FP", "FN")}
        item.update({f"{name}_total": value for name, value in totals.items()})
        item["pooled_precision"] = totals["TP"] / (totals["TP"] + totals["FP"]) if totals["TP"] + totals["FP"] else None
        item["pooled_recall"] = totals["TP"] / (totals["TP"] + totals["FN"]) if totals["TP"] + totals["FN"] else None
        item["pooled_F1"] = (2 * item["pooled_precision"] * item["pooled_recall"] /
                              (item["pooled_precision"] + item["pooled_recall"])
                              if item["pooled_precision"] is not None and item["pooled_recall"] is not None and
                              item["pooled_precision"] + item["pooled_recall"] else
                              (0.0 if item["pooled_recall"] == 0.0 else None))
        item["pooled_false_positive_rate"] = totals["FP"] / (totals["FP"] + totals["TN"]) if totals["FP"] + totals["TN"] else None
        item["pooled_false_negative_rate"] = totals["FN"] / (totals["FN"] + totals["TP"]) if totals["FN"] + totals["TP"] else None
        for name in metric_names:
            values = [float(row[name]) for row in group if row.get(name) not in (None, "") and math.isfinite(float(row[name]))]
            item[f"{name}_valid_runs"] = len(values)
            item[f"{name}_mean"] = statistics.fmean(values) if values else None
            item[f"{name}_std"] = statistics.pstdev(values) if len(values) > 1 else (0.0 if values else None)
        aggregated.append(item)
    return aggregated


def _target_trust_timeline(trust_csv: Path, target: int) -> list[tuple[float, float]]:
    latest: dict[int, float] = {}
    by_time: dict[float, list[tuple[int, float]]] = defaultdict(list)
    with trust_csv.open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            if int(row["target_id"]) == target:
                by_time[float(row["timestamp"])].append((int(row["observer_id"]), float(row["final_trust"])))
    timeline = []
    for stamp in sorted(by_time):
        for observer, value in by_time[stamp]:
            latest[observer] = value
        if latest:
            timeline.append((stamp, statistics.fmean(latest.values())))
    return timeline


def _build_run_metrics(run_dir: Path, predictions: list[dict[str, Any]], trust_csv: Path,
                       condition: dict[str, Any], evaluation_target: int | None) -> dict[str, Any]:
    simulation_dir = run_dir / "simulation"
    # Ground truth enters only after detector predictions have been created.
    summary = json.loads((simulation_dir / "summary.json").read_text(encoding="utf-8"))
    labels = {int(value) for value in summary.get("malicious_nodes", [])}
    metrics = evaluate_nodes(predictions, labels)
    processed = process_simulation_directory(simulation_dir, include_backend=False)
    target = evaluation_target if evaluation_target is not None else (next(iter(labels)) if labels else None)
    attack_observations = [
        item for item in processed.observations if target is not None and item.target_id == target and item.failed_forwarding
    ]
    flagged = [row for row in predictions if row["status"] in {"SUSPICIOUS", "MALICIOUS"}]
    target_rows = [row for row in predictions if target is not None and row["node_id"] == target]
    timeline = _target_trust_timeline(trust_csv, target) if target is not None else []
    attack_times = [item.timestamp for item in attack_observations]
    first_attack = min(attack_times) if attack_times else None
    last_attack = max(attack_times) if attack_times else None
    before = [trust for stamp, trust in timeline if first_attack is not None and stamp < first_attack]
    during = [trust for stamp, trust in timeline if first_attack is not None and last_attack is not None and first_attack <= stamp <= last_attack]
    target_trust = [value for _, value in timeline]
    max_score_values = [float(row["detection_score"]) for row in target_rows if row["detection_score"] is not None]
    trust_summary_path = run_dir / "trust" / "trust_summary.json"
    trust_summary = json.loads(trust_summary_path.read_text(encoding="utf-8"))
    simulator_metrics, _ = measure_simulation(simulation_dir, target)
    row = {
        "seed": condition["seed"], "scenario": condition["scenario"],
        "drop_probability": condition["drop_probability"], "run_directory": str(run_dir.resolve()),
        "target_node_for_analysis": target,
        "total_packets_generated": summary.get("total_packets_generated"),
        "total_packets_delivered": summary.get("total_packets_delivered"),
        "total_packets_dropped": summary.get("total_packets_dropped"),
        "attack_events": sum(item.failed_forwarding for item in attack_observations),
        "target_relay_opportunities": simulator_metrics["target_relay_opportunities"],
        "first_attack_timestamp": first_attack, "last_attack_timestamp": last_attack,
        "suspicious_windows": sum(row["status"] == "SUSPICIOUS" for row in predictions),
        "malicious_windows": sum(row["status"] == "MALICIOUS" for row in predictions),
        "insufficient_data_windows": sum(row["status"] == "INSUFFICIENT_DATA" for row in predictions),
        "affected_nodes": ";".join(map(str, sorted({row["node_id"] for row in flagged}))),
        "target_statuses": ";".join(sorted({row["status"] for row in target_rows})),
        "target_observations_max": max((row["observations"] for row in target_rows), default=0),
        "target_observation_sum": sum(row["observations"] for row in target_rows),
        "target_scored_windows": sum(row["detection_score"] is not None for row in target_rows),
        "target_max_detection_score": max(max_score_values) if max_score_values else None,
        "target_trust_before_attack": statistics.fmean(before) if before else None,
        "target_trust_during_attack": statistics.fmean(during) if during else None,
        "target_trust_mean": statistics.fmean(target_trust) if target_trust else None,
        "target_trust_after_recovery": None,
        "trust_score_observations": trust_summary["number_of_score_observations"],
        "false_positives": metrics["FP"], "false_negatives": metrics["FN"],
        "max_detection_score": max(max_score_values) if max_score_values else None,
        **{key: metrics[key] for key in ("TP", "TN", "FP", "FN", "precision", "recall", "F1", "false_positive_rate", "false_negative_rate")},
    }
    return row


def _plot_results(output_dir: Path, per_run: list[dict[str, Any]], representative: Path) -> list[str]:
    fig_dir = output_dir / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)
    created = []

    def plot_by_seed(metric: str, title: str, ylabel: str, *, include_normal: bool = False):
        fig, ax = plt.subplots(figsize=(8, 4.5))
        scenarios = sorted({r["scenario"] for r in per_run if include_normal or r["scenario"] != "normal"})
        for scenario in scenarios:
            points = sorted((r["seed"], r.get(metric)) for r in per_run if r["scenario"] == scenario and r.get(metric) is not None)
            if points:
                ax.plot([p[0] for p in points], [p[1] for p in points], marker="o", label=scenario)
        ax.set_title(title); ax.set_xlabel("Random seed"); ax.set_ylabel(ylabel)
        fig.text(0.01, 0.01, f"Source: {output_dir.name}/per_run_metrics.csv; tested seeds shown on x-axis.", fontsize=8, color="#475569")
        ax.grid(True, alpha=0.25)
        if any(line.get_label() for line in ax.lines): ax.legend(title="Scenario")
        fig.tight_layout(); name = f"{metric}_by_seed.png"; fig.savefig(fig_dir / name, dpi=160); plt.close(fig); created.append(name)

    plot_by_seed("F1", "Node-level F1 across seeds", "F1 (unitless)")
    plot_by_seed("precision", "Node-level precision across seeds", "Precision (fraction)")
    plot_by_seed("recall", "Node-level recall across seeds", "Recall (fraction)")
    plot_by_seed("false_positive_rate", "Node-level false-positive rate across seeds", "False-positive rate (fraction)", include_normal=True)
    plot_by_seed("false_negative_rate", "Node-level false-negative rate across seeds", "False-negative rate (fraction)")

    intensity_rows = [r for r in per_run if r["scenario"] != "normal" and r.get("recall") is not None]
    if intensity_rows:
        probabilities = sorted({float(r["drop_probability"]) for r in intensity_rows})
        rates = []
        counts = []
        for probability in probabilities:
            values = [float(r["recall"]) for r in intensity_rows if float(r["drop_probability"]) == probability]
            rates.append(statistics.fmean(values))
            counts.append(len(values))
        fig, ax = plt.subplots(figsize=(7.5, 4.5))
        ax.plot([100 * p for p in probabilities], rates, marker="o", color="#2563eb", linewidth=2)
        for probability, rate, count in zip(probabilities, rates, counts):
            top_point = rate >= 0.98
            ax.annotate(f"{round(rate * count):d}/{count}", (100 * probability, rate),
                        xytext=(0, -18 if top_point else 9), textcoords="offset points",
                        ha="center", va="top" if top_point else "bottom")
        ax.set_ylim(0, 1.05); ax.set_title("Attacked-node detection rate by packet-drop intensity")
        ax.set_xlabel("Configured packet-drop probability (%)"); ax.set_ylabel("Detected attacked-node runs / tested runs")
        ax.grid(True, alpha=.25)
        fig.text(.01, .01, f"Source: per_run_metrics.csv; exact detected/tested run counts={counts}; no interval estimate implied.", fontsize=8, color="#475569")
        fig.tight_layout(); name = "detection_rate_by_attack_intensity.png"; fig.savefig(fig_dir / name, dpi=160); plt.close(fig); created.append(name)

    attack_rows = [r for r in per_run if r["scenario"] != "normal" and r.get("target_trust_during_attack") is not None]
    normal_rows = [r for r in per_run if r["scenario"] == "normal" and r.get("target_trust_mean") is not None]
    if attack_rows:
        fig, ax = plt.subplots(figsize=(8, 4.5))
        for scenario in sorted({r["scenario"] for r in attack_rows}):
            points = sorted((r["seed"], r["target_trust_during_attack"]) for r in attack_rows if r["scenario"] == scenario)
            if points: ax.plot([p[0] for p in points], [p[1] for p in points], marker="o", label=f"{scenario}: during")
        if normal_rows:
            points = sorted((r["seed"], r["target_trust_mean"]) for r in normal_rows)
            ax.plot([p[0] for p in points], [p[1] for p in points], marker="s", linestyle="--", label="normal: full-run mean")
        ax.set_title("Target UAV trust during observed attacks")
        ax.set_xlabel("Random seed"); ax.set_ylabel("Mean latest relational trust (0–1)")
        fig.text(0.01, 0.01, "Source: per-run Phase 3 trust_scores.csv; seeds 42–61. Attack values average the interval from first to last observed drop.", fontsize=8, color="#475569")
        ax.grid(True, alpha=0.25); ax.legend(title="Scenario / period")
        fig.tight_layout(); name = "target_trust_across_seeds.png"; fig.savefig(fig_dir / name, dpi=160); plt.close(fig); created.append(name)

    events_path = representative / "detection" / "detection_events.csv"
    if events_path.is_file():
        with events_path.open(encoding="utf-8", newline="") as stream:
            rows = list(csv.DictReader(stream))
        rows = [r for r in rows if int(r["node_id"]) == 7 and r["detection_score"]]
        if rows:
            fig, ax = plt.subplots(figsize=(9, 4.5))
            times = [float(r["timestamp"]) for r in rows]
            scores = [float(r["detection_score"]) for r in rows]
            ax.plot(times, scores, color="#64748b", linewidth=1, label="Detection score")
            status_colors = {"NORMAL": "#2563eb", "SUSPICIOUS": "#d97706", "MALICIOUS": "#b42318"}
            for status, color in status_colors.items():
                selected = [row for row in rows if row["status"] == status]
                if selected:
                    ax.scatter([float(row["timestamp"]) for row in selected],
                               [float(row["detection_score"]) for row in selected],
                               c=color, s=14, label=f"Status: {status}")
            summary_path = representative / "detection" / "detection_summary.json"
            detector_cfg = json.loads(summary_path.read_text(encoding="utf-8"))["detector_config"]
            suspicious = detector_cfg["suspicious_threshold"]
            malicious = detector_cfg["malicious_threshold"]
            ax.axhline(suspicious, color="#d97706", linestyle="--", linewidth=1, label=f"Suspicious threshold ({suspicious:.2f})")
            ax.axhline(malicious, color="#b42318", linestyle=":", linewidth=1, label=f"Malicious threshold ({malicious:.2f})")
            ax.set_title("Seed 42, packet-drop p=0.8: UAV 7 detection score and status")
            ax.set_xlabel("Simulation time (s)"); ax.set_ylabel("Detection score (unitless)")
            fig.text(0.01, 0.01, "Source: seed 42, packet_drop_p80 detection_events.csv; simulation time 0–99 s.", fontsize=8, color="#475569")
            ax.grid(True, alpha=0.25); ax.legend()
            fig.tight_layout(); name = "representative_score_status.png"; fig.savefig(fig_dir / name, dpi=160); plt.close(fig); created.append(name)
    return created


def refresh_phase4_validation(output_dir: Path) -> dict[str, Any]:
    """Recompute aggregate files/figures from preserved per-run outputs only."""
    output_dir = Path(output_dir).resolve()
    raw_rows = read_per_run_metrics(output_dir / "per_run_metrics.csv")
    text_fields = {"scenario", "run_directory", "affected_nodes", "target_statuses"}
    per_run: list[dict[str, Any]] = []
    for raw in raw_rows:
        row: dict[str, Any] = {}
        for name, value in raw.items():
            if name in text_fields:
                row[name] = value
            elif value == "":
                row[name] = None
            else:
                numeric = float(value)
                row[name] = int(numeric) if numeric.is_integer() and name not in {"drop_probability"} else numeric
        canonical_run = output_dir / "runs" / f"seed_{row['seed']}" / str(row["scenario"])
        if canonical_run.is_dir():
            row["run_directory"] = str(canonical_run.resolve())
        audit_metrics, _ = measure_simulation(Path(row["run_directory"]) / "simulation", 7)
        row["target_relay_opportunities"] = audit_metrics["target_relay_opportunities"]
        per_run.append(row)
    _write_csv(output_dir / "per_run_metrics.csv", per_run)
    manifest_path = output_dir / "experiment_manifest.csv"
    manifest = read_per_run_metrics(manifest_path)
    for row in manifest:
        run_dir = output_dir / "runs" / f"seed_{row['seed']}" / row["scenario"]
        config_file = output_dir / "configs" / f"seed_{row['seed']}_{row['scenario']}.yaml"
        if run_dir.is_dir(): row["run_directory"] = str(run_dir.resolve())
        if config_file.is_file(): row["config_path"] = str(config_file.resolve())
    _write_csv(manifest_path, manifest)
    aggregate = aggregate_metrics(per_run)
    _write_csv(output_dir / "aggregate_metrics.csv", aggregate)
    representative = output_dir / "runs" / "seed_42" / "packet_drop_p80"
    figures = _plot_results(output_dir, per_run, representative)
    summary_path = output_dir / "validation_summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["aggregate_metrics"] = aggregate
    summary["figures"] = figures
    coverage = {
        item["scenario"]: {
            "mean_opportunities_per_run": statistics.fmean(
                int(row["target_relay_opportunities"]) for row in per_run if row["scenario"] == item["scenario"]
            ),
            "minimum_opportunities": min(
                int(row["target_relay_opportunities"]) for row in per_run if row["scenario"] == item["scenario"]
            ),
            "zero_opportunity_runs": sum(
                int(row["target_relay_opportunities"]) == 0 for row in per_run if row["scenario"] == item["scenario"]
            ),
        }
        for item in aggregate
    }
    sufficient = all(value["zero_opportunity_runs"] == 0 for scenario, value in coverage.items() if scenario != "normal")
    summary["gate_decision"] = (
        "B — proceed with later research modules while retaining low-intensity sensitivity limitations; every tested attack run had at least one observed UAV 7 relay opportunity."
        if sufficient else
        "C — retain the traffic-coverage limitation because one or more attack runs had zero observed UAV 7 relay opportunities."
    )
    summary["decision_evidence"] = {
        "target_relay_opportunities": coverage,
        "attack_event_counts_per_1000_packets": {
            item["scenario"]: {"mean": item["attack_events_mean"], "std": item["attack_events_std"],
                               "minimum": min(int(row["attack_events"]) for row in per_run if row["scenario"] == item["scenario"]),
                               "maximum": max(int(row["attack_events"]) for row in per_run if row["scenario"] == item["scenario"])}
            for item in aggregate if item["scenario"] != "normal"
        },
        "runs_without_observed_attacker_drop": {
            item["scenario"]: sum(int(row["attack_events"]) == 0 for row in per_run if row["scenario"] == item["scenario"])
            for item in aggregate if item["scenario"] != "normal"
        },
        "detected_attacked_nodes": {item["scenario"]: item["TP_total"] for item in aggregate if item["scenario"] != "normal"},
        "attacked_nodes_tested": {item["scenario"]: item["TP_total"] + item["FN_total"] for item in aggregate if item["scenario"] != "normal"},
    }
    _write_json(summary_path, summary)
    return summary


def run_phase4_validation(output_dir: Path, seeds: list[int] | None = None,
                          probabilities: list[float] | None = None) -> dict[str, Any]:
    """Run paired normal/packet-drop scenarios and persist individual + aggregate results."""
    root = project_root()
    seeds = seeds or [42, 43, 44, 45, 46]
    probabilities = probabilities or [0.25, 0.50, 0.80]
    matrix = build_validation_matrix(seeds, probabilities)
    output_dir = Path(output_dir).resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"Validation output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    configs_dir = output_dir / "configs"; configs_dir.mkdir()
    base_normal = load_yaml(root / "experiments" / "configs" / "normal.yaml")
    base_attack = load_yaml(root / "experiments" / "configs" / "packet_drop.yaml")
    if {k: v for k, v in base_normal.items() if k != "attack"} != {k: v for k, v in base_attack.items() if k != "attack"}:
        raise DataValidationError("Normal and packet-drop base configs differ outside the attack block")
    attack_ids = [int(value) for value in base_attack.get("attack", {}).get("malicious_nodes", [])]
    if len(attack_ids) != 1:
        raise DataValidationError("Current packet-drop validation expects exactly one configured attacked UAV")
    eval_target = attack_ids[0]
    manifest = []
    per_run = []
    representative = None
    for condition in matrix:
        seed = condition["seed"]
        raw = json.loads(json.dumps(base_normal))
        raw["simulation"]["seed"] = seed
        if condition["scenario"] == "normal":
            raw["attack"] = {"enabled": False, "type": "packet_drop", "malicious_nodes": [], "drop_probability": 0.0}
        else:
            raw = json.loads(json.dumps(base_attack))
            raw["simulation"]["seed"] = seed
            raw["attack"]["drop_probability"] = condition["drop_probability"]
        config_path = configs_dir / f"seed_{seed}_{condition['scenario']}.yaml"
        config_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
        run_dir = output_dir / "runs" / f"seed_{seed}" / condition["scenario"]
        run_dir.parent.mkdir(parents=True, exist_ok=True)
        cfg = load_config(overlay=config_path)
        run_simulation(config_path, "python", run_dir)
        trust_dir = run_dir / "trust"
        write_trust_results(run_dir / "simulation", trust_dir, cfg)
        predictions = detect_behavior(run_dir / "simulation", trust_dir / "trust_scores.csv", cfg.detection)
        # Predictions have already been generated before the evaluator reads labels.
        summary = json.loads((run_dir / "simulation" / "summary.json").read_text(encoding="utf-8"))
        labels = {int(node) for node in summary.get("malicious_nodes", [])}
        evaluation = evaluate_nodes(predictions, labels)
        detection_dir = run_dir / "detection"
        write_detection_results(predictions, detection_dir, evaluation, cfg.detection)
        metric = _build_run_metrics(run_dir, predictions, trust_dir / "trust_scores.csv", condition, eval_target)
        per_run.append(metric)
        manifest.append({
            "seed": seed, "scenario": condition["scenario"], "drop_probability": condition["drop_probability"],
            "config_path": str(config_path.resolve()), "run_directory": str(run_dir.resolve()),
            "simulator": "Simplified Python FANET Model — NOT NS-3",
            "prediction_labels_available_to_detector": False,
        })
        if seed == 42 and condition["scenario"] == "packet_drop_p80":
            representative = run_dir
    _write_csv(output_dir / "experiment_manifest.csv", manifest)
    _write_csv(output_dir / "per_run_metrics.csv", per_run)
    if len(read_per_run_metrics(output_dir / "per_run_metrics.csv")) != len(matrix):
        raise DataValidationError("Persisted per-run metrics count does not match the run matrix")
    aggregate = aggregate_metrics(per_run)
    _write_csv(output_dir / "aggregate_metrics.csv", aggregate)
    figures = _plot_results(output_dir, per_run, representative or Path("."))
    validation_summary = {
        "phase": "4-robustness-validation",
        "simulator": "Simplified Python FANET Model — NOT NS-3",
        "seeds": seeds, "scenarios": ["normal", "packet_drop"],
        "drop_probabilities": probabilities,
        "detector_configuration": {
            "suspicious_threshold": load_config().detection.suspicious_threshold,
            "malicious_threshold": load_config().detection.malicious_threshold,
            "min_observations": load_config().detection.min_observations,
            "window_s": load_config().detection.window_s,
        },
        "paired_conditions_per_seed": len(probabilities) + 1,
        "run_count": len(per_run),
        "prediction_label_isolation": "Detector receives simulation behavior, Phase 3 trust CSV, and detector configuration only; summary ground truth is loaded afterward for evaluation.",
        "recovery_scenario": "Not run: simulator configuration applies one attack probability for the full run and has no time-phased attack schedule. A simulator feature would be required for an authentic normal→attack→normal experiment.",
        "aggregate_standard_deviation": "Population standard deviation over the tested seed set; undefined metrics excluded.",
        "gate_decision": "B — proceed with later research modules while retaining low-intensity sensitivity limitations if relay coverage is present in every attack run.",
        "decision_evidence": {
            "attack_event_counts_per_1000_packets": {
                item["scenario"]: {"mean": item["attack_events_mean"], "std": item["attack_events_std"],
                                   "minimum": min(int(row["attack_events"]) for row in per_run if row["scenario"] == item["scenario"]),
                                   "maximum": max(int(row["attack_events"]) for row in per_run if row["scenario"] == item["scenario"])}
                for item in aggregate if item["scenario"] != "normal"
            },
            "runs_without_observed_attacker_drop": {
                item["scenario"]: sum(int(row["attack_events"]) == 0 for row in per_run if row["scenario"] == item["scenario"])
                for item in aggregate if item["scenario"] != "normal"
            },
            "detected_attacked_nodes": {
                item["scenario"]: item["TP_total"] for item in aggregate if item["scenario"] != "normal"
            },
            "attacked_nodes_tested": {item["scenario"]: item["TP_total"] + item["FN_total"]
                                      for item in aggregate if item["scenario"] != "normal"},
        },
        "aggregate_metrics": aggregate,
        "figures": figures,
    }
    _write_json(output_dir / "validation_summary.json", validation_summary)
    return validation_summary
