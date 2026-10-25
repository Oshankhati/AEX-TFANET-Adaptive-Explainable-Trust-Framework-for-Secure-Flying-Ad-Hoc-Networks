"""Command-line interface for AEX-TFANET."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aex_tfanet import __phase__, __version__
from aex_tfanet.analysis.phase4_validation import refresh_phase4_validation, run_phase4_validation
from aex_tfanet.analysis.simulator_audit import audit_validation
from aex_tfanet.routing.experiment import run_routing_comparison
from aex_tfanet.ml import run_ml
from aex_tfanet.xai import run_explanations
from aex_tfanet.analysis import evaluate_experiment
from aex_tfanet.dashboard import launch_dashboard
from aex_tfanet.exceptions import AexTfanetError
from aex_tfanet.detection import detect_behavior, evaluate_nodes, write_detection_results
from aex_tfanet.pipeline.runner import run_experiment_scaffold
from aex_tfanet.pipeline.full import run_full_experiment
from aex_tfanet.simulation.fanet import run_simulation
from aex_tfanet.trust.engine import write_trust_results
from aex_tfanet.utils.config import load_config
from aex_tfanet.utils.environment import format_report, probe_environment
from aex_tfanet.utils.logging import setup_logging

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aex-tfanet",
        description="AEX-TFANET — Adaptive Explainable Trust Framework for Secure FANETs",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("env", help="Probe Python, compiler, NS-3, and package availability")

    exp = sub.add_parser("experiment", help="Run the complete single-run simulation-to-analysis pipeline")
    exp.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Experiment YAML overlay (merged onto config.yaml)",
    )
    exp.add_argument("--output", type=Path, default=None, help="New experiment output directory")
    exp.add_argument("--ml-model", type=Path, default=None, help="Optional trained model file for ML inference and XAI")
    exp.add_argument("--scaffold", action="store_true", help="Create only the legacy Phase 1 experiment scaffold")

    dashboard = sub.add_parser("dashboard", help="Launch the optional Streamlit research dashboard")
    dashboard.add_argument("--results", type=Path, default=None, help="Results root directory")
    simulate = sub.add_parser("simulate", help="Run FANET simulation (Phase 2)")
    simulate.add_argument("--config", type=Path, default=None, help="Experiment YAML overlay")
    simulate.add_argument("--backend", choices=("python", "ns3", "auto"), default="auto")
    trust = sub.add_parser("trust", help="Process simulation events and calculate adaptive trust (Phase 3)")
    trust.add_argument("--input", type=Path, required=True, help="Simulation directory containing Phase 2 CSVs")
    trust.add_argument("--config", type=Path, default=None, help="Full project YAML configuration")
    trust.add_argument("--output", type=Path, default=None, help="Trust output directory (default: sibling trust/)")
    process = sub.add_parser("process", help="Process simulation events into relational trust records")
    process.add_argument("--input", type=Path, required=True, help="Simulation directory containing Phase 2 CSVs")
    process.add_argument("--config", type=Path, default=None)
    process.add_argument("--output", type=Path, default=None)
    detect = sub.add_parser("detect", help="Run deterministic behavioral detection (Phase 4)")
    detect.add_argument("--input", type=Path, required=True, help="Experiment directory or simulation directory")
    detect.add_argument("--trust-input", type=Path, default=None, help="Phase 3 trust_scores.csv or trust output directory")
    detect.add_argument("--config", type=Path, default=None, help="Full project YAML configuration")
    detect.add_argument("--output", type=Path, default=None, help="Detection output directory (default: sibling detection/)")
    validate = sub.add_parser("validate-detection", help="Run paired multi-seed Phase 4 robustness validation")
    validate.add_argument("--output", type=Path, default=None, help="Validation folder (default: results/phase4_validation)")
    validate.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44, 45, 46])
    validate.add_argument("--drop-probabilities", type=float, nargs="+", default=[0.25, 0.50, 0.80])
    validate.add_argument("--refresh-existing", action="store_true", help="Rebuild aggregate files and figures from existing per-run metrics")
    audit = sub.add_parser("audit-simulator", help="Measure packet, relay, route, and per-UAV coverage from saved simulation traces")
    audit.add_argument("--input", type=Path, default=Path("results/phase4_validation_200m"), help="Validation output containing experiment_manifest.csv")
    audit.add_argument("--output", type=Path, default=Path("results/simulator_validity_after_200m"), help="New or existing audit output directory")
    audit.add_argument("--target-node", type=int, default=7, help="Transit relay to quantify")
    route = sub.add_parser("route", help="Run paired baseline versus trust-aware routing experiments")
    route.add_argument("--output", type=Path, default=None, help="New output directory (default: timestamped under results/)")
    route.add_argument("--seeds", type=int, nargs="+", default=list(range(42, 62)))
    route.add_argument("--drop-probability", type=float, default=0.8)
    ml = sub.add_parser("ml", help="Train and evaluate seed-grouped behavioral ML on saved Phase 4 traces")
    ml.add_argument("--input", type=Path, default=Path("results/phase4_validation_200m"))
    ml.add_argument("--output", type=Path, default=Path("results/ml_phase4_200m"))
    explain = sub.add_parser("explain", help="Explain the saved ML model with SHAP when available")
    explain.add_argument("--input", type=Path, default=Path("results/ml_phase4_200m"))
    explain.add_argument("--output", type=Path, default=Path("results/xai_phase4_200m"))
    evaluate = sub.add_parser("evaluate", help="Calculate performance metrics from a saved experiment")
    evaluate.add_argument("--input", type=Path, required=True, help="Experiment folder or simulation folder")
    evaluate.add_argument("--output", type=Path, default=None, help="Metrics output directory")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "env":
            setup_logging("INFO")
            cfg = load_config()
            report = probe_environment(cfg.simulation.ns3.install_path)
            print(format_report(report))
            return 0
        if args.command == "experiment":
            if args.scaffold:
                out = run_experiment_scaffold(args.config)
                print(f"Experiment scaffold written to: {out}")
            else:
                out = run_full_experiment(args.config, args.output, args.ml_model)
                print(f"Complete experiment artifacts: {out}")
            return 0
        if args.command == "simulate":
            out = run_simulation(args.config, args.backend)
            print(f"Simulation results: {out}")
            print(f"CSV and summary files: {out / 'simulation'}")
            return 0
        if args.command in {"trust", "process"}:
            cfg = (load_config(path=args.config) if args.config and args.config.name == "config.yaml"
                   else load_config(overlay=args.config) if args.config else load_config())
            input_dir = args.input.resolve()
            output_dir = args.output or (input_dir.parent / "trust")
            if output_dir.exists() and args.output is None:
                from datetime import datetime, timezone
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
                output_dir = input_dir.parent / f"trust_{stamp}"
            summary = write_trust_results(input_dir, output_dir, cfg)
            print(f"Trust scores: {output_dir / 'trust_scores.csv'}")
            print(f"Trust summary: {output_dir / 'trust_summary.json'}")
            print(f"Calculated {summary['number_of_score_observations']} relational trust observations.")
            return 0
        if args.command == "detect":
            cfg = (load_config(path=args.config) if args.config and args.config.name == "config.yaml"
                   else load_config(overlay=args.config) if args.config else load_config())
            input_path = args.input.resolve()
            simulation_dir = input_path / "simulation" if (input_path / "simulation").is_dir() else input_path
            experiment_dir = simulation_dir.parent
            trust_path = args.trust_input or (experiment_dir / "trust")
            trust_csv = trust_path / "trust_scores.csv" if trust_path.is_dir() else trust_path
            predictions = detect_behavior(simulation_dir, trust_csv, cfg.detection)
            evaluation = None
            summary_path = simulation_dir / "summary.json"
            if summary_path.is_file():
                try:
                    metadata = json.loads(summary_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    from aex_tfanet.exceptions import DataValidationError
                    raise DataValidationError(f"Invalid simulation summary.json: {exc}") from exc
                # Ground truth is read only after predictions have been generated.
                if isinstance(metadata, dict) and isinstance(metadata.get("malicious_nodes"), list):
                    labels = {int(node) for node in metadata["malicious_nodes"]}
                    evaluation = evaluate_nodes(predictions, labels)
            output_dir = args.output or (experiment_dir / "detection")
            if output_dir.exists() and args.output is None:
                from datetime import datetime, timezone
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
                output_dir = experiment_dir / f"detection_{stamp}"
            report = write_detection_results(predictions, output_dir, evaluation, cfg.detection)
            print(f"Detection events: {output_dir / 'detection_events.csv'}")
            print(f"Detection summary: {output_dir / 'detection_summary.json'}")
            print(f"Rows: {report['row_count']}; statuses: {report['status_counts']}")
            if evaluation is not None:
                print(f"Evaluation metrics: {output_dir / 'detection_metrics.json'}")
            else:
                print("Evaluation: not evaluated (simulation ground-truth metadata unavailable).")
            return 0
        if args.command == "validate-detection":
            output_dir = args.output or (Path(__file__).resolve().parents[2] / "results" / "phase4_validation")
            summary = (refresh_phase4_validation(output_dir) if args.refresh_existing else
                       run_phase4_validation(output_dir, args.seeds, args.drop_probabilities))
            print(f"Phase 4 validation artifacts: {output_dir.resolve()}")
            print(f"Scenarios: {summary['run_count']} runs; seeds: {summary['seeds']}")
            print(f"Figures: {len(summary['figures'])}")
            return 0
        if args.command == "audit-simulator":
            summary = audit_validation(args.input, args.output, args.target_node)
            print(f"Simulator audit: {args.output.resolve()}")
            print(f"Measured {summary['run_count']} actual runs; per-run and per-UAV CSVs plus JSON summary written.")
            return 0
        if args.command == "route":
            from datetime import datetime, timezone
            out = args.output or (Path(__file__).resolve().parents[2] / "results" / f"routing_comparison_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}")
            summary = run_routing_comparison(out, args.seeds, args.drop_probability)
            print(f"Routing comparison artifacts: {out.resolve()}")
            print(f"Completed {summary['run_count']} runs across seeds {summary['seeds']}.")
            return 0
        if args.command == "ml":
            metrics = run_ml(args.input, args.output)
            print(f"ML artifacts: {args.output.resolve()}")
            print(f"Seed-group test accuracy={metrics['accuracy']:.3f}; malicious F1={metrics['f1_malicious']:.3f}.")
            return 0
        if args.command == "explain":
            result = run_explanations(args.input, args.output)
            print(f"XAI artifacts: {args.output.resolve()}")
            print(f"SHAP: {result['shap_status']}")
            return 0
        if args.command == "evaluate":
            result = evaluate_experiment(args.input, args.output)
            output_dir = args.output or (args.input / "metrics" if (args.input / "simulation").is_dir() else args.input.parent / "metrics")
            print(f"Performance metrics: {output_dir.resolve() / 'metrics.json'}")
            print(f"PDR={result['packet_delivery_ratio']}; throughput={result['throughput_mbps']} Mbps; delay={result['delay_status']}")
            return 0
        if args.command == "dashboard":
            return launch_dashboard(args.results)
        parser.error(f"Unknown command: {args.command}")
    except AexTfanetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0
