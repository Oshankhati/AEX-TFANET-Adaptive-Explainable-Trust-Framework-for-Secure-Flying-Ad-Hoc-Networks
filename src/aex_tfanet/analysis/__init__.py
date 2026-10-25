"""Performance metric calculation from saved experiment output."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from aex_tfanet.exceptions import DataValidationError
from aex_tfanet.utils.config import load_config


def evaluate_experiment(experiment_dir: Path, output_dir: Path | None = None) -> dict[str, Any]:
    """Calculate actual packet, route, trust, detection metrics for one run."""
    experiment_dir = Path(experiment_dir)
    simulation_dir = experiment_dir / "simulation" if (experiment_dir / "simulation").is_dir() else experiment_dir
    summary_path = simulation_dir / "summary.json"
    if not summary_path.is_file():
        raise DataValidationError(f"Simulation summary not found: {summary_path}")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    generated = int(summary["total_packets_generated"])
    delivered = int(summary["total_packets_delivered"])
    dropped = int(summary["total_packets_dropped"])
    duration = float(summary["simulation_duration_s"])
    packet_size = int(summary.get("packet_size_bytes", load_config().simulation.packet_size_bytes))
    delivered_bytes = delivered * packet_size
    routes_path = simulation_dir / "route_decisions.csv"
    routes = []
    if routes_path.is_file():
        with routes_path.open(encoding="utf-8-sig", newline="") as stream:
            routes = list(csv.DictReader(stream))
    routed = [row for row in routes if row.get("selected_path")]
    hops = [int(row["hop_count"]) for row in routed]
    labels = {int(node) for node in summary.get("malicious_nodes", [])}
    exposed = 0
    for row in routed:
        path = [int(node) for node in row["selected_path"].split(">")]
        exposed += int(bool(labels.intersection(path[1:-1])))
    result: dict[str, Any] = {
        "provenance": summary.get("backend", "Unavailable"),
        "packets_generated": generated,
        "packets_delivered": delivered,
        "packets_dropped": dropped,
        "packet_delivery_ratio": delivered / generated if generated else None,
        "packet_loss_ratio": dropped / generated if generated else None,
        "delivered_application_bytes": delivered_bytes,
        "throughput_mbps": delivered_bytes * 8 / duration / 1_000_000 if duration > 0 else None,
        "average_end_to_end_delay_s": None,
        "delay_status": "Not evaluated. The simulator does not model per-hop transmission or queueing delay.",
        "routing_mode": summary.get("routing_mode"),
        "routed_packets": len(routed) if routes_path.is_file() else None,
        "route_unavailable_count": len(routes) - len(routed) if routes_path.is_file() else None,
        "mean_route_hops": sum(hops) / len(hops) if hops else None,
        "route_changes": summary.get("route_changes"),
        "attacked_intermediate_exposure_count": exposed if routes_path.is_file() and labels else (0 if routes_path.is_file() else None),
        "attacked_intermediate_exposure_rate": exposed / len(routed) if routed and labels else (0.0 if routed and not labels else None),
        "routing_overhead": None,
        "routing_overhead_status": "Not evaluated. Control and signaling packet costs are not represented by the simulator.",
        "detection": None,
        "trust": None,
    }
    detection_metrics = experiment_dir / "detection" / "detection_metrics.json"
    if detection_metrics.is_file():
        result["detection"] = json.loads(detection_metrics.read_text(encoding="utf-8"))
    trust_summary = experiment_dir / "trust" / "trust_summary.json"
    if trust_summary.is_file():
        trust = json.loads(trust_summary.read_text(encoding="utf-8"))
        result["trust"] = {
            "number_of_score_observations": trust.get("number_of_score_observations"),
            "overall_final_trust_mean": trust.get("mean_trust"),
        }
    output_dir = Path(output_dir) if output_dir else experiment_dir / "metrics"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "metrics.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return result


__all__ = ["evaluate_experiment"]
