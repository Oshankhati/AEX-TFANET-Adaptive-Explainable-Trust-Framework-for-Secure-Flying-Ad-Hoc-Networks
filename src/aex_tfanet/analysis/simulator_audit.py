"""Measure traffic and relay coverage from real simulator event traces.

This analysis is descriptive: it does not generate events or inspect attack
configuration when constructing route and node metrics.
"""
from __future__ import annotations

import csv
import json
import statistics
from collections import Counter, defaultdict
from dataclasses import replace
from pathlib import Path
from typing import Any

from aex_tfanet.exceptions import DataValidationError
from aex_tfanet.simulation.fanet import run_python_simulation
from aex_tfanet.utils.config import load_config


def _read_events(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise DataValidationError(f"Missing simulator event file: {path}")
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        rows = list(reader)
        if not reader.fieldnames or not rows:
            raise DataValidationError(f"Simulator event file is empty or lacks a header: {path}")
    return rows


def measure_simulation(simulation_dir: Path, target_node: int | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return run-level and per-node counts inferred only from packet events."""
    simulation_dir = Path(simulation_dir)
    events = _read_events(simulation_dir / "packet_events.csv")
    summary_path = simulation_dir / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.is_file() else {}
    by_packet: dict[int, list[dict[str, str]]] = defaultdict(list)
    for event in events:
        try:
            by_packet[int(event["packet_id"])].append(event)
        except (KeyError, ValueError) as exc:
            raise DataValidationError(f"Malformed packet event in {simulation_dir}: {exc}") from exc

    nodes: dict[int, Counter[str]] = defaultdict(Counter)
    route_signatures: set[tuple[int, ...]] = set()
    traversals: Counter[int] = Counter()
    multihop = 0
    hop_counts: list[int] = []
    generated = delivered = dropped = forwarding = 0
    target_opportunities = target_drops = 0
    for packet_id, packet_events in by_packet.items():
        packet_events.sort(key=lambda e: (float(e["timestamp"]), {"generated": 0, "forwarded": 1, "dropped": 2, "received": 3}.get(e["action"], 4)))
        source, destination = int(packet_events[0]["source"]), int(packet_events[0]["destination"])
        route = [source]
        terminal = None
        for event in packet_events:
            node = int(event["current_node"])
            action = event["action"]
            if action == "generated":
                generated += 1
                nodes[source]["packets_generated"] += 1
            elif action == "forwarded":
                forwarding += 1
                nodes[node]["forwarding_events"] += 1
                nodes[node]["relay_opportunities"] += 1
                nodes[node]["successful_forwardings"] += 1
                target_opportunities += int(node == target_node)
            elif action == "dropped":
                dropped += 1
                nodes[node]["packets_dropped_at_node"] += 1
                if node != source and node != destination:
                    nodes[node]["relay_opportunities"] += 1
                    target_opportunities += int(node == target_node)
                    target_drops += int(node == target_node)
                terminal = "dropped"
            elif action == "received":
                delivered += 1
                nodes[node]["packets_received"] += 1
                terminal = "received"
            if action == "generated" and event.get("next_hop"):
                route.append(int(event["next_hop"]))
            elif action == "forwarded" and event.get("next_hop"):
                nxt = int(event["next_hop"])
                if route[-1] != node:
                    route.append(node)
                route.append(nxt)
            elif action == "dropped" and node != source:
                if route[-1] != node:
                    route.append(node)
                if event.get("next_hop"):
                    route.append(int(event["next_hop"]))
        # A packet with a valid first hop and terminal event has an observed route.
        # A source-side no-route drop is not counted as a route or relay event.
        if len(route) > 1:
            if terminal == "received" and route[-1] != destination:
                route.append(destination)
            if route[-1] == destination or terminal == "dropped":
                route_signatures.add(tuple(route))
                for node in set(route):
                    traversals[node] += 1
                hops = max(0, len(route) - 1)
                hop_counts.append(hops)
                multihop += hops > 1

    all_nodes = set(nodes) | set(traversals)
    per_node: list[dict[str, Any]] = []
    for node in sorted(all_nodes):
        counts = nodes[node]
        per_node.append({
            "node_id": node,
            "packets_generated": counts["packets_generated"],
            "packets_received": counts["packets_received"],
            "packets_dropped_at_node": counts["packets_dropped_at_node"],
            "forwarding_events": counts["forwarding_events"],
            "relay_opportunities": counts["relay_opportunities"],
            "packets_traversing_node": traversals[node],
        })
    run_metrics = {
        "run_directory": str(simulation_dir.parent.resolve()),
        "seed": summary.get("random_seed"),
        "backend": summary.get("backend", "Unavailable"),
        "packets_generated_from_events": generated,
        "packets_delivered_from_events": delivered,
        "packets_dropped_from_events": dropped,
        "forwarding_events_from_events": forwarding,
        "unique_route_signatures": len(route_signatures),
        "multihop_packet_count": multihop,
        "mean_route_hops_observed": statistics.fmean(hop_counts) if hop_counts else None,
        "route_count_observed": len(hop_counts),
        "zero_route_runs": int(not hop_counts),
        "target_node": target_node,
        "target_relay_opportunities": target_opportunities,
        "target_observed_relay_drops": target_drops,
        "zero_target_opportunity_run": int(target_node is not None and target_opportunities == 0),
    }
    return run_metrics, per_node


def audit_validation(validation_dir: Path, output_dir: Path, target_node: int = 7) -> dict[str, Any]:
    """Audit every real run listed in a Phase 4 validation manifest."""
    validation_dir, output_dir = Path(validation_dir), Path(output_dir)
    manifest = _read_events(validation_dir / "experiment_manifest.csv")
    run_rows: list[dict[str, Any]] = []
    node_rows: list[dict[str, Any]] = []
    for row in manifest:
        run_dir = Path(row["run_directory"])
        if not run_dir.is_absolute():
            run_dir = validation_dir / run_dir
        metrics, nodes = measure_simulation(run_dir / "simulation", target_node)
        metrics.update({"scenario": row.get("scenario"), "drop_probability": row.get("drop_probability")})
        run_rows.append(metrics)
        for item in nodes:
            node_rows.append({"seed": metrics["seed"], "scenario": metrics["scenario"], **item})

    output_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(output_dir / "per_run_simulator_metrics.csv", run_rows)
    _write_csv(output_dir / "per_node_simulator_metrics.csv", node_rows)
    scenarios: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in run_rows:
        scenarios[str(row["scenario"])].append(row)
    scenario_summary = {}
    for name, rows in sorted(scenarios.items()):
        scenario_summary[name] = {
            "runs": len(rows),
            "mean_packets_generated": statistics.fmean(r["packets_generated_from_events"] for r in rows),
            "mean_packets_delivered": statistics.fmean(r["packets_delivered_from_events"] for r in rows),
            "mean_packets_dropped": statistics.fmean(r["packets_dropped_from_events"] for r in rows),
            "mean_forwarding_events": statistics.fmean(r["forwarding_events_from_events"] for r in rows),
            "mean_unique_route_signatures": statistics.fmean(r["unique_route_signatures"] for r in rows),
            "mean_multihop_packets": statistics.fmean(r["multihop_packet_count"] for r in rows),
            "mean_target_relay_opportunities": statistics.fmean(r["target_relay_opportunities"] for r in rows),
            "mean_target_observed_drops": statistics.fmean(r["target_observed_relay_drops"] for r in rows),
            "zero_target_opportunity_runs": sum(r["zero_target_opportunity_run"] for r in rows),
            "mean_route_hops_observed": statistics.fmean(r["mean_route_hops_observed"] for r in rows if r["mean_route_hops_observed"] is not None) if any(r["mean_route_hops_observed"] is not None for r in rows) else None,
        }
    summary = {
        "provenance": "Measured from packet_events.csv in the preserved Phase 4 runs; no event generation or detector labels used for route construction.",
        "target_node": target_node,
        "run_count": len(run_rows),
        "scenario_summary": scenario_summary,
        "interpretation": [
            "The simulator emits one packet per UAV per timestep, but random source-destination pairs and shortest-hop paths may not expose a given relay often.",
            "A packet-drop event is counted as a relay attack observation only when the dropped node is neither packet source nor destination.",
        ],
    }
    (output_dir / "simulator_audit_summary.json").write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return summary


def run_topology_sensitivity(output_dir: Path, seeds: list[int], ranges_m: list[float],
                             target_node: int = 7) -> list[dict[str, Any]]:
    """Run normal traffic at candidate radio ranges; this is a sensitivity study."""
    from aex_tfanet.utils.paths import project_root

    output_dir = Path(output_dir)
    if output_dir.exists() and any(output_dir.iterdir()):
        raise DataValidationError(f"Refusing to overwrite non-empty sensitivity output: {output_dir}")
    rows: list[dict[str, Any]] = []
    base = load_config()
    for radius in ranges_m:
        if radius <= 0:
            raise ValueError("candidate communication ranges must be positive")
        for seed in seeds:
            cfg = replace(base, simulation=replace(base.simulation, seed=seed, communication_range_m=radius))
            run_path = output_dir / "runs" / f"range_{radius:g}m" / f"seed_{seed}"
            run_python_simulation(cfg, run_path / "simulation", overlay={})
            metrics, _ = measure_simulation(run_path / "simulation", target_node)
            summary = json.loads((run_path / "simulation" / "summary.json").read_text(encoding="utf-8"))
            rows.append({
                "seed": seed,
                "communication_range_m": radius,
                "packets_generated": metrics["packets_generated_from_events"],
                "packets_delivered": metrics["packets_delivered_from_events"],
                "packets_dropped": metrics["packets_dropped_from_events"],
                "pdr": summary["packet_delivery_ratio"],
                "forwarding_events": metrics["forwarding_events_from_events"],
                "multihop_packets": metrics["multihop_packet_count"],
                "mean_route_hops": metrics["mean_route_hops_observed"],
                "unique_route_signatures": metrics["unique_route_signatures"],
                "target_relay_opportunities": metrics["target_relay_opportunities"],
                "zero_target_opportunity_run": metrics["zero_target_opportunity_run"],
                "backend": metrics["backend"],
            })
    _write_csv(output_dir / "topology_sensitivity_per_run.csv", rows)
    summary_rows = []
    for radius in ranges_m:
        group = [row for row in rows if row["communication_range_m"] == radius]
        for metric in ("pdr", "forwarding_events", "multihop_packets", "mean_route_hops", "unique_route_signatures", "target_relay_opportunities"):
            vals = [float(row[metric]) for row in group if row[metric] is not None]
            summary_rows.append({
                "communication_range_m": radius,
                "metric": metric,
                "mean": statistics.fmean(vals) if vals else None,
                "std": statistics.pstdev(vals) if len(vals) > 1 else (0.0 if vals else None),
                "minimum": min(vals) if vals else None,
                "maximum": max(vals) if vals else None,
                "zero_opportunity_runs": sum(row["zero_target_opportunity_run"] for row in group) if metric == "target_relay_opportunities" else None,
                "runs": len(group),
            })
    _write_csv(output_dir / "topology_sensitivity_summary.csv", summary_rows)
    (output_dir / "README.txt").write_text(
        "Exploratory normal-traffic sensitivity to communication_range_m. "
        "No attack is enabled and no attacker label affects routing. "
        "Each run is the Simplified Python FANET Model — NOT NS-3. "
        "These runs are parameter exploration, not Phase 4 validation results.\n",
        encoding="utf-8",
    )
    return summary_rows


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise DataValidationError(f"Cannot write empty audit file: {path}")
    columns = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
