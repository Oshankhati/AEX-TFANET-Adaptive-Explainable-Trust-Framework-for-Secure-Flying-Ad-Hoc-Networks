"""Paired multi-seed baseline versus trust-aware routing experiments."""
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

from aex_tfanet.exceptions import DataValidationError
from aex_tfanet.simulation.fanet import run_simulation
from aex_tfanet.utils.config import load_config
from aex_tfanet.utils.paths import project_root


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise DataValidationError(f"Cannot write empty routing experiment artifact: {path}")
    columns = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: "" if value is None else value for key, value in row.items()})


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        rows = list(reader)
        if not reader.fieldnames:
            raise DataValidationError(f"Missing CSV header in {path}")
        return rows


def run_routing_comparison(output_dir: Path, seeds: list[int] | None = None,
                           drop_probability: float = 0.8) -> dict[str, Any]:
    """Run paired normal and p-drop scenarios under both real routing policies."""
    output_dir = Path(output_dir).resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"Routing experiment output directory is not empty: {output_dir}")
    seeds = seeds or list(range(42, 62))
    if not seeds or len(seeds) != len(set(seeds)) or any(isinstance(s, bool) or s < 0 for s in seeds):
        raise ValueError("seeds must be unique non-negative integers")
    if not math.isfinite(drop_probability) or not 0 < drop_probability <= 1:
        raise ValueError("drop_probability must be finite and in (0, 1]")
    root = project_root()
    output_dir.mkdir(parents=True, exist_ok=True)
    config_dir = output_dir / "configs"; config_dir.mkdir()
    (output_dir / "runs").mkdir()
    base_normal = yaml.safe_load((root / "experiments/configs/normal.yaml").read_text(encoding="utf-8"))
    base_attack = yaml.safe_load((root / "experiments/configs/packet_drop.yaml").read_text(encoding="utf-8"))
    if {k: v for k, v in base_normal.items() if k != "attack"} != {k: v for k, v in base_attack.items() if k != "attack"}:
        raise DataValidationError("Normal and packet-drop routing profiles differ outside the attack block")

    records: list[dict[str, Any]] = []
    manifest: list[dict[str, Any]] = []
    for seed in seeds:
        for scenario in ("normal", f"packet_drop_p{round(drop_probability * 100):02d}"):
            for policy, mode in (("baseline", "baseline"), ("aex_tfanet", "aex_tfanet")):
                raw = json.loads(json.dumps(base_normal if scenario == "normal" else base_attack))
                raw.setdefault("simulation", {})["seed"] = seed
                raw.setdefault("routing", {})["mode"] = mode
                if scenario != "normal":
                    raw["attack"]["drop_probability"] = drop_probability
                config_path = config_dir / f"seed_{seed}_{scenario}_{policy}.yaml"
                config_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
                run_dir = output_dir / "runs" / f"seed_{seed}" / scenario / policy
                run_dir.parent.mkdir(parents=True, exist_ok=True)
                run_simulation(config_path, "python", run_dir)
                sim_dir = run_dir / "simulation"
                summary = json.loads((sim_dir / "summary.json").read_text(encoding="utf-8"))
                route_rows = _read_csv(sim_dir / "route_decisions.csv")
                routed = [row for row in route_rows if row["selected_path"]]
                hop_counts = [int(row["hop_count"]) for row in routed]
                malicious = {int(node) for node in summary.get("malicious_nodes", [])}
                exposure = 0
                for row in routed:
                    path = [int(node) for node in row["selected_path"].split(">")]
                    if malicious.intersection(path[1:-1]):
                        exposure += 1
                packet_size = load_config(overlay=config_path).simulation.packet_size_bytes
                duration = float(summary["simulation_duration_s"])
                delivered_bytes = int(summary["total_packets_delivered"]) * packet_size
                records.append({
                    "seed": seed, "scenario": scenario, "routing_policy": policy,
                    "routing_mode": mode, "simulator": summary["backend"],
                    "packets_generated": summary["total_packets_generated"],
                    "packets_delivered": summary["total_packets_delivered"],
                    "packets_dropped": summary["total_packets_dropped"],
                    "pdr": summary["packet_delivery_ratio"],
                    "packet_loss_ratio": summary["packet_loss_ratio"],
                    "throughput_mbps": delivered_bytes * 8 / duration / 1_000_000 if duration > 0 else None,
                    "delay_s": None,
                    "routed_packets": len(routed),
                    "unavailable_routes": len(route_rows) - len(routed),
                    "mean_route_hops": statistics.fmean(hop_counts) if hop_counts else None,
                    "malicious_intermediate_exposures": exposure,
                    "malicious_exposure_rate": exposure / len(routed) if routed and malicious else (0.0 if not malicious and routed else None),
                    "route_changes": summary.get("route_changes"),
                    "route_change_rate": summary.get("route_changes", 0) / len(routed) if routed else None,
                    "mean_selected_route_cost": statistics.fmean(float(row["route_cost"]) for row in routed if row["route_cost"] != "") if any(row["route_cost"] != "" for row in routed) else None,
                    "config_path": str(config_path.resolve()), "run_directory": str(run_dir.resolve()),
                })
                manifest.append({"seed": seed, "scenario": scenario, "routing_policy": policy,
                                 "config_path": str(config_path.resolve()), "run_directory": str(run_dir.resolve()),
                                 "simulator": summary["backend"], "labels_used_for_route_selection": False})
    _write_csv(output_dir / "per_run_routing_metrics.csv", records)
    _write_csv(output_dir / "experiment_manifest.csv", manifest)

    metrics = ("pdr", "packet_loss_ratio", "throughput_mbps", "delay_s", "mean_route_hops",
               "malicious_exposure_rate", "route_changes", "route_change_rate", "mean_selected_route_cost")
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[(record["scenario"], record["routing_policy"])].append(record)
    aggregate = []
    for (scenario, policy), group in sorted(groups.items()):
        item: dict[str, Any] = {"scenario": scenario, "routing_policy": policy, "run_count": len(group)}
        for metric in metrics:
            values = [float(row[metric]) for row in group if row.get(metric) is not None]
            item[f"{metric}_valid_runs"] = len(values)
            item[f"{metric}_mean"] = statistics.fmean(values) if values else None
            item[f"{metric}_std"] = statistics.pstdev(values) if len(values) > 1 else (0.0 if values else None)
            item[f"{metric}_min"] = min(values) if values else None
            item[f"{metric}_max"] = max(values) if values else None
        aggregate.append(item)
    _write_csv(output_dir / "aggregate_routing_metrics.csv", aggregate)
    figures_dir = output_dir / "figures"; figures_dir.mkdir()
    _make_figures(figures_dir, records)
    result = {
        "study": "Paired baseline shortest-hop versus online AEX-TFANET trust-aware routing",
        "simulator": "Simplified Python FANET Model — NOT NS-3",
        "seeds": seeds, "scenarios": ["normal", f"packet_drop_p{round(drop_probability * 100):02d}"],
        "run_count": len(records), "routing_modes": ["baseline", "aex_tfanet"],
        "delay": "Not evaluated. The simulator forwards within the current timestep and does not represent per-hop transmission delay.",
        "throughput_definition": "Delivered application bytes (delivered packets × configured packet_size_bytes × 8) divided by configured simulation duration; Mbps.",
        "route_cost": "Trust-aware routes use configured hop, direct forwarding-trust, current link-stability, and observed forwarding-success weights. Delay is omitted because it is unavailable.",
        "attack_exposure": "Evaluated after routing by checking whether the ground-truth attacked UAV is an intermediate node in the selected path; labels are never passed to route selection.",
        "aggregate_metrics": aggregate,
        "figures": [str(path.relative_to(output_dir)) for path in sorted(figures_dir.glob("*.png"))],
    }
    (output_dir / "routing_comparison_summary.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return result


def _make_figures(directory: Path, rows: list[dict[str, Any]]) -> None:
    specs = [
        ("pdr", "Packet delivery ratio by routing policy", "PDR (fraction)"),
        ("packet_loss_ratio", "Packet loss by routing policy", "Packet loss ratio (fraction)"),
        ("throughput_mbps", "Delivered application throughput by routing policy", "Throughput (Mbps)"),
        ("mean_route_hops", "Mean selected route length by routing policy", "Hops per routed packet"),
        ("malicious_exposure_rate", "Selected-route exposure to attacked UAV", "Exposed routed packets (fraction)"),
        ("route_changes", "Route changes by routing policy", "Route changes (count per run)"),
    ]
    for metric, title, ylabel in specs:
        fig, ax = plt.subplots(figsize=(7.5, 4.5))
        scenarios = sorted({row["scenario"] for row in rows})
        policies = ("baseline", "aex_tfanet")
        width = 0.34
        x = list(range(len(scenarios)))
        for offset, policy in enumerate(policies):
            means = []
            deviations = []
            for scenario in scenarios:
                values = [float(r[metric]) for r in rows if r["scenario"] == scenario and r["routing_policy"] == policy and r[metric] is not None]
                means.append(statistics.fmean(values) if values else float("nan"))
                deviations.append(statistics.pstdev(values) if len(values) > 1 else (0.0 if values else 0.0))
            positions = [value + (offset - .5) * width for value in x]
            ax.bar(positions, means, width, yerr=deviations, capsize=4, label=policy)
        ax.set_xticks(x, scenarios)
        ax.set_title(title); ax.set_xlabel("Scenario"); ax.set_ylabel(ylabel)
        ax.legend(title="Routing policy"); ax.grid(axis="y", alpha=.25)
        fig.text(.01, .01, "Source: per_run_routing_metrics.csv; bars are means and error bars are population SD across seeds.", fontsize=8, color="#475569")
        fig.tight_layout(); fig.savefig(directory / f"{metric}_by_policy.png", dpi=160); plt.close(fig)
