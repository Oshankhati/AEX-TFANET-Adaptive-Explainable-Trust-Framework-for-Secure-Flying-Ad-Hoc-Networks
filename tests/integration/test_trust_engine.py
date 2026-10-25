from __future__ import annotations

import csv
import json
from pathlib import Path

from aex_tfanet.simulation.fanet import run_python_simulation
from aex_tfanet.trust.engine import write_trust_results
from aex_tfanet.trust.processor import process_simulation_directory
from aex_tfanet.utils.config import load_config
from aex_tfanet.utils.paths import project_root


ROOT = project_root()


def _scenario(name: str):
    config_path = ROOT / "experiments" / "configs" / f"{name}.yaml"
    return load_config(overlay=config_path), config_path


def test_phase2_to_trust_pipeline_and_reproducible_outputs(tmp_path: Path) -> None:
    cfg, _ = _scenario("packet_drop")
    simulation_dir = tmp_path / "experiment" / "simulation"
    run_python_simulation(cfg, simulation_dir)
    data = process_simulation_directory(simulation_dir)
    assert data.backend is not None
    out_a, out_b = tmp_path / "experiment" / "trust_a", tmp_path / "experiment" / "trust_b"
    summary_a = write_trust_results(simulation_dir, out_a, cfg)
    summary_b = write_trust_results(simulation_dir, out_b, cfg)
    scores_a = out_a / "trust_scores.csv"
    scores_b = out_b / "trust_scores.csv"
    assert scores_a.is_file() and (out_a / "trust_summary.json").is_file()
    assert scores_a.read_bytes() == scores_b.read_bytes()
    assert summary_a["mean_trust"] == summary_b["mean_trust"]
    rows = list(csv.DictReader(scores_a.open(encoding="utf-8", newline="")))
    assert rows and all(0 <= float(row["final_trust"]) <= 1 for row in rows)
    assert all(row["classification"] in {"Highly Trusted", "Trusted", "Suspicious", "Untrusted / Malicious"} for row in rows)
    assert all((row["indirect_trust"] == "") == (row["indirect_available"] == "False") for row in rows)
    assert summary_a["backend_used"] == "Simplified Python FANET Model — NOT NS-3"


def test_observed_packet_drops_reduce_relational_trust_without_using_labels(tmp_path: Path) -> None:
    normal_cfg, _ = _scenario("normal")
    attack_cfg, _ = _scenario("packet_drop")
    normal_sim = tmp_path / "normal" / "simulation"
    attack_sim = tmp_path / "attack" / "simulation"
    normal_summary = run_python_simulation(normal_cfg, normal_sim)
    attack_summary = run_python_simulation(attack_cfg, attack_sim)
    # Malicious-node metadata is not used by processing or the trust engine.
    for summary_path in (normal_sim / "summary.json", attack_sim / "summary.json"):
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary.pop("malicious_nodes", None)
        summary_path.write_text(json.dumps(summary), encoding="utf-8")
    normal_out = tmp_path / "normal" / "trust"
    attack_out = tmp_path / "attack" / "trust"
    write_trust_results(normal_sim, normal_out, normal_cfg)
    write_trust_results(attack_sim, attack_out, attack_cfg)
    normal_rows = list(csv.DictReader((normal_out / "trust_scores.csv").open(encoding="utf-8", newline="")))
    attack_rows = list(csv.DictReader((attack_out / "trust_scores.csv").open(encoding="utf-8", newline="")))
    normal_target = {(int(r["observer_id"]), int(r["target_id"])): float(r["final_trust"]) for r in normal_rows if int(r["target_id"]) == 7}
    attack_target = {(int(r["observer_id"]), int(r["target_id"])): float(r["final_trust"]) for r in attack_rows if int(r["target_id"]) == 7}
    common = set(normal_target) & set(attack_target)
    assert common
    # Same seed preserves routes; the added failures lower trust for directly affected observers.
    normal_latest = {}
    attack_latest = {}
    for row in normal_rows:
        key = (int(row["observer_id"]), int(row["target_id"]))
        normal_latest[key] = row
    for row in attack_rows:
        key = (int(row["observer_id"]), int(row["target_id"]))
        attack_latest[key] = row
    failure_pairs = {key for key, row in attack_latest.items() if key[1] == 7 and int(row["failed_forwarding"]) > 0}
    # Event-level failures may precede a pair's final timestamp; compare cumulative direct evidence from the CSV.
    attack_inputs = process_simulation_directory(attack_sim)
    failure_pairs = {(o.observer_id, o.target_id) for o in attack_inputs.observations if o.target_id == 7 and o.failed_forwarding > 0}
    assert failure_pairs
    compared = failure_pairs & common
    assert compared
    assert all(attack_target[pair] < normal_target[pair] for pair in common)
