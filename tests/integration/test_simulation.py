from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from aex_tfanet.exceptions import DataValidationError, EnvironmentError
from aex_tfanet.simulation.fanet import (
    BACKEND_LABEL,
    PACKET_COLUMNS,
    UAV_COLUMNS,
    run_python_simulation,
    run_simulation,
    validate_uav_events,
)
from aex_tfanet.utils.config import load_config
from aex_tfanet.utils.paths import project_root

ROOT = project_root()


def _load(name: str):
    path = ROOT / "experiments" / "configs" / f"{name}.yaml"
    return load_config(overlay=path), path


def test_uav_creation_movement_and_changing_neighbours(tmp_path: Path) -> None:
    cfg, _ = _load("normal")
    run_python_simulation(cfg, tmp_path)
    with (tmp_path / "uav_events.csv").open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == cfg.simulation.num_uavs * 100
    assert len({(row["position_x"], row["position_y"]) for row in rows if row["uav_id"] == "1"}) > 1
    with (tmp_path / "neighbor_events.csv").open(encoding="utf-8", newline="") as f:
        links = list(csv.DictReader(f))
    assert any(link["connected"] == "True" for link in links)
    assert any(link["connected"] == "False" for link in links)


def test_packet_generation_forwarding_and_delivery(tmp_path: Path) -> None:
    cfg, _ = _load("normal")
    summary = run_python_simulation(cfg, tmp_path)
    with (tmp_path / "packet_events.csv").open(encoding="utf-8", newline="") as f:
        events = list(csv.DictReader(f))
    actions = {event["action"] for event in events}
    assert {"generated", "received"} <= actions
    assert summary["total_packets_generated"] == 1000
    assert summary["total_packets_delivered"] > 0
    assert summary["total_forwarding_events"] > 0
    assert summary["backend"] == BACKEND_LABEL
    assert summary["average_delay_s"] is None


def test_packet_drop_scenario_changes_actual_packet_events(tmp_path: Path) -> None:
    normal_cfg, _ = _load("normal")
    attack_cfg, _ = _load("packet_drop")
    normal = run_python_simulation(normal_cfg, tmp_path / "normal")
    attack = run_python_simulation(attack_cfg, tmp_path / "attack")
    assert attack["total_packets_dropped"] > normal["total_packets_dropped"]
    assert attack["packet_loss_ratio"] > normal["packet_loss_ratio"]
    assert attack["malicious_nodes"] == [7]
    with (tmp_path / "attack" / "packet_events.csv").open(encoding="utf-8", newline="") as f:
        events = list(csv.DictReader(f))
    assert any(e["action"] == "dropped" and e["current_node"] == "7" for e in events)


def test_blackhole_drops_every_actual_relay_opportunity(tmp_path: Path) -> None:
    cfg, _ = _load("blackhole")
    summary = run_python_simulation(cfg, tmp_path)
    with (tmp_path / "packet_events.csv").open(encoding="utf-8", newline="") as stream:
        events = list(csv.DictReader(stream))
    node_seven_outcomes = [event["action"] for event in events
                           if event["current_node"] == "7" and event["action"] in {"forwarded", "dropped"}]
    assert summary["attack_type"] == "blackhole"
    assert summary["drop_probability"] == 1.0
    assert node_seven_outcomes
    assert set(node_seven_outcomes) == {"dropped"}


def test_blackhole_drops_every_actual_relay_opportunity(tmp_path: Path) -> None:
    cfg, _ = _load("blackhole")
    summary = run_python_simulation(cfg, tmp_path)
    with (tmp_path / "packet_events.csv").open(encoding="utf-8", newline="") as stream:
        events = list(csv.DictReader(stream))
    node_seven_outcomes = [event["action"] for event in events
                           if event["current_node"] == "7" and event["action"] in {"forwarded", "dropped"}]
    assert summary["attack_type"] == "blackhole"
    assert summary["drop_probability"] == 1.0
    assert node_seven_outcomes
    assert set(node_seven_outcomes) == {"dropped"}


def test_seed_reproduces_identical_csvs(tmp_path: Path) -> None:
    cfg, _ = _load("normal")
    left, right = tmp_path / "left", tmp_path / "right"
    run_python_simulation(cfg, left)
    run_python_simulation(cfg, right)
    for filename in ("uav_events.csv", "neighbor_events.csv", "packet_events.csv", "route_decisions.csv", "summary.json"):
        assert (left / filename).read_bytes() == (right / filename).read_bytes()


def test_csv_schema_and_data_validation(tmp_path: Path) -> None:
    cfg, _ = _load("normal")
    run_python_simulation(cfg, tmp_path)
    with (tmp_path / "uav_events.csv").open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert list(rows[0]) == UAV_COLUMNS
    with (tmp_path / "packet_events.csv").open(encoding="utf-8", newline="") as f:
        packets = list(csv.DictReader(f))
    assert list(packets[0]) == PACKET_COLUMNS
    invalid = [dict(timestamp=0, uav_id=1, position_x=0, position_y=0, mobility_mps=1, neighbors=0, packets_generated=0, packets_sent=0, packets_forwarded=0, packets_received=0, packets_dropped=0, forwarding_ratio=1.1, delivery_ratio=1, link_stability=1)]
    with pytest.raises(DataValidationError, match="ratios"):
        validate_uav_events(invalid)


def test_cli_output_structure_and_auto_backend_fails_clearly(tmp_path: Path) -> None:
    cfg, path = _load("normal")
    try:
        out = run_simulation(path, "auto", tmp_path / "auto")
    except EnvironmentError as exc:
        assert "NS-3 unavailable" in str(exc)
    else:
        # On a host with NS-3 installed, the backend still requires its validated runner.
        assert out.exists()
    out = run_simulation(path, "python", tmp_path / "integration")
    sim = out / "simulation"
    assert all((sim / n).is_file() for n in ("uav_events.csv", "neighbor_events.csv", "packet_events.csv", "route_decisions.csv", "summary.json"))
    summary = json.loads((sim / "summary.json").read_text(encoding="utf-8"))
    assert summary["backend"] == BACKEND_LABEL
