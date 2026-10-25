from __future__ import annotations

import csv
from dataclasses import replace
from pathlib import Path

import pytest

from aex_tfanet.detection import detect_behavior, evaluate_nodes
from aex_tfanet.exceptions import DataValidationError
from aex_tfanet.simulation.fanet import NEIGHBOR_COLUMNS, PACKET_COLUMNS, UAV_COLUMNS
from aex_tfanet.trust.schemas import TRUST_SCORE_COLUMNS
from aex_tfanet.utils.config import load_config


def _write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def _fixture(root: Path, actions: list[str]) -> tuple[Path, Path]:
    simulation = root / "simulation"
    simulation.mkdir(parents=True)
    uavs = []
    neighbors = []
    packets = []
    trust = []
    for i, action in enumerate(actions):
        t = float(i)
        for node in (1, 2):
            uavs.append({"timestamp": t, "uav_id": node, "position_x": 1, "position_y": 1,
                         "mobility_mps": 0, "neighbors": 1, "packets_generated": int(node == 1),
                         "packets_sent": int(node == 1), "packets_forwarded": 0, "packets_received": 0,
                         "packets_dropped": 0, "forwarding_ratio": 1.0 if node == 1 else (0.0 if action == "dropped" else 1.0),
                         "delivery_ratio": 1, "link_stability": 0.8})
        neighbors.extend([
            {"timestamp": t, "uav_id": 1, "neighbor_id": 2, "distance": 10, "connected": "true"},
            {"timestamp": t, "uav_id": 2, "neighbor_id": 1, "distance": 10, "connected": "true"},
        ])
        packets.extend([
            {"timestamp": t, "packet_id": i + 1, "source": 1, "destination": 2,
             "current_node": 1, "next_hop": 2, "action": "generated"},
            {"timestamp": t, "packet_id": i + 1, "source": 1, "destination": 2,
             "current_node": 2, "next_hop": "", "action": action},
        ])
        trust.append({"timestamp": t, "observer_id": 1, "target_id": 2, "packets_observed": 1,
                      "successful_forwarding": int(action != "dropped"), "failed_forwarding": int(action == "dropped"),
                      "forwarding_ratio": float(action != "dropped"), "delivery_observations": int(action == "received"),
                      "neighbor_connected": "True", "direct_trust": 0.5, "indirect_trust": "",
                      "indirect_available": "False", "indirect_recommenders": 0, "historical_trust": 0.5,
                      "final_trust": 0.5 if action == "dropped" else 0.7, "classification": "Suspicious"})
    _write_csv(simulation / "uav_events.csv", UAV_COLUMNS, uavs)
    _write_csv(simulation / "neighbor_events.csv", NEIGHBOR_COLUMNS, neighbors)
    _write_csv(simulation / "packet_events.csv", PACKET_COLUMNS, packets)
    trust_path = root / "trust_scores.csv"
    _write_csv(trust_path, TRUST_SCORE_COLUMNS, trust)
    return simulation, trust_path


def _cfg(**overrides):
    return replace(load_config().detection, **overrides)


def test_repeated_observed_drops_raise_behavioral_alert(tmp_path: Path) -> None:
    simulation, trust = _fixture(tmp_path, ["dropped"] * 5)
    rows = detect_behavior(simulation, trust, _cfg(min_observations=3, window_s=10))
    target = [row for row in rows if row["node_id"] == 2]
    assert target[-1]["recent_drops"] == 5
    assert target[-1]["status"] in {"SUSPICIOUS", "MALICIOUS"}
    assert "trust_classification" in target[-1]
    assert "ground_truth" not in target[-1]


def test_recovery_after_window_of_successful_behavior(tmp_path: Path) -> None:
    simulation, trust = _fixture(tmp_path, ["dropped"] * 3 + ["received"] * 5)
    rows = detect_behavior(simulation, trust, _cfg(min_observations=3, window_s=2))
    target = [row for row in rows if row["node_id"] == 2]
    assert any(row["status"] in {"SUSPICIOUS", "MALICIOUS"} for row in target[:4])
    assert target[-1]["recent_drops"] == 0
    assert target[-1]["status"] == "NORMAL"


def test_insufficient_observations_are_not_called_normal(tmp_path: Path) -> None:
    simulation, trust = _fixture(tmp_path, ["dropped"] * 2)
    rows = detect_behavior(simulation, trust, _cfg(min_observations=3))
    assert all(row["status"] == "INSUFFICIENT_DATA" for row in rows if row["node_id"] == 2)


def test_threshold_boundaries_are_inclusive(tmp_path: Path) -> None:
    simulation, trust = _fixture(tmp_path, ["dropped"] * 5)
    first = detect_behavior(simulation, trust, _cfg(min_observations=3))
    score = [row for row in first if row["node_id"] == 2][-1]["detection_score"]
    suspicious_cfg = _cfg(min_observations=3, suspicious_threshold=score, malicious_threshold=min(1.0, score + 0.1))
    assert [r for r in detect_behavior(simulation, trust, suspicious_cfg) if r["node_id"] == 2][-1]["status"] == "SUSPICIOUS"
    malicious_cfg = _cfg(min_observations=3, suspicious_threshold=max(0.0, score - 0.1), malicious_threshold=score)
    assert [r for r in detect_behavior(simulation, trust, malicious_cfg) if r["node_id"] == 2][-1]["status"] == "MALICIOUS"


def test_missing_trust_file_and_malformed_feature_are_rejected(tmp_path: Path) -> None:
    simulation, trust = _fixture(tmp_path, ["received"] * 3)
    with pytest.raises(DataValidationError, match="not found"):
        detect_behavior(simulation, tmp_path / "absent.csv", _cfg(min_observations=1))
    rows = list(csv.DictReader(trust.open(encoding="utf-8")))
    rows[0]["final_trust"] = "nan"
    _write_csv(trust, TRUST_SCORE_COLUMNS, rows)
    with pytest.raises(DataValidationError, match="valid range"):
        detect_behavior(simulation, trust, _cfg(min_observations=1))


def test_determinism_and_node_level_evaluation() -> None:
    rows = [
        {"node_id": 1, "status": "SUSPICIOUS"},
        {"node_id": 1, "status": "NORMAL"},
        {"node_id": 2, "status": "NORMAL"},
    ]
    assert evaluate_nodes(rows, {1}) == evaluate_nodes(rows, {1})
    metrics = evaluate_nodes(rows, {1})
    assert (metrics["TP"], metrics["TN"], metrics["FP"], metrics["FN"]) == (1, 1, 0, 0)


def test_predictions_ignore_attack_metadata_even_if_summary_changes(tmp_path: Path) -> None:
    import json

    simulation, trust = _fixture(tmp_path, ["dropped"] * 4)
    summary = simulation / "summary.json"
    summary.write_text(json.dumps({"malicious_nodes": [1]}), encoding="utf-8")
    first = detect_behavior(simulation, trust, _cfg(min_observations=2))
    summary.write_text("malformed content should not be opened by prediction", encoding="utf-8")
    second = detect_behavior(simulation, trust, _cfg(min_observations=2))
    assert first == second


def test_repeated_detector_execution_is_deterministic(tmp_path: Path) -> None:
    simulation, trust = _fixture(tmp_path, ["dropped", "received", "dropped", "received"])
    config = _cfg(min_observations=2)
    assert detect_behavior(simulation, trust, config) == detect_behavior(simulation, trust, config)
