import csv
import json
import pytest

from aex_tfanet.analysis import evaluate_experiment


def test_metrics_are_calculated_from_real_summary_and_route_rows(tmp_path):
    sim = tmp_path / "simulation"
    sim.mkdir()
    (sim / "summary.json").write_text(json.dumps({
        "backend": "Simplified Python FANET Model — NOT NS-3", "simulation_duration_s": 10,
        "packet_size_bytes": 512, "total_packets_generated": 10, "total_packets_delivered": 8,
        "total_packets_dropped": 2, "malicious_nodes": [2], "routing_mode": "aex_tfanet", "route_changes": 1,
    }), encoding="utf-8")
    with (sim / "route_decisions.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["selected_path", "hop_count"])
        writer.writeheader(); writer.writerows([
            {"selected_path": "1>2>3", "hop_count": 2},
            {"selected_path": "1>3", "hop_count": 1},
        ])

    metrics = evaluate_experiment(tmp_path)

    assert metrics["packet_delivery_ratio"] == 0.8
    assert metrics["packet_loss_ratio"] == 0.2
    assert metrics["throughput_mbps"] == pytest.approx(0.0032768)
    assert metrics["average_end_to_end_delay_s"] is None
    assert metrics["mean_route_hops"] == 1.5
    assert metrics["attacked_intermediate_exposure_count"] == 1
    assert (tmp_path / "metrics" / "metrics.json").is_file()
