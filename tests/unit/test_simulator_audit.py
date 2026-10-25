import csv
import json

from aex_tfanet.analysis.simulator_audit import measure_simulation


def test_measure_simulation_counts_only_observed_relay_events(tmp_path):
    columns = ["timestamp", "packet_id", "source", "destination", "current_node", "next_hop", "action"]
    events = [
        [0, 1, 1, 3, 1, 2, "generated"],
        [0, 1, 1, 3, 2, 3, "forwarded"],
        [0, 1, 1, 3, 3, "", "received"],
        [0, 2, 2, 1, 2, 1, "generated"],
        [0, 2, 2, 1, 1, "", "received"],
        [1, 3, 1, 3, 1, "", "generated"],
        [1, 3, 1, 3, 1, "", "dropped"],
    ]
    with (tmp_path / "packet_events.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(columns)
        writer.writerows(events)
    (tmp_path / "summary.json").write_text(json.dumps({"random_seed": 9, "backend": "test"}), encoding="utf-8")

    metrics, nodes = measure_simulation(tmp_path, target_node=2)

    assert metrics["packets_generated_from_events"] == 3
    assert metrics["packets_delivered_from_events"] == 2
    assert metrics["packets_dropped_from_events"] == 1
    assert metrics["forwarding_events_from_events"] == 1
    assert metrics["target_relay_opportunities"] == 1
    assert metrics["target_observed_relay_drops"] == 0
    assert metrics["unique_route_signatures"] == 2
    assert metrics["zero_target_opportunity_run"] == 0
    by_node = {row["node_id"]: row for row in nodes}
    assert by_node[2]["packets_traversing_node"] == 2
    assert by_node[2]["relay_opportunities"] == 1
