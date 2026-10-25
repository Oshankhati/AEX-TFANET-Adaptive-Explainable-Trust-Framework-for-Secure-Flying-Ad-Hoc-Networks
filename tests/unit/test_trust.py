from __future__ import annotations

import csv
from pathlib import Path

import pytest

from aex_tfanet.exceptions import DataValidationError
from aex_tfanet.trust.adaptive import adapt_trust, fuse_trust, update_history
from aex_tfanet.trust.classifier import classify_trust
from aex_tfanet.trust.direct import calculate_direct_trust
from aex_tfanet.trust.indirect import aggregate_recommendations
from aex_tfanet.trust.models import Recommendation
from aex_tfanet.trust.processor import process_simulation_directory
from aex_tfanet.trust.engine import validate_trust_scores
from aex_tfanet.utils.paths import project_root


def test_direct_trust_zero_observations_uses_neutral_beta_prior() -> None:
    assert calculate_direct_trust(0, 0) == 0.5


def test_direct_trust_all_successes_and_failures_are_smoothed_and_bounded() -> None:
    assert calculate_direct_trust(9, 0) == pytest.approx(10 / 11)
    assert calculate_direct_trust(0, 9) == pytest.approx(1 / 11)
    assert 0 <= calculate_direct_trust(10**8, 0) <= 1


def test_direct_trust_mixed_successes_and_custom_beta_priors() -> None:
    assert calculate_direct_trust(9, 1) == pytest.approx(10 / 12)
    assert calculate_direct_trust(1, 1, alpha=2, beta=3) == pytest.approx(3 / 7)


@pytest.mark.parametrize("successes,failures,alpha,beta", [(-1, 0, 1, 1), (0, -1, 1, 1), (0, 0, 0, 1)])
def test_direct_trust_rejects_invalid_parameters(successes, failures, alpha, beta) -> None:
    with pytest.raises(DataValidationError):
        calculate_direct_trust(successes, failures, alpha, beta)


def test_indirect_trust_one_and_multiple_weighted_recommendations() -> None:
    score, count = aggregate_recommendations([Recommendation(0.8, 0.25)])
    assert score == pytest.approx(0.25) and count == 1
    score, count = aggregate_recommendations([Recommendation(0.8, 0.25), Recommendation(0.2, 0.75)])
    assert score == pytest.approx(0.35) and count == 2


def test_indirect_trust_filters_untrusted_recommenders_and_reports_unavailable() -> None:
    assert aggregate_recommendations([], min_recommendations=1) == (None, 0)
    assert aggregate_recommendations([Recommendation(0.0, 1.0)]) == (None, 0)
    assert aggregate_recommendations([Recommendation(0.1, 0.0)], min_recommender_trust=0.2) == (None, 0)


def test_indirect_trust_zero_total_weight_is_unavailable() -> None:
    assert aggregate_recommendations([Recommendation(0, 0.9), Recommendation(0, 0.2)]) == (None, 0)


def test_history_ewma_first_repeated_and_changing_observations() -> None:
    assert update_history(None, 0.8, 0.3) == 0.8
    assert update_history(0.8, 0.8, 0.3) == pytest.approx(0.8)
    assert update_history(0.8, 0.2, 0.3) == pytest.approx(0.62)
    assert update_history(0.2, 0.8, 0.3) == pytest.approx(0.38)


def test_adaptive_fusion_renormalizes_when_indirect_is_unavailable() -> None:
    assert fuse_trust({"direct": 0.8, "indirect": None, "history": 0.4}, {"direct": 0.5, "indirect": 0.2, "history": 0.3}) == pytest.approx(0.65)
    assert fuse_trust({"direct": 0.2, "indirect": 0.9}, {"direct": 0.5, "indirect": 0.2}) < 0.5


def test_adaptive_trust_decays_on_bad_evidence_and_recovers_gradually() -> None:
    lower = adapt_trust(0.9, 0.3, decay_rate=0.25, recovery_rate=0.1)
    recover = adapt_trust(lower, 0.9, decay_rate=0.25, recovery_rate=0.1)
    assert lower == pytest.approx(0.75)
    assert lower < recover < 0.9
    assert adapt_trust(None, 0.7, decay_rate=0.25, recovery_rate=0.1) == 0.7
    assert adapt_trust(0.3, 0.0, decay_rate=1, recovery_rate=1, minimum=0.1) == 0.1


def test_trust_classification_threshold_boundaries() -> None:
    classify = lambda x: classify_trust(x, highly_trusted=0.8, trusted=0.6, suspicious=0.4)
    assert classify(0.8) == "Highly Trusted"
    assert classify(0.6) == "Trusted"
    assert classify(0.4) == "Suspicious"
    assert classify(0.399) == "Untrusted / Malicious"


def _write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def _valid_input(folder: Path) -> Path:
    folder.mkdir()
    uav_columns = ["timestamp", "uav_id", "position_x", "position_y", "mobility_mps", "neighbors", "packets_generated", "packets_sent", "packets_forwarded", "packets_received", "packets_dropped", "forwarding_ratio", "delivery_ratio", "link_stability"]
    uavs = []
    for stamp in (0.0, 1.0):
        for node in (1, 2):
            uavs.append(dict(timestamp=stamp, uav_id=node, position_x=node, position_y=0, mobility_mps=1, neighbors=1, packets_generated=1, packets_sent=1, packets_forwarded=0, packets_received=0, packets_dropped=0, forwarding_ratio=1, delivery_ratio=1, link_stability=1))
    _write_csv(folder / "uav_events.csv", uav_columns, uavs)
    neighbor_columns = ["timestamp", "uav_id", "neighbor_id", "distance", "connected"]
    neighbors = [dict(timestamp=t, uav_id=a, neighbor_id=b, distance=1, connected=True) for t in (0.0, 1.0) for a,b in ((1,2),(2,1))]
    _write_csv(folder / "neighbor_events.csv", neighbor_columns, neighbors)
    packet_columns = ["timestamp", "packet_id", "source", "destination", "current_node", "next_hop", "action"]
    packets = [
        dict(timestamp=0, packet_id=1, source=1, destination=2, current_node=1, next_hop=2, action="generated"),
        dict(timestamp=0, packet_id=1, source=1, destination=2, current_node=2, next_hop="", action="received"),
        dict(timestamp=1, packet_id=2, source=1, destination=2, current_node=1, next_hop=2, action="generated"),
        dict(timestamp=1, packet_id=2, source=1, destination=2, current_node=2, next_hop="", action="dropped"),
    ]
    _write_csv(folder / "packet_events.csv", packet_columns, packets)
    return folder


def test_processor_creates_direct_temporal_relationships_from_outcomes(tmp_path: Path) -> None:
    data = process_simulation_directory(_valid_input(tmp_path / "valid"))
    assert data.node_ids == {1, 2}
    assert [(o.observer_id, o.target_id, o.successful_forwarding, o.failed_forwarding) for o in data.observations] == [(1, 2, 1, 0), (1, 2, 0, 1)]


def test_processor_rejects_missing_column_malformed_value_empty_data_and_unknown_ids(tmp_path: Path) -> None:
    root = project_root()
    base = _valid_input(tmp_path / "base")
    missing = tmp_path / "missing"
    import shutil
    shutil.copytree(base, missing)
    text = (missing / "packet_events.csv").read_text(encoding="utf-8").replace(",next_hop,", ",hop,")
    (missing / "packet_events.csv").write_text(text, encoding="utf-8")
    with pytest.raises(DataValidationError, match="missing required columns"):
        process_simulation_directory(missing)

    malformed = tmp_path / "malformed"
    shutil.copytree(base, malformed)
    text = (malformed / "uav_events.csv").read_text(encoding="utf-8").replace("0.0,1,1,0", "bad,1,1,0", 1)
    (malformed / "uav_events.csv").write_text(text, encoding="utf-8")
    with pytest.raises(DataValidationError, match="numeric"):
        process_simulation_directory(malformed)

    empty = tmp_path / "empty"
    shutil.copytree(base, empty)
    (empty / "packet_events.csv").write_text("timestamp,packet_id,source,destination,current_node,next_hop,action\n", encoding="utf-8")
    with pytest.raises(DataValidationError, match="no data rows"):
        process_simulation_directory(empty)

    unknown = tmp_path / "unknown"
    shutil.copytree(base, unknown)
    text = (unknown / "packet_events.csv").read_text(encoding="utf-8").replace("0,1,1,2,1,2,generated", "0,1,1,3,1,2,generated")
    (unknown / "packet_events.csv").write_text(text, encoding="utf-8")
    with pytest.raises(DataValidationError, match="unknown"):
        process_simulation_directory(unknown)


def test_processor_rejects_duplicate_packet_events(tmp_path: Path) -> None:
    root = _valid_input(tmp_path / "duplicate")
    path = root / "packet_events.csv"
    with path.open(encoding="utf-8") as stream:
        content = stream.read()
    path.write_text(content + content.splitlines()[1] + "\n", encoding="utf-8")
    with pytest.raises(DataValidationError, match="duplicate event"):
        process_simulation_directory(root)


def test_trust_output_validator_rejects_nan_and_self_relationships() -> None:
    row = dict(timestamp=0, observer_id=1, target_id=2, packets_observed=1, successful_forwarding=1,
               failed_forwarding=0, forwarding_ratio=1, delivery_observations=0, neighbor_connected=True,
               direct_trust=0.8, indirect_trust="", indirect_available=False, indirect_recommenders=0,
               historical_trust=0.8, final_trust=0.8, classification="Highly Trusted")
    validate_trust_scores([row], {1, 2})
    bad = dict(row, final_trust=float("nan"))
    with pytest.raises(DataValidationError, match="finite"):
        validate_trust_scores([bad], {1, 2})
    bad_pair = dict(row, target_id=1)
    with pytest.raises(DataValidationError, match="impossible relationship"):
        validate_trust_scores([bad_pair], {1, 2})
