from __future__ import annotations

import pytest

from aex_tfanet.analysis.phase4_validation import aggregate_metrics, build_validation_matrix, read_per_run_metrics
from aex_tfanet.detection import evaluate_nodes
from aex_tfanet.exceptions import DataValidationError


def test_matrix_has_paired_scenarios_for_multiple_seeds() -> None:
    matrix = build_validation_matrix([42, 43], [0.25, 0.5, 0.8])
    assert len(matrix) == 8
    for seed in (42, 43):
        group = [row for row in matrix if row["seed"] == seed]
        assert [row["scenario"] for row in group] == [
            "normal", "packet_drop_p25", "packet_drop_p50", "packet_drop_p80"
        ]
        assert group[0]["drop_probability"] == 0


def test_matrix_rejects_missing_duplicate_or_invalid_inputs() -> None:
    with pytest.raises(ValueError, match="seeds"):
        build_validation_matrix([], [0.8])
    with pytest.raises(ValueError, match="unique"):
        build_validation_matrix([42, 42], [0.8])
    with pytest.raises(ValueError, match="probabilities"):
        build_validation_matrix([42], [])
    with pytest.raises(ValueError, match=r"\(0, 1\]"):
        build_validation_matrix([42], [0.0])


def test_aggregate_means_and_population_standard_deviation() -> None:
    rows = [
        {"scenario": "packet_drop_p80", "drop_probability": 0.8, "seed": 42, "F1": 0.5, "TP": 1, "TN": 8, "FP": 1, "FN": 1},
        {"scenario": "packet_drop_p80", "drop_probability": 0.8, "seed": 43, "F1": 1.0, "TP": 2, "TN": 9, "FP": 0, "FN": 0},
        {"scenario": "normal", "drop_probability": 0.0, "seed": 42, "F1": None, "TP": 0, "TN": 10, "FP": 0, "FN": 0},
    ]
    result = {row["scenario"]: row for row in aggregate_metrics(rows, ["F1", "FP"])}
    assert result["packet_drop_p80"]["F1_mean"] == pytest.approx(0.75)
    assert result["packet_drop_p80"]["F1_std"] == pytest.approx(0.25)
    assert result["packet_drop_p80"]["TP_total"] == 3
    assert result["packet_drop_p80"]["pooled_precision"] == pytest.approx(0.75)
    assert result["packet_drop_p80"]["pooled_recall"] == pytest.approx(0.75)
    assert result["normal"]["F1_mean"] is None
    assert result["normal"]["F1_valid_runs"] == 0


def test_empty_metric_aggregation_is_rejected() -> None:
    with pytest.raises(DataValidationError, match="No per-run rows"):
        aggregate_metrics([])


def test_missing_and_empty_metrics_files_are_rejected(tmp_path) -> None:
    with pytest.raises(DataValidationError, match="not found"):
        read_per_run_metrics(tmp_path / "missing.csv")
    empty = tmp_path / "empty.csv"
    empty.write_text("seed,scenario\n", encoding="utf-8")
    with pytest.raises(DataValidationError, match="no result rows"):
        read_per_run_metrics(empty)


def test_zero_positive_class_metrics_are_marked_undefined() -> None:
    metrics = evaluate_nodes([{"node_id": 1, "status": "NORMAL"}, {"node_id": 2, "status": "NORMAL"}], set())
    assert metrics["TP"] == 0 and metrics["TN"] == 2
    assert metrics["precision"] is None
    assert metrics["recall"] is None
    assert metrics["F1"] is None
    assert metrics["false_positive_rate"] == 0
    assert metrics["false_negative_rate"] is None


def test_false_positive_and_false_negative_counts_and_rates() -> None:
    metrics = evaluate_nodes([
        {"node_id": 1, "status": "NORMAL"},
        {"node_id": 2, "status": "SUSPICIOUS"},
    ], {1})
    assert (metrics["TP"], metrics["TN"], metrics["FP"], metrics["FN"]) == (0, 0, 1, 1)
    assert metrics["false_positive_rate"] == 1
    assert metrics["false_negative_rate"] == 1
    assert metrics["precision"] == 0
    assert metrics["recall"] == 0
