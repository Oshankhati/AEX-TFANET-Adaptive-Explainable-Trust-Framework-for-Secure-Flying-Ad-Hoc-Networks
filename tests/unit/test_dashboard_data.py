import json

import pytest

from aex_tfanet.dashboard_data import (
    ArtifactError,
    artifact_inventory,
    confined_path,
    discover_experiments,
    read_csv,
    read_json,
)


def test_discover_experiments_only_finds_saved_simulation_summaries(tmp_path):
    run = tmp_path / "experiment_a"
    summary = run / "simulation" / "summary.json"
    summary.parent.mkdir(parents=True)
    summary.write_text(json.dumps({"backend": "python"}), encoding="utf-8")
    (tmp_path / "incomplete" / "simulation").mkdir(parents=True)

    assert discover_experiments(tmp_path) == [run.resolve()]


def test_confined_path_rejects_traversal(tmp_path):
    run = tmp_path / "run"
    run.mkdir()

    with pytest.raises(ArtifactError, match="outside the selected experiment"):
        confined_path(tmp_path, run, "../../secret.txt")
    with pytest.raises(ArtifactError, match="outside the configured results"):
        confined_path(tmp_path, tmp_path.parent, "secret.txt")


def test_read_json_and_csv_report_missing_and_malformed_files(tmp_path):
    missing = tmp_path / "missing.json"
    with pytest.raises(ArtifactError, match="missing"):
        read_json(missing)

    malformed = tmp_path / "broken.json"
    malformed.write_text("not-json", encoding="utf-8")
    with pytest.raises(ArtifactError, match="Could not read"):
        read_json(malformed)

    malformed_csv = tmp_path / "broken.csv"
    malformed_csv.write_text('column\n"unfinished', encoding="utf-8")
    with pytest.raises(ArtifactError, match="Could not read"):
        read_csv(malformed_csv)

    csv_path = tmp_path / "trace.csv"
    csv_path.write_text("uav_id,value\n1,0.5\n", encoding="utf-8")
    frame = read_csv(csv_path)
    assert list(frame.columns) == ["uav_id", "value"]
    assert frame.iloc[0].value == 0.5


def test_inventory_is_relative_and_reports_sizes(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "metrics.json"
    artifact.write_text("{}", encoding="utf-8")

    assert artifact_inventory(run) == [{"artifact": "metrics.json", "bytes": 2}]
