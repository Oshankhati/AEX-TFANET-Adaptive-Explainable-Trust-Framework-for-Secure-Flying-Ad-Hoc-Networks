from __future__ import annotations

from aex_tfanet.utils.paths import project_root


def test_sample_csv_is_labelled_demo_data() -> None:
    path = project_root() / "data" / "sample" / "uav_features.csv"
    text = path.read_text(encoding="utf-8")
    assert "DEMO/SAMPLE DATA" in text
    assert "uav_id" in text
