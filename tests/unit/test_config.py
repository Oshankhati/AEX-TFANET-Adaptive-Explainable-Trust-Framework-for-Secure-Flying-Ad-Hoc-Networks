from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from aex_tfanet.exceptions import ConfigError
from aex_tfanet.utils.config import load_config, load_yaml
from aex_tfanet.utils.paths import project_root


def test_default_config_loads() -> None:
    cfg = load_config()
    assert cfg.project.name == "AEX-TFANET"
    assert cfg.simulation.num_uavs == 10
    assert cfg.simulation.source == "python_fanet"
    assert cfg.trust.direct_weight + cfg.trust.indirect_weight == pytest.approx(1.0)
    assert cfg.trust_thresholds.suspicious <= cfg.trust_thresholds.trusted


def test_experiment_overlay_changes_routing_mode() -> None:
    overlay = project_root() / "experiments" / "configs" / "baseline.yaml"
    cfg = load_config(overlay=overlay)
    assert cfg.routing.mode == "baseline"
    assert cfg.simulation.seed == 42


def test_trust_component_weights_may_be_normalized_by_the_engine(tmp_path: Path) -> None:
    overlay = tmp_path / "weights.yaml"
    overlay.write_text("trust:\n  direct_weight: 0.5\n  indirect_weight: 0.2\n  history_weight: 0.3\n", encoding="utf-8")
    cfg = load_config(overlay=overlay)
    assert cfg.trust.direct_weight == pytest.approx(0.5)
    assert cfg.trust.indirect_weight == pytest.approx(0.2)
    assert cfg.trust.history_weight == pytest.approx(0.3)


def test_missing_file_raises() -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_yaml(Path("does-not-exist.yaml"))


def test_invalid_source_rejected(tmp_path: Path) -> None:
    overlay = tmp_path / "bad.yaml"
    overlay.write_text("simulation:\n  source: imaginary\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="simulation.source"):
        load_config(overlay=overlay)


def test_threshold_order_rejected(tmp_path: Path) -> None:
    overlay = tmp_path / "bad.yaml"
    overlay.write_text(
        yaml.safe_dump(
            {
                "trust_thresholds": {
                    "highly_trusted": 0.2,
                    "trusted": 0.9,
                    "suspicious": 0.4,
                    "malicious": 0.0,
                }
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="trust_thresholds must satisfy"):
        load_config(overlay=overlay)
