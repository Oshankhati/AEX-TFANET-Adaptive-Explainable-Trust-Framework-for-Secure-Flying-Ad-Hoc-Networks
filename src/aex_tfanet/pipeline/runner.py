"""Experiment runner.

Phase 1 only creates a reproducible experiment directory. Later phases will
append simulation, trust, detection, routing, XAI, and metrics into the same
layout.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import yaml

from aex_tfanet.utils.config import AppConfig, load_config
from aex_tfanet.utils.environment import probe_environment
from aex_tfanet.utils.logging import get_logger, setup_logging
from aex_tfanet.utils.seed import set_global_seed

LOGGER = get_logger(__name__)

PHASE1_NOTE = (
    "Phase 1 scaffold only. FANET simulation, trust, detection, routing, "
    "ML, XAI, and performance evaluation are not implemented yet."
)


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def create_experiment_dir(output_root: Path, experiment_name: str) -> Path:
    stamp = _timestamp()
    path = output_root / f"{experiment_name}_{stamp}"
    (path / "figures").mkdir(parents=True, exist_ok=True)
    (path / "logs").mkdir(parents=True, exist_ok=True)
    return path


def run_experiment_scaffold(config_path: Path | None = None) -> Path:
    """Load config, seed RNGs, probe the environment, write artefacts.

    Does not invent simulation results.
    """

    overlay = Path(config_path) if config_path else None
    if overlay is not None and overlay.name == "config.yaml" and overlay.parent.name != "experiments":
        cfg = load_config(overlay)
    elif overlay is not None:
        cfg = load_config(overlay=overlay)
    else:
        cfg = load_config()
    return _run(cfg)


def _run(cfg: AppConfig) -> Path:
    experiment_name = cfg.source_path.stem if cfg.source_path else "default"
    out_dir = create_experiment_dir(cfg.experiments.output_directory, experiment_name)
    setup_logging(
        cfg.logging.level,
        log_file=out_dir / "logs" / "experiment.log",
        fmt=cfg.logging.format,
    )
    LOGGER.info("Starting experiment scaffold")
    LOGGER.info("UAV count (configured): %s", cfg.simulation.num_uavs)
    LOGGER.info("Simulation duration (configured): %s seconds", cfg.simulation.duration_s)
    LOGGER.info("Data source: %s", cfg.simulation.source)
    set_global_seed(cfg.simulation.seed)
    LOGGER.info("Global seed set to %s", cfg.simulation.seed)

    report = probe_environment(cfg.simulation.ns3.install_path)
    (out_dir / "environment.json").write_text(
        json.dumps(report.to_dict(), indent=2),
        encoding="utf-8",
    )
    dumped = {
        "project": {
            "name": cfg.project.name,
            "version": cfg.project.version,
            "description": cfg.project.description,
        },
        "simulation": {
            "source": cfg.simulation.source,
            "num_uavs": cfg.simulation.num_uavs,
            "duration_s": cfg.simulation.duration_s,
            "seed": cfg.simulation.seed,
            "communication_range_m": cfg.simulation.communication_range_m,
        },
        "trust": {
            "direct_weight": cfg.trust.direct_weight,
            "indirect_weight": cfg.trust.indirect_weight,
            "update_rate": cfg.trust.update_rate,
        },
        "routing": {"mode": cfg.routing.mode},
        "note": PHASE1_NOTE,
    }
    (out_dir / "config.yaml").write_text(
        yaml.safe_dump(dumped, sort_keys=False),
        encoding="utf-8",
    )
    (out_dir / "STATUS.txt").write_text(PHASE1_NOTE + "\n", encoding="utf-8")
    if not report.ns3_available:
        LOGGER.warning("NS-3 is not available: %s", report.ns3_details)
    LOGGER.info("Experiment directory: %s", out_dir)
    LOGGER.info("Experiment scaffold completed")
    return out_dir
