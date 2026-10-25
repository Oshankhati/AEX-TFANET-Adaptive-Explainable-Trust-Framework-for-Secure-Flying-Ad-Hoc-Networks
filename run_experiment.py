#!/usr/bin/env python3
"""Convenience entry point: python run_experiment.py --config experiments/configs/normal.yaml"""

from __future__ import annotations

import argparse
from pathlib import Path

from aex_tfanet.pipeline.runner import run_experiment_scaffold


def main() -> int:
    parser = argparse.ArgumentParser(description="AEX-TFANET experiment scaffold (Phase 1)")
    parser.add_argument("--config", type=Path, default=Path("experiments/configs/normal.yaml"))
    args = parser.parse_args()
    out = run_experiment_scaffold(args.config)
    print(f"Experiment scaffold written to: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
