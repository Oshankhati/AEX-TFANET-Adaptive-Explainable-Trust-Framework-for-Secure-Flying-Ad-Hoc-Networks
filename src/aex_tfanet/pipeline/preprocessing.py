"""Public bridge to the leakage-aware temporal ML feature extractor."""

from pathlib import Path

from aex_tfanet.ml import FEATURE_COLUMNS, build_temporal_dataset


def prepare_temporal_features(validation_dir: Path):
    """Return causal telemetry/trust snapshots and the ordered feature names."""
    return build_temporal_dataset(validation_dir)


__all__ = ["FEATURE_COLUMNS", "prepare_temporal_features"]
