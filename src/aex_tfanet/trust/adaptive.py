"""EWMA historical smoothing and adaptive trust fusion."""
from __future__ import annotations

import math
from collections.abc import Mapping

from aex_tfanet.exceptions import ConfigError, DataValidationError


def update_history(previous: float | None, current_observation: float, smoothing: float) -> float:
    if not 0 <= smoothing <= 1 or not math.isfinite(smoothing):
        raise ConfigError("history smoothing must be in [0, 1]")
    if not 0 <= current_observation <= 1 or not math.isfinite(current_observation):
        raise DataValidationError("history observation must be in [0, 1]")
    if previous is None:
        return current_observation
    if not 0 <= previous <= 1 or not math.isfinite(previous):
        raise DataValidationError("previous historical trust must be in [0, 1]")
    return smoothing * current_observation + (1 - smoothing) * previous


def fuse_trust(components: Mapping[str, float | None], weights: Mapping[str, float]) -> float:
    """Normalize weights over available evidence; missing values never imply trust."""
    active = []
    for name, value in components.items():
        weight = weights.get(name, 0.0)
        if not math.isfinite(weight) or weight < 0:
            raise ConfigError("trust weights must be finite and non-negative")
        if value is None or weight == 0:
            continue
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise DataValidationError(f"{name} trust must be in [0, 1]")
        active.append((weight, value))
    denominator = sum(weight for weight, _ in active)
    if denominator <= 0:
        raise ConfigError("at least one positive weight must have an available trust value")
    return min(1.0, max(0.0, sum(weight * value for weight, value in active) / denominator))


def adapt_trust(previous: float | None, current_evidence: float, *, decay_rate: float, recovery_rate: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    """Move toward current evidence using separate configured fall/recovery rates."""
    if not (0 < decay_rate <= 1 and 0 < recovery_rate <= 1):
        raise ConfigError("decay_rate and recovery_rate must be in (0, 1]")
    if not (0 <= minimum < maximum <= 1 and 0 <= current_evidence <= 1 and math.isfinite(current_evidence)):
        raise DataValidationError("trust bounds or current evidence are invalid")
    current_evidence = min(maximum, max(minimum, current_evidence))
    if previous is None:
        return current_evidence
    if not minimum <= previous <= maximum:
        raise DataValidationError("previous final trust is outside configured bounds")
    rate = recovery_rate if current_evidence >= previous else decay_rate
    return min(maximum, max(minimum, previous + rate * (current_evidence - previous)))
