"""Recommender-weighted indirect trust aggregation."""
from __future__ import annotations

import math
from collections.abc import Iterable

from aex_tfanet.exceptions import DataValidationError
from aex_tfanet.trust.models import Recommendation


def aggregate_recommendations(
    recommendations: Iterable[Recommendation],
    *,
    min_recommender_trust: float = 0.0,
    min_recommendations: int = 1,
) -> tuple[float | None, int]:
    """Return weighted recommendation and number included; unavailable if no weight."""
    if not 0 <= min_recommender_trust <= 1 or min_recommendations < 1:
        raise DataValidationError("Recommendation thresholds are out of range")
    weighted_sum = 0.0
    weight_sum = 0.0
    count = 0
    for item in recommendations:
        trust, recommendation = item.recommender_trust, item.recommendation
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in (trust, recommendation)):
            raise DataValidationError("Recommendations must be finite numeric values")
        if not 0 <= trust <= 1 or not 0 <= recommendation <= 1:
            raise DataValidationError("Recommender trust and recommendation must be in [0, 1]")
        if trust < min_recommender_trust or trust == 0:
            continue
        weighted_sum += trust * recommendation
        weight_sum += trust
        count += 1
    if count < min_recommendations or weight_sum <= 0:
        return None, count
    return min(1.0, max(0.0, weighted_sum / weight_sum)), count
