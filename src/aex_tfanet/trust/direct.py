"""Pure, bounded Beta/Laplace direct-trust estimator."""
from __future__ import annotations

import math

from aex_tfanet.exceptions import DataValidationError


def calculate_direct_trust(successes: int | float, failures: int | float, alpha: float = 1.0, beta: float = 1.0) -> float:
    values = (successes, failures, alpha, beta)
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in values):
        raise DataValidationError("Direct-trust inputs must be finite numbers")
    if successes < 0 or failures < 0 or alpha <= 0 or beta <= 0:
        raise DataValidationError("Success/failure counts must be non-negative and alpha/beta must be > 0")
    score = (successes + alpha) / (successes + failures + alpha + beta)
    return min(1.0, max(0.0, float(score)))
