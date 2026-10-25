"""Deterministic seeding for reproducible experiments."""

from __future__ import annotations

import os
import random

import numpy as np


def set_global_seed(seed: int) -> None:
    """Seed Python, NumPy, and PYTHONHASHSEED.

    Scikit-learn estimators should still receive random_state explicitly.
    """

    if seed < 0:
        raise ValueError(f"seed must be >= 0, got {seed}")
    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    np.random.seed(seed)
