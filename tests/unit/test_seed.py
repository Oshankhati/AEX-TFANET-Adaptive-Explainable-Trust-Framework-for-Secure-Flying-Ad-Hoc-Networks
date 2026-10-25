from __future__ import annotations

import random

import numpy as np
import pytest

from aex_tfanet.utils.seed import set_global_seed


def test_seed_is_reproducible() -> None:
    set_global_seed(42)
    a = [random.random() for _ in range(5)]
    b = np.random.rand(5).tolist()
    set_global_seed(42)
    c = [random.random() for _ in range(5)]
    d = np.random.rand(5).tolist()
    assert a == c
    assert b == d


def test_negative_seed_rejected() -> None:
    with pytest.raises(ValueError):
        set_global_seed(-1)
