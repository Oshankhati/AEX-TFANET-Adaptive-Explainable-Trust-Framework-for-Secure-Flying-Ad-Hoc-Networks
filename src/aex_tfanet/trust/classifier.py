"""Configurable interpretation of numeric trust values."""
from __future__ import annotations

from aex_tfanet.exceptions import ConfigError


def classify_trust(value: float, *, highly_trusted: float, trusted: float, suspicious: float) -> str:
    if not 0 <= suspicious <= trusted <= highly_trusted <= 1:
        raise ConfigError("classification thresholds must satisfy 0 <= suspicious <= trusted <= highly_trusted <= 1")
    if not 0 <= value <= 1:
        raise ValueError("trust score must be in [0, 1]")
    if value >= highly_trusted:
        return "Highly Trusted"
    if value >= trusted:
        return "Trusted"
    if value >= suspicious:
        return "Suspicious"
    return "Untrusted / Malicious"
