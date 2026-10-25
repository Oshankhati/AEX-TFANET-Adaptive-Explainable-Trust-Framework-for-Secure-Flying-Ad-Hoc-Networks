"""Typed observations and trust time-series records."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TrustObservation:
    timestamp: float
    observer_id: int
    target_id: int
    packets_observed: int
    successful_forwarding: int
    failed_forwarding: int
    forwarding_ratio: float
    delivery_observations: int
    neighbor_connected: bool


@dataclass(frozen=True)
class Recommendation:
    recommender_trust: float
    recommendation: float


@dataclass(frozen=True)
class TrustScore:
    timestamp: float
    observer_id: int
    target_id: int
    packets_observed: int
    successful_forwarding: int
    failed_forwarding: int
    forwarding_ratio: float
    delivery_observations: int
    neighbor_connected: bool
    direct_trust: float
    indirect_trust: float | None
    indirect_recommenders: int
    historical_trust: float
    final_trust: float
    classification: str
