"""CSV schemas for trust-series output."""
TRUST_SCORE_COLUMNS = [
    "timestamp", "observer_id", "target_id", "packets_observed",
    "successful_forwarding", "failed_forwarding", "forwarding_ratio",
    "delivery_observations", "neighbor_connected", "direct_trust",
    "indirect_trust", "indirect_available", "indirect_recommenders",
    "historical_trust", "final_trust", "classification",
]
TRUST_CLASSES = {"Highly Trusted", "Trusted", "Suspicious", "Untrusted / Malicious"}
