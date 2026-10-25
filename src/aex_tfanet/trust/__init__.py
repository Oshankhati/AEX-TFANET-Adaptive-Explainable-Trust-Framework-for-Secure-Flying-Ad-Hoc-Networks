"""Phase 3 trust processing and adaptive scoring API."""
from .adaptive import adapt_trust, fuse_trust, update_history
from .classifier import classify_trust
from .direct import calculate_direct_trust
from .engine import calculate_trust_series, validate_trust_scores, write_trust_results
from .indirect import aggregate_recommendations
from .models import Recommendation, TrustObservation, TrustScore
from .processor import process_simulation_directory

__all__ = [
    "Recommendation", "TrustObservation", "TrustScore", "adapt_trust",
    "aggregate_recommendations", "calculate_direct_trust", "calculate_trust_series",
    "classify_trust", "fuse_trust", "process_simulation_directory",
    "update_history", "validate_trust_scores", "write_trust_results",
]
