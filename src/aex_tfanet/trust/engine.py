"""Relational, event-derived trust time-series engine."""
from __future__ import annotations

import csv
import json
import math
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any

from aex_tfanet.exceptions import DataValidationError
from aex_tfanet.trust.adaptive import adapt_trust, fuse_trust, update_history
from aex_tfanet.trust.classifier import classify_trust
from aex_tfanet.trust.direct import calculate_direct_trust
from aex_tfanet.trust.indirect import aggregate_recommendations
from aex_tfanet.trust.models import Recommendation, TrustScore
from aex_tfanet.trust.processor import ProcessedSimulation, process_simulation_directory
from aex_tfanet.trust.schemas import TRUST_CLASSES, TRUST_SCORE_COLUMNS
from aex_tfanet.utils.config import AppConfig


def validate_trust_scores(rows: list[dict[str, Any]], node_ids: set[int]) -> None:
    if not rows:
        raise DataValidationError("trust_scores.csv contains no data rows")
    for line, row in enumerate(rows, 2):
        missing = set(TRUST_SCORE_COLUMNS) - set(row)
        if missing:
            raise DataValidationError(f"trust_scores.csv row {line} is missing columns: {sorted(missing)}")
        try:
            stamp = float(row["timestamp"])
            observer, target = int(row["observer_id"]), int(row["target_id"])
        except (TypeError, ValueError) as exc:
            raise DataValidationError(f"trust_scores.csv row {line} has invalid timestamp or node IDs") from exc
        if not math.isfinite(stamp) or observer not in node_ids or target not in node_ids or observer == target:
            raise DataValidationError(f"trust_scores.csv row {line} has an impossible relationship")
        for key in ("direct_trust", "historical_trust", "final_trust"):
            try:
                value = float(row[key])
            except (TypeError, ValueError) as exc:
                raise DataValidationError(f"trust_scores.csv row {line} {key} must be numeric") from exc
            if not math.isfinite(value) or not 0 <= value <= 1:
                raise DataValidationError(f"trust_scores.csv row {line} {key} must be finite and in [0, 1]")
        available = row["indirect_available"] in (True, "True", "true", 1, "1")
        indirect = row["indirect_trust"]
        if available:
            try:
                value = float(indirect)
            except (TypeError, ValueError) as exc:
                raise DataValidationError(f"trust_scores.csv row {line} has missing indirect trust marked available") from exc
            if not math.isfinite(value) or not 0 <= value <= 1:
                raise DataValidationError(f"trust_scores.csv row {line} indirect_trust must be in [0, 1]")
        elif indirect not in (None, "", "null"):
            raise DataValidationError(f"trust_scores.csv row {line} unavailable indirect_trust must be blank")
        if row["classification"] not in TRUST_CLASSES:
            raise DataValidationError(f"trust_scores.csv row {line} has invalid classification")
        if row["indirect_available"] not in (True, False, "True", "False", "true", "false", 1, 0, "1", "0"):
            raise DataValidationError(f"trust_scores.csv row {line} indirect_available must be boolean")


def _recommendations(
    observer: int,
    target: int,
    timestamp: float,
    direct_scores: dict[tuple[int, int], float],
    neighbors: dict[tuple[float, int], set[int]],
) -> list[Recommendation]:
    result = []
    for recommender in neighbors.get((timestamp, observer), set()):
        if recommender == target:
            continue
        observer_opinion = direct_scores.get((observer, recommender))
        recommendation = direct_scores.get((recommender, target))
        if observer_opinion is not None and recommendation is not None:
            result.append(Recommendation(observer_opinion, recommendation))
    return result


def calculate_trust_series(data: ProcessedSimulation, cfg: AppConfig) -> list[TrustScore]:
    """Calculate temporal pair scores using only processed packet/link evidence."""
    trust_cfg = cfg.trust
    counts: dict[tuple[int, int], list[int]] = defaultdict(lambda: [0, 0])
    histories: dict[tuple[int, int], float] = {}
    finals: dict[tuple[int, int], float] = {}
    weights = {
        "direct": trust_cfg.direct_weight,
        "indirect": trust_cfg.indirect_weight,
        "history": trust_cfg.history_weight,
    }
    observations_by_time: dict[float, list] = defaultdict(list)
    for item in data.observations:
        observations_by_time[item.timestamp].append(item)
    scores: list[TrustScore] = []
    for timestamp in sorted(observations_by_time):
        current = sorted(observations_by_time[timestamp], key=lambda x: (x.observer_id, x.target_id))
        for item in current:
            counters = counts[(item.observer_id, item.target_id)]
            counters[0] += item.successful_forwarding
            counters[1] += item.failed_forwarding
        direct_scores = {
            pair: calculate_direct_trust(successes, failures, trust_cfg.prior_success, trust_cfg.prior_failure)
            for pair, (successes, failures) in counts.items()
        }
        pending = []
        for item in current:
            pair = (item.observer_id, item.target_id)
            direct = direct_scores[pair]
            history = update_history(histories.get(pair), direct, trust_cfg.history_lambda)
            if trust_cfg.indirect_enabled:
                recs = _recommendations(item.observer_id, item.target_id, timestamp, direct_scores, data.neighbors)
                indirect, recommender_count = aggregate_recommendations(
                    recs,
                    min_recommender_trust=trust_cfg.min_recommender_trust,
                    min_recommendations=trust_cfg.min_recommendations,
                )
            else:
                indirect, recommender_count = None, 0
            evidence = fuse_trust(
                {"direct": direct, "indirect": indirect, "history": history}, weights
            )
            final = adapt_trust(
                finals.get(pair), evidence,
                decay_rate=trust_cfg.decay_rate,
                recovery_rate=trust_cfg.recovery_rate,
                minimum=trust_cfg.minimum_trust,
                maximum=trust_cfg.maximum_trust,
            )
            classification = classify_trust(
                final,
                highly_trusted=cfg.trust_thresholds.highly_trusted,
                trusted=cfg.trust_thresholds.trusted,
                suspicious=cfg.trust_thresholds.suspicious,
            )
            pending.append(TrustScore(
                timestamp=timestamp,
                observer_id=item.observer_id,
                target_id=item.target_id,
                packets_observed=item.packets_observed,
                successful_forwarding=item.successful_forwarding,
                failed_forwarding=item.failed_forwarding,
                forwarding_ratio=item.forwarding_ratio,
                delivery_observations=item.delivery_observations,
                neighbor_connected=item.neighbor_connected,
                direct_trust=direct,
                indirect_trust=indirect,
                indirect_recommenders=recommender_count,
                historical_trust=history,
                final_trust=final,
                classification=classification,
            ))
            histories[pair] = history
            finals[pair] = final
        scores.extend(pending)
    validate_trust_scores([asdict(item) | {
        "indirect_available": item.indirect_trust is not None,
    } for item in scores], data.node_ids)
    return scores


def write_trust_results(
    input_dir: Path,
    output_dir: Path,
    cfg: AppConfig,
) -> dict[str, Any]:
    """Read Phase 2 traces and persist validated trust time series and summary."""
    data = process_simulation_directory(input_dir)
    scores = calculate_trust_series(data, cfg)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    csv_path = output_dir / "trust_scores.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=TRUST_SCORE_COLUMNS)
        writer.writeheader()
        for score in scores:
            row = asdict(score)
            row["indirect_available"] = score.indirect_trust is not None
            writer.writerow(row)
    # Validate the serialized representation as well, including explicit unavailable fields.
    with csv_path.open(encoding="utf-8", newline="") as stream:
        parsed = list(csv.DictReader(stream))
    validate_trust_scores(parsed, data.node_ids)

    latest_pair: dict[tuple[int, int], TrustScore] = {}
    for score in scores:
        latest_pair[(score.observer_id, score.target_id)] = score
    target_scores: dict[int, list[float]] = defaultdict(list)
    for score in latest_pair.values():
        target_scores[score.target_id].append(score.final_trust)
    target_means = {target: sum(values) / len(values) for target, values in target_scores.items()}
    thresholds = {
        target: classify_trust(
            value,
            highly_trusted=cfg.trust_thresholds.highly_trusted,
            trusted=cfg.trust_thresholds.trusted,
            suspicious=cfg.trust_thresholds.suspicious,
        ) for target, value in target_means.items()
    }
    final_values = [score.final_trust for score in scores]
    trust_config = {
        "direct_alpha": cfg.trust.prior_success,
        "direct_beta": cfg.trust.prior_failure,
        "indirect_enabled": cfg.trust.indirect_enabled,
        "min_recommender_trust": cfg.trust.min_recommender_trust,
        "min_recommendations": cfg.trust.min_recommendations,
        "history_lambda": cfg.trust.history_lambda,
        "weights": {"direct": cfg.trust.direct_weight, "indirect": cfg.trust.indirect_weight, "history": cfg.trust.history_weight},
        "decay_rate": cfg.trust.decay_rate,
        "recovery_rate": cfg.trust.recovery_rate,
        "bounds": {"minimum": cfg.trust.minimum_trust, "maximum": cfg.trust.maximum_trust},
        "thresholds": {"highly_trusted": cfg.trust_thresholds.highly_trusted, "trusted": cfg.trust_thresholds.trusted, "suspicious": cfg.trust_thresholds.suspicious},
    }
    summary = {
        "number_of_nodes": len(data.node_ids),
        "number_of_relationships": len(latest_pair),
        "number_of_score_observations": len(scores),
        "mean_trust": sum(final_values) / len(final_values),
        "minimum_trust": min(final_values),
        "maximum_trust": max(final_values),
        "highly_trusted_nodes": sorted(node for node, label in thresholds.items() if label == "Highly Trusted"),
        "trusted_nodes": sorted(node for node, label in thresholds.items() if label == "Trusted"),
        "suspicious_nodes": sorted(node for node, label in thresholds.items() if label == "Suspicious"),
        "untrusted_nodes": sorted(node for node, label in thresholds.items() if label == "Untrusted / Malicious"),
        "node_aggregation": "mean of each observer's latest final trust for the target; does not replace relational scores",
        "trust_engine_configuration": trust_config,
        "source_simulation": str(Path(input_dir).resolve()),
        "backend_used": data.backend or "not_available",
    }
    (output_dir / "trust_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary
