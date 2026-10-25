"""Causal rolling-window detector over observed FANET forwarding behavior.

Ground-truth labels are deliberately not accepted by :func:`detect_behavior`.
They are accepted only by :func:`evaluate_nodes`, after predictions exist.
"""
from __future__ import annotations

import csv
import json
import math
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Iterable

from aex_tfanet.exceptions import DataValidationError
from aex_tfanet.simulation.fanet import PACKET_COLUMNS, UAV_COLUMNS
from aex_tfanet.trust.processor import process_simulation_directory
from aex_tfanet.trust.schemas import TRUST_SCORE_COLUMNS
from aex_tfanet.utils.config import DetectionConfig

DETECTION_COLUMNS = [
    "timestamp", "node_id", "observations", "recent_successes", "recent_drops",
    "drop_ratio", "final_trust", "trust_classification", "forwarding_ratio",
    "link_stability", "detection_score", "status", "reason",
]


def _rows(path: Path, required: Iterable[str]) -> list[dict[str, str]]:
    if not path.is_file():
        raise DataValidationError(f"Required detection input not found: {path}")
    try:
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if not reader.fieldnames:
                raise DataValidationError(f"{path.name} has no CSV header")
            missing = set(required) - set(reader.fieldnames)
            if missing:
                raise DataValidationError(f"{path.name} missing required columns: {sorted(missing)}")
            values = list(reader)
    except (OSError, UnicodeError, csv.Error) as exc:
        raise DataValidationError(f"Could not read {path.name}: {exc}") from exc
    if not values:
        raise DataValidationError(f"{path.name} contains no data rows")
    if any(None in row for row in values):
        raise DataValidationError(f"{path.name} contains malformed rows")
    return values


def _num(value: str, context: str, *, minimum: float | None = None, maximum: float | None = None) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise DataValidationError(f"{context} must be numeric, got {value!r}") from exc
    if not math.isfinite(result) or (minimum is not None and result < minimum) or (maximum is not None and result > maximum):
        raise DataValidationError(f"{context} is outside its valid range")
    return result


def _id(value: str, context: str) -> int:
    result = _num(value, context, minimum=1)
    if not result.is_integer():
        raise DataValidationError(f"{context} must be an integer")
    return int(result)


def _load_inputs(simulation_dir: Path, trust_csv: Path):
    uavs = _rows(simulation_dir / "uav_events.csv", UAV_COLUMNS)
    packet_rows = _rows(simulation_dir / "packet_events.csv", PACKET_COLUMNS)
    trust_rows = _rows(trust_csv, TRUST_SCORE_COLUMNS)
    node_ticks: dict[tuple[float, int], dict[str, float]] = {}
    nodes: set[int] = set()
    ticks: set[float] = set()
    for line, row in enumerate(uavs, 2):
        t = _num(row["timestamp"], f"uav_events.csv row {line} timestamp", minimum=0)
        node = _id(row["uav_id"], f"uav_events.csv row {line} uav_id")
        if (t, node) in node_ticks:
            raise DataValidationError(f"uav_events.csv has duplicate node {node} at {t}")
        node_ticks[(t, node)] = {
            "forwarding_ratio": _num(row["forwarding_ratio"], f"uav_events.csv row {line} forwarding_ratio", minimum=0, maximum=1),
            "link_stability": _num(row["link_stability"], f"uav_events.csv row {line} link_stability", minimum=0, maximum=1),
        }
        nodes.add(node); ticks.add(t)
    for t in ticks:
        if {n for tt, n in node_ticks if tt == t} != nodes:
            raise DataValidationError(f"uav_events.csv timestamp {t} has an incomplete node set")

    packet_events: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for line, row in enumerate(packet_rows, 2):
        t = _num(row["timestamp"], f"packet_events.csv row {line} timestamp", minimum=0)
        pid = _id(row["packet_id"], f"packet_events.csv row {line} packet_id")
        current = _id(row["current_node"], f"packet_events.csv row {line} current_node")
        action = row["action"].strip()
        if action not in {"generated", "forwarded", "received", "dropped"} or t not in ticks or current not in nodes:
            raise DataValidationError(f"packet_events.csv row {line} has an unknown action, timestamp, or node")
        nxt = row["next_hop"].strip()
        next_hop = _id(nxt, f"packet_events.csv row {line} next_hop") if nxt else None
        packet_events[pid].append({"timestamp": t, "current": current, "next": next_hop, "action": action})

    # Count only outcomes observed at a node that another node actually addressed.
    # A source's no-route drop has no incoming send intent and is excluded.
    outcomes: dict[tuple[float, int], list[int]] = defaultdict(lambda: [0, 0])
    for events in packet_events.values():
        by_node = {e["current"]: e for e in events if e["action"] in {"forwarded", "received", "dropped"}}
        for send in events:
            if send["action"] not in {"generated", "forwarded"} or send["next"] is None:
                continue
            target_event = by_node.get(send["next"])
            if target_event is None or target_event["action"] not in {"forwarded", "received", "dropped"}:
                continue
            bucket = outcomes[(target_event["timestamp"], target_event["current"])]
            bucket[1 if target_event["action"] == "dropped" else 0] += 1

    trust_by_time: dict[float, list[tuple[int, int, float, str]]] = defaultdict(list)
    for line, row in enumerate(trust_rows, 2):
        t = _num(row["timestamp"], f"trust_scores.csv row {line} timestamp", minimum=0)
        observer = _id(row["observer_id"], f"trust_scores.csv row {line} observer_id")
        target = _id(row["target_id"], f"trust_scores.csv row {line} target_id")
        trust = _num(row["final_trust"], f"trust_scores.csv row {line} final_trust", minimum=0, maximum=1)
        classification = row["classification"].strip()
        if classification not in {"Highly Trusted", "Trusted", "Suspicious", "Untrusted / Malicious"}:
            raise DataValidationError(f"trust_scores.csv row {line} has an unknown trust classification")
        if target not in nodes:
            raise DataValidationError(f"trust_scores.csv row {line} references unknown target {target}")
        if observer not in nodes:
            raise DataValidationError(f"trust_scores.csv row {line} references unknown observer {observer}")
        trust_by_time[t].append((observer, target, trust, classification))
    return nodes, sorted(ticks), node_ticks, outcomes, dict(trust_by_time)


def detect_behavior(simulation_dir: Path, trust_csv: Path, config: DetectionConfig) -> list[dict[str, Any]]:
    """Return causal node/time predictions using behavior and trust only."""
    # Reuse Phase 3's strict Phase 2 schema, topology, and packet consistency checks.
    # Its processor does not consume malicious-node metadata.
    process_simulation_directory(Path(simulation_dir), include_backend=False)
    nodes, ticks, node_ticks, outcomes, trust_events = _load_inputs(Path(simulation_dir), Path(trust_csv))
    history: dict[int, deque[tuple[float, int, int]]] = {n: deque() for n in nodes}
    latest_relations: dict[int, dict[int, tuple[float, str]]] = {n: {} for n in nodes}
    event_ticks = sorted(set(ticks) | set(trust_events))
    trust_pointer = 0
    trust_times = sorted(trust_events)
    output: list[dict[str, Any]] = []
    weights = {
        "drop": config.drop_weight,
        "trust": config.trust_weight,
        "forwarding": config.forwarding_weight,
        "instability": config.instability_weight,
    }
    for t in event_ticks:
        while trust_pointer < len(trust_times) and trust_times[trust_pointer] <= t:
            stamp = trust_times[trust_pointer]
            for observer, target, score, cls in trust_events[stamp]:
                latest_relations[target][observer] = (score, cls)
            trust_pointer += 1
        for node in sorted(nodes):
            if (t, node) not in node_ticks:
                continue
            success, drops = outcomes.get((t, node), (0, 0))
            q = history[node]
            if success + drops:
                q.append((t, success, drops))
            while q and q[0][0] < t - config.window_s:
                q.popleft()
            recent_success = sum(item[1] for item in q)
            recent_drops = sum(item[2] for item in q)
            observations = recent_success + recent_drops
            drop_ratio = recent_drops / observations if observations else None
            relation_values = list(latest_relations[node].values())
            trust_score = sum(v[0] for v in relation_values) / len(relation_values) if relation_values else None
            trust_class = max((v[1] for v in relation_values), key=lambda c: sum(vv[1] == c for vv in relation_values)) if relation_values else ""
            uav = node_ticks[(t, node)]
            components: dict[str, float] = {}
            if drop_ratio is not None:
                components["drop"] = drop_ratio
            if trust_score is not None:
                components["trust"] = 1.0 - trust_score
            components["forwarding"] = 1.0 - uav["forwarding_ratio"]
            components["instability"] = 1.0 - uav["link_stability"]
            active_weight = sum(weights[name] for name in components)
            if observations < config.min_observations:
                score = None
                status = "INSUFFICIENT_DATA"
                reason = f"{observations} forwarding outcomes in the {config.window_s:g}s window; need {config.min_observations}"
            elif active_weight <= 0:
                score = None
                status = "INSUFFICIENT_DATA"
                reason = "no weighted evidence features are available"
            else:
                score = sum(components[name] * weights[name] for name in components) / active_weight
                if score >= config.malicious_threshold:
                    status = "MALICIOUS"
                elif score >= config.suspicious_threshold:
                    status = "SUSPICIOUS"
                else:
                    status = "NORMAL"
                top = sorted(components, key=lambda name: (-components[name] * weights[name], name))[:2]
                reason = "; ".join(f"{name} evidence={components[name]:.3f}" for name in top)
            output.append({
                "timestamp": t, "node_id": node, "observations": observations,
                "recent_successes": recent_success, "recent_drops": recent_drops,
                "drop_ratio": drop_ratio, "final_trust": trust_score,
                "trust_classification": trust_class, "forwarding_ratio": uav["forwarding_ratio"],
                "link_stability": uav["link_stability"], "detection_score": score,
                "status": status, "reason": reason,
            })
    if not output:
        raise DataValidationError("No detector rows could be built from the supplied inputs")
    return output


def evaluate_nodes(predictions: list[dict[str, Any]], malicious_node_ids: set[int]) -> dict[str, Any]:
    """Evaluate node-level alerts using labels supplied by the caller only here."""
    nodes = sorted({int(row["node_id"]) for row in predictions})
    by_node: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in predictions:
        by_node[int(row["node_id"])].append(row)
    tp = tn = fp = fn = 0
    for node in nodes:
        predicted_positive = any(
            row["status"] in {"SUSPICIOUS", "MALICIOUS"} for row in by_node[node]
        )
        actual_positive = node in malicious_node_ids
        if predicted_positive and actual_positive: tp += 1
        elif predicted_positive: fp += 1
        elif actual_positive: fn += 1
        else: tn += 1
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and precision + recall else
          (0.0 if recall == 0.0 else None))
    return {
        "evaluation_unit": "node; positive prediction means any SUSPICIOUS or MALICIOUS window",
        "node_count": len(nodes), "actual_positive_nodes": len(malicious_node_ids & set(nodes)),
        "predicted_positive_nodes": tp + fp,
        "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "precision": precision, "recall": recall, "F1": f1,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "false_negative_rate": fn / (fn + tp) if fn + tp else None,
        "confusion_matrix": {"actual_positive": {"predicted_positive": tp, "predicted_negative": fn},
                             "actual_negative": {"predicted_positive": fp, "predicted_negative": tn}},
        "class_counts": {"actual_positive": tp + fn, "actual_negative": tn + fp,
                         "predicted_positive": tp + fp, "predicted_negative": tn + fn},
        "ground_truth_source": "simulation summary metadata; used only by this evaluator",
    }


def write_detection_results(predictions: list[dict[str, Any]], output_dir: Path,
                            evaluation: dict[str, Any] | None = None,
                            config: DetectionConfig | None = None) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "detection_events.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=DETECTION_COLUMNS)
        writer.writeheader()
        for row in predictions:
            writer.writerow({key: "" if row.get(key) is None else row.get(key) for key in DETECTION_COLUMNS})
    counts: dict[str, int] = defaultdict(int)
    for row in predictions:
        counts[row["status"]] += 1
    summary = {
        "detector": "deterministic_behavioral_v1",
        "prediction_inputs": ["observed packet forwarding outcomes", "causal Phase 3 trust history", "forwarding ratio", "link stability"],
        "prediction_excludes_ground_truth_labels": True,
        "row_count": len(predictions), "node_count": len({row["node_id"] for row in predictions}),
        "status_counts": dict(sorted(counts.items())),
        "evaluation": "available" if evaluation is not None else "not evaluated: no simulation ground-truth metadata",
    }
    if config is not None:
        summary["detector_config"] = {
            "suspicious_threshold": config.suspicious_threshold,
            "malicious_threshold": config.malicious_threshold,
            "min_observations": config.min_observations,
            "window_s": config.window_s,
            "weights": {"drop": config.drop_weight, "trust": config.trust_weight,
                        "forwarding": config.forwarding_weight, "instability": config.instability_weight},
        }
    (output_dir / "detection_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if evaluation is not None:
        (output_dir / "detection_metrics.json").write_text(json.dumps(evaluation, indent=2) + "\n", encoding="utf-8")
    return summary
