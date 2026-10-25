"""Validate Phase 2 CSVs and derive only observed directed forwarding outcomes."""
from __future__ import annotations

import csv
import json
import math
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aex_tfanet.exceptions import DataValidationError
from aex_tfanet.simulation.fanet import NEIGHBOR_COLUMNS, PACKET_COLUMNS, UAV_COLUMNS
from aex_tfanet.trust.models import TrustObservation


@dataclass(frozen=True)
class ProcessedSimulation:
    node_ids: set[int]
    timestamps: set[float]
    observations: list[TrustObservation]
    neighbors: dict[tuple[float, int], set[int]]
    backend: str | None


def _load_rows(path: Path, required: list[str], *, allow_empty: set[str] | None = None) -> list[dict[str, str]]:
    if not path.is_file():
        raise DataValidationError(f"Required simulation input not found: {path}")
    try:
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames is None:
                raise DataValidationError(f"{path.name} has no CSV header")
            if len(reader.fieldnames) != len(set(reader.fieldnames)):
                raise DataValidationError(f"{path.name} contains duplicate column names")
            missing = set(required) - set(reader.fieldnames)
            if missing:
                raise DataValidationError(f"{path.name} missing required columns: {sorted(missing)}")
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error) as exc:
        raise DataValidationError(f"Could not read {path.name}: {exc}") from exc
    if not rows:
        raise DataValidationError(f"{path.name} contains no data rows")
    for line, row in enumerate(rows, 2):
        if None in row or any(row.get(col) is None for col in required):
            raise DataValidationError(f"{path.name} row {line} is malformed")
        allowed_empty = allow_empty or set()
        if any(row.get(col, "").strip() == "" for col in required if col not in allowed_empty):
            raise DataValidationError(f"{path.name} row {line} has an empty required value")
    return rows


def _number(value: str, context: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise DataValidationError(f"{context} must be numeric, got {value!r}") from exc
    if not math.isfinite(result):
        raise DataValidationError(f"{context} must be finite")
    return result


def _integer(value: str, context: str, *, minimum: int = 0) -> int:
    number = _number(value, context)
    if not number.is_integer() or number < minimum:
        raise DataValidationError(f"{context} must be an integer >= {minimum}")
    return int(number)


def _read_nodes(path: Path) -> tuple[set[int], set[float]]:
    rows = _load_rows(path, UAV_COLUMNS)
    node_ids: set[int] = set()
    timestamps: set[float] = set()
    tick_nodes: dict[float, set[int]] = defaultdict(set)
    numeric = ("position_x", "position_y", "mobility_mps", "forwarding_ratio", "delivery_ratio", "link_stability")
    counters = ("neighbors", "packets_generated", "packets_sent", "packets_forwarded", "packets_received", "packets_dropped")
    for line, row in enumerate(rows, 2):
        stamp = _number(row["timestamp"], f"uav_events.csv row {line} timestamp")
        if stamp < 0:
            raise DataValidationError(f"uav_events.csv row {line} timestamp must be >= 0")
        node = _integer(row["uav_id"], f"uav_events.csv row {line} uav_id", minimum=1)
        timestamps.add(stamp); node_ids.add(node)
        if node in tick_nodes[stamp]:
            raise DataValidationError(f"uav_events.csv has duplicate UAV {node} at timestamp {stamp}")
        tick_nodes[stamp].add(node)
        for key in numeric:
            value = _number(row[key], f"uav_events.csv row {line} {key}")
            if key.endswith("ratio") or key == "link_stability":
                if not 0 <= value <= 1:
                    raise DataValidationError(f"uav_events.csv row {line} {key} must be in [0, 1]")
            elif key == "mobility_mps" and value < 0:
                raise DataValidationError(f"uav_events.csv row {line} {key} must be >= 0")
        for key in counters:
            _integer(row[key], f"uav_events.csv row {line} {key}")
    if not node_ids or not timestamps:
        raise DataValidationError("uav_events.csv contains no usable nodes or timestamps")
    expected = len(node_ids)
    for stamp, present in tick_nodes.items():
        if len(present) != expected:
            raise DataValidationError(f"uav_events.csv timestamp {stamp} is missing UAV rows")
    return node_ids, timestamps


def _read_neighbors(path: Path, node_ids: set[int], timestamps: set[float]) -> dict[tuple[float, int], set[int]]:
    rows = _load_rows(path, NEIGHBOR_COLUMNS)
    links: dict[tuple[float, int, int], bool] = {}
    adjacency: dict[tuple[float, int], set[int]] = defaultdict(set)
    for line, row in enumerate(rows, 2):
        stamp = _number(row["timestamp"], f"neighbor_events.csv row {line} timestamp")
        if stamp < 0:
            raise DataValidationError(f"neighbor_events.csv row {line} timestamp must be >= 0")
        observer = _integer(row["uav_id"], f"neighbor_events.csv row {line} uav_id", minimum=1)
        target = _integer(row["neighbor_id"], f"neighbor_events.csv row {line} neighbor_id", minimum=1)
        distance = _number(row["distance"], f"neighbor_events.csv row {line} distance")
        connected_text = row["connected"].strip().lower()
        if connected_text not in {"true", "false"}:
            raise DataValidationError(f"neighbor_events.csv row {line} connected must be true/false")
        if stamp not in timestamps or observer not in node_ids or target not in node_ids:
            raise DataValidationError(f"neighbor_events.csv row {line} references an unknown timestamp or UAV")
        if observer == target or distance < 0:
            raise DataValidationError(f"neighbor_events.csv row {line} has an impossible link")
        key = (stamp, observer, target)
        if key in links:
            raise DataValidationError(f"neighbor_events.csv contains duplicate directed link {key}")
        connected = connected_text == "true"
        links[key] = connected
        if connected:
            adjacency[(stamp, observer)].add(target)
    for stamp, observer, target in links:
        reverse = (stamp, target, observer)
        if reverse not in links or links[reverse] != links[(stamp, observer, target)]:
            raise DataValidationError(f"neighbor_events.csv has a missing or inconsistent reciprocal link at {stamp}: {observer}<->{target}")
    return adjacency


def _read_packets(path: Path, node_ids: set[int], timestamps: set[float]) -> dict[int, list[dict[str, Any]]]:
    rows = _load_rows(path, PACKET_COLUMNS, allow_empty={"next_hop"})
    grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
    seen_events: set[tuple[int, str, int]] = set()
    allowed = {"generated", "forwarded", "received", "dropped"}
    packet_meta: dict[int, tuple[float, int, int]] = {}
    for line, row in enumerate(rows, 2):
        stamp = _number(row["timestamp"], f"packet_events.csv row {line} timestamp")
        if stamp < 0:
            raise DataValidationError(f"packet_events.csv row {line} timestamp must be >= 0")
        packet_id = _integer(row["packet_id"], f"packet_events.csv row {line} packet_id", minimum=1)
        source = _integer(row["source"], f"packet_events.csv row {line} source", minimum=1)
        destination = _integer(row["destination"], f"packet_events.csv row {line} destination", minimum=1)
        current = _integer(row["current_node"], f"packet_events.csv row {line} current_node", minimum=1)
        nxt = _integer(row["next_hop"], f"packet_events.csv row {line} next_hop", minimum=1) if row["next_hop"].strip() else None
        action = row["action"].strip()
        if action not in allowed or stamp not in timestamps or any(n not in node_ids for n in (source, destination, current)):
            raise DataValidationError(f"packet_events.csv row {line} has an unknown action, timestamp, or UAV")
        if nxt is not None and nxt not in node_ids:
            raise DataValidationError(f"packet_events.csv row {line} next_hop is an unknown UAV")
        if source == destination or (action == "generated" and current != source) or (action == "received" and current != destination):
            raise DataValidationError(f"packet_events.csv row {line} has an impossible source/destination relationship")
        meta = (stamp, source, destination)
        if packet_id in packet_meta and packet_meta[packet_id] != meta:
            raise DataValidationError(f"packet_events.csv packet {packet_id} has inconsistent identity fields")
        packet_meta[packet_id] = meta
        duplicate_key = (packet_id, action, current)
        if duplicate_key in seen_events:
            raise DataValidationError(f"packet_events.csv contains a duplicate event: {duplicate_key}")
        seen_events.add(duplicate_key)
        grouped[packet_id].append({"timestamp": stamp, "source": source, "destination": destination, "current_node": current, "next_hop": nxt, "action": action})
    if not grouped:
        raise DataValidationError("packet_events.csv contains no packet data")
    for packet_id, events in grouped.items():
        if sum(event["action"] == "generated" for event in events) != 1:
            raise DataValidationError(f"packet_events.csv packet {packet_id} must have exactly one generated event")
        outcomes = [(event["current_node"], event["action"]) for event in events if event["action"] in {"forwarded", "received", "dropped"}]
        if len({node for node, _ in outcomes}) != len(outcomes):
            raise DataValidationError(f"packet_events.csv packet {packet_id} has conflicting outcomes for one node")
    return grouped


def process_simulation_directory(input_dir: Path, *, include_backend: bool = True) -> ProcessedSimulation:
    """Convert actual CSV send/outcome events into directed temporal observations."""
    input_dir = Path(input_dir)
    node_ids, timestamps = _read_nodes(input_dir / "uav_events.csv")
    adjacency = _read_neighbors(input_dir / "neighbor_events.csv", node_ids, timestamps)
    packets = _read_packets(input_dir / "packet_events.csv", node_ids, timestamps)
    counts: dict[tuple[float, int, int], dict[str, int]] = defaultdict(lambda: {"success": 0, "failure": 0, "delivery": 0})
    for packet_id, events in packets.items():
        outcomes = {event["current_node"]: event["action"] for event in events if event["action"] in {"forwarded", "received", "dropped"}}
        for send in events:
            if send["action"] not in {"generated", "forwarded"} or send["next_hop"] is None:
                continue
            observer, target, stamp = send["current_node"], send["next_hop"], send["timestamp"]
            if observer == target:
                raise DataValidationError(f"packet {packet_id} contains a self-link")
            if target not in adjacency.get((stamp, observer), set()):
                raise DataValidationError(f"packet {packet_id} sends over an unobserved/disconnected link {observer}->{target}")
            outcome = outcomes.get(target)
            if outcome not in {"forwarded", "received", "dropped"}:
                continue
            bucket = counts[(stamp, observer, target)]
            if outcome == "dropped":
                bucket["failure"] += 1
            else:
                bucket["success"] += 1
                bucket["delivery"] += int(outcome == "received")
    observations = []
    for (stamp, observer, target), values in sorted(counts.items()):
        successes, failures = values["success"], values["failure"]
        total = successes + failures
        if total == 0:
            continue
        observations.append(TrustObservation(
            timestamp=stamp, observer_id=observer, target_id=target,
            packets_observed=total, successful_forwarding=successes,
            failed_forwarding=failures, forwarding_ratio=successes / total,
            delivery_observations=values["delivery"], neighbor_connected=True,
        ))
    if not observations:
        raise DataValidationError("No observer-target forwarding outcomes can be derived from the packet trace")
    backend = None
    if include_backend:
        try:
            summary_path = input_dir / "summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.is_file() else {}
        except (OSError, json.JSONDecodeError) as exc:
            raise DataValidationError(f"Invalid simulation summary.json: {exc}") from exc
        backend = summary.get("backend") if isinstance(summary, dict) else None
    return ProcessedSimulation(node_ids, timestamps, observations, adjacency, backend)
