"""Deterministic simplified Python FANET model; it is not an NS-3 simulator."""
from __future__ import annotations

import csv
import json
import math
import random
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import yaml

from aex_tfanet.exceptions import DataValidationError, EnvironmentError, SimulationError
from aex_tfanet.routing import select_route
from aex_tfanet.utils.config import AppConfig, load_yaml
from aex_tfanet.utils.environment import probe_environment
from aex_tfanet.utils.paths import project_root

BACKEND_LABEL = "Simplified Python FANET Model — NOT NS-3"
UAV_COLUMNS = ["timestamp", "uav_id", "position_x", "position_y", "mobility_mps", "neighbors", "packets_generated", "packets_sent", "packets_forwarded", "packets_received", "packets_dropped", "forwarding_ratio", "delivery_ratio", "link_stability"]
NEIGHBOR_COLUMNS = ["timestamp", "uav_id", "neighbor_id", "distance", "connected"]
PACKET_COLUMNS = ["timestamp", "packet_id", "source", "destination", "current_node", "next_hop", "action"]
ROUTE_COLUMNS = ["timestamp", "packet_id", "source", "destination", "routing_mode", "selected_path", "route_cost", "mean_intermediate_trust", "alternative_count", "hop_count"]


class SimulationBackend(Protocol):
    """Common backend boundary for Phase 2 event data producers."""

    name: str

    def run(self, cfg: AppConfig, output_dir: Path, overlay: dict[str, Any]) -> dict[str, Any]: ...

@dataclass
class UAV:
    uav_id: int
    x: float
    y: float
    target_x: float
    target_y: float
    speed: float


def validate_uav_events(rows: list[dict[str, Any]]) -> None:
    _validate_rows(rows, UAV_COLUMNS, "uav_events")
    for i, row in enumerate(rows, 2):
        for key in ("timestamp", "uav_id", "position_x", "position_y", "mobility_mps", "packets_generated", "packets_sent", "packets_forwarded", "packets_received", "packets_dropped", "forwarding_ratio", "delivery_ratio", "link_stability"):
            value = row[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise DataValidationError(f"uav_events row {i}: {key} must be finite numeric data")
        if row["timestamp"] < 0 or row["uav_id"] < 1 or not float(row["uav_id"]).is_integer():
            raise DataValidationError(f"uav_events row {i}: timestamp and UAV ID must be non-negative/positive")
        if any(row[k] < 0 for k in ("packets_generated", "packets_sent", "packets_forwarded", "packets_received", "packets_dropped")):
            raise DataValidationError(f"uav_events row {i}: packet counts must be >= 0")
        if any(not 0 <= row[k] <= 1 for k in ("forwarding_ratio", "delivery_ratio", "link_stability")):
            raise DataValidationError(f"uav_events row {i}: ratios must be in [0, 1]")
        if not isinstance(row["neighbors"], int) or row["neighbors"] < 0:
            raise DataValidationError(f"uav_events row {i}: neighbors must be a non-negative integer")


def validate_neighbor_events(rows: list[dict[str, Any]]) -> None:
    _validate_rows(rows, NEIGHBOR_COLUMNS, "neighbor_events")
    for i, row in enumerate(rows, 2):
        for key in ("timestamp", "uav_id", "neighbor_id", "distance"):
            value = row[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise DataValidationError(f"neighbor_events row {i}: {key} must be finite numeric data")
        if row["timestamp"] < 0 or row["distance"] < 0 or row["uav_id"] < 1 or row["neighbor_id"] < 1:
            raise DataValidationError(f"neighbor_events row {i}: invalid timestamp, distance, or UAV ID")
        if not isinstance(row["connected"], bool):
            raise DataValidationError(f"neighbor_events row {i}: connected must be boolean")


def validate_packet_events(rows: list[dict[str, Any]]) -> None:
    _validate_rows(rows, PACKET_COLUMNS, "packet_events")
    allowed_actions = {"generated", "forwarded", "received", "dropped"}
    for i, row in enumerate(rows, 2):
        for key in ("timestamp", "packet_id", "source", "destination", "current_node"):
            value = row[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise DataValidationError(f"packet_events row {i}: {key} must be finite numeric data")
        if row["timestamp"] < 0 or row["packet_id"] < 1 or any(row[k] < 1 for k in ("source", "destination", "current_node")):
            raise DataValidationError(f"packet_events row {i}: invalid timestamp, packet ID, or UAV ID")
        if row["action"] not in allowed_actions:
            raise DataValidationError(f"packet_events row {i}: unsupported action {row['action']!r}")
        if row["next_hop"] != "" and (not str(row["next_hop"]).isdigit() or int(row["next_hop"]) < 1):
            raise DataValidationError(f"packet_events row {i}: next_hop must be an empty value or positive UAV ID")


def _validate_rows(rows: list[dict[str, Any]], columns: list[str], name: str) -> None:
    if not rows:
        raise DataValidationError(f"{name} contains no data rows")
    missing = set(columns) - set(rows[0])
    if missing:
        raise DataValidationError(f"{name} missing required columns: {sorted(missing)}")
    for i, row in enumerate(rows, 2):
        if set(columns) - set(row):
            raise DataValidationError(f"{name} row {i} is malformed")


def _path(graph: dict[int, set[int]], source: int, destination: int) -> list[int] | None:
    queue = deque([source]); previous = {source: None}
    while queue:
        node = queue.popleft()
        if node == destination:
            result = [node]
            while previous[result[-1]] is not None:
                result.append(previous[result[-1]])
            return list(reversed(result))
        for neighbor in sorted(graph[node]):
            if neighbor not in previous:
                previous[neighbor] = node; queue.append(neighbor)
    return None


def _move(uav: UAV, dt: float, width: float, height: float) -> None:
    dx, dy = uav.target_x-uav.x, uav.target_y-uav.y
    distance = math.hypot(dx, dy)
    if distance <= uav.speed * dt or distance == 0:
        uav.x, uav.y = uav.target_x, uav.target_y
    else:
        fraction = uav.speed * dt / distance
        uav.x += dx*fraction; uav.y += dy*fraction


def run_python_simulation(cfg: AppConfig, output_dir: Path, overlay: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run reproducible mobility/topology/packet events and write validated CSVs."""
    sim = cfg.simulation
    dt = float(getattr(sim, "time_step_s", 1.0))
    if dt <= 0 or sim.duration_s <= 0 or sim.packet_interval_s <= 0:
        raise SimulationError("time_step_s, duration_s, and packet_interval_s must be > 0")
    raw = overlay if overlay is not None else (
        load_yaml(cfg.source_path) if cfg.source_path.name != "config.yaml" else {}
    )
    mobility = raw.get("mobility", {})
    model = mobility.get("model", cfg.mobility.model)
    if model not in {"random_waypoint", "bounded_random"}:
        raise SimulationError(f"Unsupported mobility model: {model}")
    min_speed = float(mobility.get("min_speed_mps", cfg.mobility.min_speed_mps)); max_speed = float(mobility.get("max_speed_mps", cfg.mobility.max_speed_mps))
    attack = raw.get("attack", {})
    attack_type = attack.get("type", "packet_drop") if attack else None
    enabled = bool(attack.get("enabled", bool(attack))) if attack else False
    malicious = {int(n) for n in attack.get("malicious_nodes", ([attack["uav_id"]] if "uav_id" in attack else []))} if enabled else set()
    probability = float(attack.get("drop_probability", 0.0)) if enabled else 0.0
    if attack_type == "blackhole" and enabled:
        configured_probability = attack.get("drop_probability")
        if configured_probability not in (None, 1, 1.0):
            raise SimulationError("blackhole is deterministic; omit drop_probability or set it to 1.0")
        probability = 1.0
    elif attack_type == "packet_drop":
        if not 0 <= probability <= 1:
            raise SimulationError("packet_drop drop_probability must be in [0, 1]")
    elif enabled:
        raise SimulationError("attack must be packet_drop or blackhole")
    if any(n < 1 or n > sim.num_uavs for n in malicious):
        raise SimulationError("malicious node IDs must be within the configured UAV range")
    rng = random.Random(sim.seed)
    traffic_rng = random.Random(sim.seed ^ 0x5A17)
    attack_rng = random.Random(sim.seed ^ 0xA77AC)
    uavs = {}
    for i in range(1, sim.num_uavs+1):
        x, y = rng.uniform(0, sim.area_x_m), rng.uniform(0, sim.area_y_m)
        uavs[i] = UAV(i, x, y, rng.uniform(0, sim.area_x_m), rng.uniform(0, sim.area_y_m), rng.uniform(min_speed, max_speed))
    ticks = max(1, math.ceil(sim.duration_s / dt))
    prev_links: dict[int, set[int]] = {i:set() for i in uavs}
    totals = {i: defaultdict(int) for i in uavs}; rows=[]; neighbors=[]; packets=[]; route_rows=[]
    relay_successes = defaultdict(int); relay_failures = defaultdict(int)
    last_route_by_flow: dict[tuple[int, int], tuple[int, ...]] = {}; route_changes = 0
    generated=delivered=dropped=forwarding=0; packet_id=0
    for tick in range(ticks):
        timestamp = round(tick*dt, 6)
        if tick:
            for u in uavs.values():
                _move(u, dt, sim.area_x_m, sim.area_y_m)
                if (u.x, u.y)==(u.target_x,u.target_y):
                    u.target_x=rng.uniform(0,sim.area_x_m); u.target_y=rng.uniform(0,sim.area_y_m)
                    u.speed=rng.uniform(min_speed,max_speed)
        graph={i:set() for i in uavs}
        for i in range(1,sim.num_uavs+1):
            for j in range(i+1,sim.num_uavs+1):
                a,b=uavs[i],uavs[j]; dist=math.hypot(a.x-b.x,a.y-b.y)
                if dist <= sim.communication_range_m:
                    graph[i].add(j); graph[j].add(i)
                neighbors.append({"timestamp":timestamp,"uav_id":i,"neighbor_id":j,"distance":round(dist,6),"connected":dist<=sim.communication_range_m})
                neighbors.append({"timestamp":timestamp,"uav_id":j,"neighbor_id":i,"distance":round(dist,6),"connected":dist<=sim.communication_range_m})
        node_stability = {
            i: (len(graph[i] & prev_links[i]) / len(graph[i] | prev_links[i]) if graph[i] | prev_links[i] else 1.0)
            for i in uavs
        }
        edge_stability = {(i, j): min(node_stability[i], node_stability[j]) for i in graph for j in graph[i]}
        for i,u in uavs.items():
            # Generate at configured packet interval; destination varies deterministically.
            if timestamp < sim.duration_s and tick % max(1,round(sim.packet_interval_s/dt)) == 0:
                dest=traffic_rng.choice([n for n in uavs if n!=i]); packet_id+=1; generated+=1; totals[i]["generated"]+=1
                generated_event = dict(timestamp=timestamp,packet_id=packet_id,source=i,destination=dest,current_node=i,next_hop="",action="generated")
                packets.append(generated_event)
                trust_estimates = {
                    node: (relay_successes[node] + 1) / (relay_successes[node] + relay_failures[node] + 2)
                    for node in uavs
                }
                decision = select_route(
                    graph, i, dest, mode=cfg.routing.mode, trust=trust_estimates,
                    link_stability=edge_stability,
                    weights={"hop": cfg.routing.hop_weight, "trust": cfg.routing.trust_weight,
                             "link": cfg.routing.link_weight, "delivery": cfg.routing.delivery_weight},
                    alternatives=3,
                )
                route = list(decision.selected.path) if decision.selected is not None else None
                path_text = ">".join(map(str, route)) if route else ""
                route_rows.append({
                    "timestamp": timestamp, "packet_id": packet_id, "source": i, "destination": dest,
                    "routing_mode": cfg.routing.mode, "selected_path": path_text,
                    "route_cost": decision.selected.cost if decision.selected else "",
                    "mean_intermediate_trust": decision.mean_intermediate_trust if decision.mean_intermediate_trust is not None else "",
                    "alternative_count": len(decision.alternatives),
                    "hop_count": len(route) - 1 if route else "",
                })
                if route:
                    flow = (i, dest)
                    if flow in last_route_by_flow and last_route_by_flow[flow] != tuple(route):
                        route_changes += 1
                    last_route_by_flow[flow] = tuple(route)
                if route is None:
                    dropped+=1; totals[i]["dropped"]+=1
                    packets.append(dict(timestamp=timestamp,packet_id=packet_id,source=i,destination=dest,current_node=i,next_hop="",action="dropped"))
                    continue
                # Record the actual first hop so downstream observers can associate
                # the next node's forwarding/drop outcome with this transmission.
                generated_event["next_hop"] = route[1]
                success=True
                for k,node in enumerate(route[:-1]):
                    nxt=route[k+1]; totals[node]["sent"]+=1
                    if k>0 and node in malicious and (
                        attack_type == "blackhole" or attack_rng.random() < probability
                    ):
                        relay_failures[node] += 1
                        dropped+=1; totals[node]["dropped"]+=1; success=False
                        packets.append(dict(timestamp=timestamp,packet_id=packet_id,source=i,destination=dest,current_node=node,next_hop=nxt,action="dropped")); break
                    if k>0:
                        relay_successes[node] += 1
                        totals[node]["forwarded"]+=1; forwarding+=1
                        packets.append(dict(timestamp=timestamp,packet_id=packet_id,source=i,destination=dest,current_node=node,next_hop=nxt,action="forwarded"))
                if success:
                    delivered+=1; totals[dest]["received"]+=1
                    totals[i]["delivered"]+=1
                    packets.append(dict(timestamp=timestamp,packet_id=packet_id,source=i,destination=dest,current_node=dest,next_hop="",action="received"))
        for i,u in uavs.items():
            t=totals[i]; sent=t["sent"]; observed=t["forwarded"]+t["dropped"]
            rows.append(dict(timestamp=timestamp,uav_id=i,position_x=round(u.x,6),position_y=round(u.y,6),mobility_mps=round(u.speed,6),neighbors=len(graph[i]),packets_generated=t["generated"],packets_sent=sent,packets_forwarded=t["forwarded"],packets_received=t["received"],packets_dropped=t["dropped"],forwarding_ratio=round(t["forwarded"]/observed,6) if observed else 1.0,delivery_ratio=round(t["delivered"]/max(1,t["generated"]),6),link_stability=round(node_stability[i],6)))
            prev_links[i]=graph[i]
    validate_uav_events(rows)
    validate_neighbor_events(neighbors)
    validate_packet_events(packets)
    output_dir.mkdir(parents=True,exist_ok=True)
    for name,data,columns in (("uav_events.csv",rows,UAV_COLUMNS),("neighbor_events.csv",neighbors,NEIGHBOR_COLUMNS),("packet_events.csv",packets,PACKET_COLUMNS),("route_decisions.csv",route_rows,ROUTE_COLUMNS)):
        with (output_dir/name).open("w",newline="",encoding="utf-8") as f:
            writer=csv.DictWriter(f,fieldnames=columns); writer.writeheader(); writer.writerows(data)
    summary={"backend":BACKEND_LABEL,"num_uavs":sim.num_uavs,"simulation_duration_s":sim.duration_s,"time_step_s":dt,"packet_size_bytes":sim.packet_size_bytes,"total_packets_generated":generated,"total_packets_delivered":delivered,"total_packets_dropped":dropped,"packet_delivery_ratio":delivered/generated if generated else 0.0,"packet_loss_ratio":dropped/generated if generated else 0.0,"average_delay_s":None,"total_forwarding_events":forwarding,"routing_mode":cfg.routing.mode,"route_decisions":len(route_rows),"route_changes":route_changes,"malicious_nodes":sorted(malicious),"attack_type":attack_type if enabled else None,"drop_probability":probability if enabled else 0.0,"random_seed":sim.seed,"mobility_model":model}
    (output_dir/"summary.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
    return summary


def run_ns3(cfg: AppConfig, output_dir: Path) -> dict[str, Any]:
    report=probe_environment(cfg.simulation.ns3.install_path)
    if not report.ns3_available or not __import__("shutil").which("ns3"):
        raise EnvironmentError("NS-3 unavailable")
    raise SimulationError("NS-3 is detected, but this source-only NS-3 backend has not yet been validated for this installation; no results were generated.")


class PythonFANETBackend:
    name = "python"

    def run(self, cfg: AppConfig, output_dir: Path, overlay: dict[str, Any]) -> dict[str, Any]:
        return run_python_simulation(cfg, output_dir, overlay)


class NS3Backend:
    name = "ns3"

    def run(self, cfg: AppConfig, output_dir: Path, overlay: dict[str, Any]) -> dict[str, Any]:
        return run_ns3(cfg, output_dir)


def run_simulation(config_path: Path | None, backend: str, output_dir: Path | None = None) -> Path:
    from datetime import datetime, timezone
    from aex_tfanet.utils.config import load_config
    root=project_root(); overlay_path=Path(config_path) if config_path else None
    cfg=load_config(overlay=overlay_path) if overlay_path else load_config()
    raw=load_yaml(overlay_path) if overlay_path else {}
    if backend == "auto":
        if probe_environment(cfg.simulation.ns3.install_path).ns3_available:
            backend="ns3"
        else:
            raise EnvironmentError("NS-3 unavailable. Select --backend python explicitly to run the simplified Python FANET model.")
    name=(overlay_path.stem if overlay_path else "simulation")
    stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out=output_dir or (cfg.experiments.output_directory/f"{name}_{stamp}")
    sim_dir=out/"simulation"; sim_dir.mkdir(parents=True,exist_ok=False)
    (out/"config.yaml").write_text(yaml.safe_dump(raw or {"simulation":{"seed":cfg.simulation.seed}},sort_keys=False),encoding="utf-8")
    (out/"environment.json").write_text(json.dumps(probe_environment(cfg.simulation.ns3.install_path).to_dict(),indent=2),encoding="utf-8")
    backends: dict[str, SimulationBackend] = {
        "python": PythonFANETBackend(),
        "ns3": NS3Backend(),
    }
    selected = backends.get(backend)
    if selected is None:
        raise SimulationError(f"Unknown backend: {backend}")
    summary=selected.run(cfg,sim_dir,raw)
    (out/"STATUS.txt").write_text(f"Simulation completed using {summary['backend']}\n",encoding="utf-8")
    return out
