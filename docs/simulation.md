# Phase 2 simulation

AEX-TFANET separates data generation behind simulation backends. The Python implementation writes the shared CSV contract. NS-3 remains the intended research backend and is not substituted by Python when absent.

## Run

```powershell
python -m aex_tfanet simulate --config experiments/configs/normal.yaml --backend python
python -m aex_tfanet simulate --config experiments/configs/packet_drop.yaml --backend python
python -m aex_tfanet simulate --config experiments/configs/normal.yaml --backend ns3
```

`--backend auto` selects NS-3 only when it is detected. If it is unavailable, the command reports `NS-3 unavailable` and asks for explicit `--backend python`. The Python CSV summary identifies its backend as **Simplified Python FANET Model — NOT NS-3**. Each run gets a new `results/<scenario>_<UTC-id>/simulation/` directory.

## Backends

### NS-3

NS-3 is the intended research-grade network simulator. `simulation/ns3/` contains a starter C++ scratch program and setup notes. NS-3 is not installed in the current environment, so the C++ source has not been compiled or validated, and this release does not claim an operational NS-3 backend. No NS-3 result files are generated when NS-3 is missing or the backend is unvalidated.

### Simplified Python FANET Model — NOT NS-3

This lightweight discrete-time model supports development, demonstrations, reproducibility, and future trust/routing work on machines without NS-3. It does not model the wireless PHY/MAC, interference, propagation, energy, or protocol retransmissions, so its metrics are not substitutes for NS-3 results.

- UAVs move in a bounded 2D area using seeded random-waypoint motion.
- An undirected link exists when Euclidean distance is within `communication_range_m`; the graph is rebuilt each timestep.
- Packets are generated at the configured interval. A deterministic breadth-first route is found over the current graph; no route means a packet drop. Reachable packets are delivered hop by hop within the timestep.
- A configured malicious relay probabilistically drops packets it is asked to forward. Source and destination endpoints are not treated as forwarding relays.
- `attack.type: blackhole` implements deterministic all-drop behavior at configured transit relays. The same actual-received-packet rule applies; source and destination endpoints remain unaffected. No attack events are created in the absence of an incoming route.
- The current research configuration uses a 200 m communication range. This was selected through a normal-traffic sensitivity study on seeds 42–61: it increased UAV 7's mean relay opportunities from 18.85 to 41.70 per 1,000 generated packets while retaining 95.03% mean PDR. This is a topology parameter choice, not a detector adjustment; the 250 m historical Phase 4 results remain preserved.
- Complexity per time step is O(N²) for link discovery plus O(P(V+E)) for generated packets and BFS routing. This is suitable for the default 10–50 UAV development scenarios.
- The current model is 2D; `area_z_m` and packet size are carried by project configuration but do not affect propagation or delay.

## Configuration

The normal baseline is `experiments/configs/normal.yaml`. `experiments/configs/packet_drop.yaml` configures probabilistic dropping, and `experiments/configs/blackhole.yaml` configures deterministic blackhole behavior. `experiments/configs/baseline.yaml` and `experiments/configs/trust_aware.yaml` select routing policies. Shared settings are inherited from `config.yaml`. Use `attack.enabled`, `attack.type`, `attack.malicious_nodes`, and (for `packet_drop`) `attack.drop_probability` to control the attack. A blackhole must omit drop probability or set it to 1.0. Set `simulation.seed` to reproduce mobility, destinations, and attack decisions.

## CSV contract

All event CSVs have a header and use scalar values; neighbour sets are represented by a count in `uav_events.csv`, with individual links in `neighbor_events.csv`.

- `uav_events.csv`: timestamp, UAV ID, position, speed, neighbour count, per-UAV packet counters, forwarding/delivery ratios, and link stability (Jaccard similarity of consecutive neighbour sets).
- `neighbor_events.csv`: one directed row per node pair and timestep with distance and connected flag.
- `packet_events.csv`: packet ID, endpoints, current node, next hop, and generated/forwarded/received/dropped action. A generated event records the actual first next hop when a route exists, enabling Phase 3 to associate that transmission with the target's observed outcome.
- `route_decisions.csv`: policy, selected path, route cost, alternatives found, hop count, and mean intermediate trust when trust-aware routing is selected. It records a selected route, not a ground-truth label.
- `summary.json`: calculated packet counts and ratios, forward events, scenario, seed, backend, and `average_delay_s: null` because this model does not simulate delay.

`validate_uav_events` checks required columns, finite numeric values, nonnegative packet counts, valid UAV IDs, and ratios within [0, 1]. CSVs are validated before writing.

## Reproducibility and limits

A fixed seed controls initial positions, waypoint destinations, speeds, packet destinations, and packet-drop decisions. Runs with identical inputs produce identical event contents (experiment directory timestamps differ). Link stability describes neighbour-set overlap and does not mean measured radio quality. Delivery is same-step routing over the generated graph, not a radio packet-level network simulation. No trust scores, classifiers, trust-aware routes, or explanations are implemented in Phase 2.

## Relay-opportunity validity audit

`results/simulator_validity_before/` measures packet generation, delivery/drop events, forwarding, per-UAV traffic, traversed routes, route diversity, and UAV 7 relay opportunities directly from the historical Phase 4 packet traces. `results/simulator_topology_sensitivity/` contains the 20-seed normal-traffic sensitivity runs at 200, 180, and 160 m. The 200 m setting was chosen as a balance: 180 m raised opportunity counts further but reduced mean PDR to 88.62%; 160 m reduced mean PDR to 75.79%. These are results of the Simplified Python FANET Model — NOT NS-3. The audit does not create behavior events and counts an attacker drop only when the UAV appears as a transit relay.
