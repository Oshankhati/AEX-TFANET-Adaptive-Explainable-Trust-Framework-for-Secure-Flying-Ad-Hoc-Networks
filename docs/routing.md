# Baseline and trust-aware routing

## Implemented policy

Each generated packet is routed over the live connectivity graph for its current simulation timestamp.

- `baseline` uses deterministic shortest-hop search with lexicographic tie-breaking.
- `aex_tfanet` uses a weighted simple-path search. It learns per-UAV forwarding reliability online from prior observed relay outcomes using a Beta(1,1) estimate. It uses the same-time topology and link stability from consecutive neighbor sets. Attack labels and configured attacker IDs are not inputs to route selection, and no node is removed from the graph.

The documented implementation cost is:

```text
C(P) = w_h * hops(P)
     + (w_T + w_D) * sum(1 - trust(v), v is an intermediate UAV)
     + w_L * sum(1 - link_stability(e), e is a selected edge)
```

`trust(v) = (observed_successes(v) + 1) / (observed_successes(v) + observed_failures(v) + 2)`. The delivery-quality weight currently uses the same forwarding-success estimate as trust; it is a configurable preference weight, not an independent measurement. `delay_weight` is retained in configuration but omitted because this simulator does not model transmission or queueing delay. Link stability is the Jaccard overlap of adjacent time-step neighbor sets. A live edge is required; a low-trust UAV remains eligible but incurs a cost. Route costs are policy scores, not physical energy or time.

The router returns the selected route and up to three lowest-cost alternatives. Missing connectivity returns an unavailable route. `route_decisions.csv` stores the selected route, policy, score, alternatives found, route length, and intermediate trust. Route changes count changes in selected path for repeated source-destination flows.

## Reproduce the paired experiment

```powershell
python -m aex_tfanet route --output results/routing_comparison_seed42_61 --seeds 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 --drop-probability 0.8
```

The run consists of 20 seeds × two scenarios (normal and packet drop p=.8) × two routing policies = 80 simulations. Per-seed results, saved configs, route traces, aggregates, and figures are in `results/routing_comparison_seed42_61/`. Figures derive from the per-run CSV.

## Results in the tested simplified model

| Scenario | Policy | PDR mean ± SD | Loss mean | Throughput mean | Mean route hops | Attacked-relay exposure | Route changes/run |
|---|---|---:|---:|---:|---:|---:|---:|
| Normal | Baseline | 0.9503 ± 0.0300 | 0.0497 | 0.03892 Mbps | 1.648 | 0% | 385.85 |
| Normal | AEX-TFANET | 0.9503 ± 0.0300 | 0.0497 | 0.03892 Mbps | 1.665 | 0% | 387.50 |
| Packet drop p=.8 | Baseline | 0.9167 ± 0.0446 | 0.0834 | 0.03755 Mbps | 1.648 | 4.43% | 385.85 |
| Packet drop p=.8 | AEX-TFANET | 0.9353 ± 0.0404 | 0.0648 | 0.03831 Mbps | 1.670 | 1.94% | 388.00 |

Exposure is evaluated after route selection by checking whether the known attacked UAV is an intermediate path node. Mean route length and route-change counts are descriptive of this model. Throughput is delivered application bytes divided by the configured 100 s duration; it is not PHY throughput. Delay and control/signaling overhead are **Not evaluated**. At p=.8 in this tested configuration, the trust-aware policy had higher mean PDR and lower attacker exposure, with slightly longer routes and more path changes. This is not a guarantee of improvement on other topologies, attacks, or radio-realistic simulators.

## Profiles and output

`experiments/configs/baseline.yaml` and `experiments/configs/trust_aware.yaml` select the policies for individual simulation runs. `normal.yaml` and `packet_drop.yaml` remain baseline profiles for historical comparability; the paired experiment runner explicitly runs both policies. Full experiment data are from the **Simplified Python FANET Model — NOT NS-3**. NS-3 has not been compiled or run in this environment.
