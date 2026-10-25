# Frontend integration contract

## Existing backend reused

The dashboard calls no duplicate research algorithm. It reads outputs from the existing Python FANET simulator, adaptive trust engine, behavioral detector, route-selection/paired comparison runner, performance analyzer, grouped ML pipeline, and SHAP/XAI pipeline. Its only write action is the explicitly requested run form, which calls the existing `aex_tfanet experiment` CLI using a bounded set of profile/input values.

## Artifact contract

The following saved artifacts are optional unless otherwise stated. A missing or malformed file is reported in the affected view; other pages remain available.

| Artifact | Use |
|---|---|
| `simulation/summary.json` | Required for experiment discovery; backend, seed, scenario, node count, duration, packet totals |
| `simulation/uav_events.csv` | Timestamped UAV positions and telemetry |
| `simulation/neighbor_events.csv` | Timestamped link/neighbor state |
| `simulation/packet_events.csv` | Packet action events; raw artifact preview only |
| `simulation/route_decisions.csv` | Routes actually chosen by each saved run |
| `trust/trust_scores.csv`, `trust_summary.json` | Relational trust history and class summary |
| `detection/detection_events.csv`, `detection_metrics.json` | Detector status windows and evaluator results |
| `metrics/metrics.json` | Performance values and unavailable metric status |
| `manifest.json`, `config.yaml`, `environment.json` | Run provenance/settings/environment |
| `ml_metrics.json`, `feature_importance.csv`, predictions | Offline model results and supported feature data |
| XAI status and local/global explanation CSVs | Saved SHAP explanation status and values |
| `aggregate_routing_metrics.csv` | Paired baseline/trust-aware aggregates from routing experiments |

The app checks columns before drawing a visualization. It does not fill missing scores, make routes, interpolate nodes, synthesize timeline events, or convert unavailable delay/overhead into zero.

## Safe experiment execution

The dashboard only exposes Normal, Packet drop, and Blackhole presets. It bounds seed, UAV count, duration, and packet-drop probability in UI controls, writes the selected values into a generated YAML under `results/.dashboard_configs/`, and passes a fixed list of arguments to the local Python child process. `shell=False`; no arbitrary command or path is accepted. A unique results directory is used for every launch. Process state is actual child-process state, while model outputs are presented after artifact creation. The user may stop the subprocess. The active process is not a live simulation telemetry feed.

The existing Streamlit app is the frontend and existing CLI is the backend entry point. No custom REST endpoints were added; Streamlit exposes its own `/_stcore/health` status route.

## Reproduce and troubleshoot

```powershell
python -m aex_tfanet env
python -m aex_tfanet experiment --config experiments/configs/packet_drop.yaml --output results/my_run
python -m aex_tfanet dashboard
```

Use a fresh output directory. If an artifact is missing, check the selected run's manifest/status and the CLI run log before rerunning. Missing optional SHAP or model outputs are shown as not evaluated/unavailable. For simulator assumptions and unmodeled metrics see [limitations](limitations.md).
