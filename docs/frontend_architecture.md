# Frontend architecture

## Technology choice

The project already has a functioning Streamlit dashboard, Python CLI, and local artifact pipeline. This frontend extends Streamlit to keep the demonstration in-process with the Python ecosystem and avoid maintaining a separate JavaScript service. There is no FastAPI service in this project, and the dashboard does not add one; Streamlit serves the UI and its built-in `/_stcore/health` endpoint.

```text
Browser
  ↓ Streamlit pages/widgets
dashboard/app.py
  ↓ confined artifact service (dashboard_data.py)
results/<experiment>/ CSV + JSON + figures
  ↑ optional fixed-argv subprocess for `python -m aex_tfanet experiment`
existing simulation → trust → detection/routing → evaluation → ML/XAI modules
```

## Page → source map

| Page | Main source | Existing module/artifact |
|---|---|---|
| Overview / Monitor | `simulation/summary.json`, `metrics/metrics.json` | simulation and analysis |
| FANET Topology | `uav_events.csv`, `neighbor_events.csv`, trust/detection traces | simulator, trust, detector |
| Trust Engine | `trust_scores.csv`, `trust_summary.json` | `trust.engine` |
| Threat Detection | `detection_events.csv`, `detection_metrics.json` | `detection.behavioral` |
| Secure Routing | `route_decisions.csv`, `aggregate_routing_metrics.csv` | simulator routing and `routing.experiment` |
| ML Detection | `ml_metrics.json`, `feature_importance.csv` | `ml.run_ml` |
| Explainable AI | XAI status, local/global SHAP CSVs | `xai.run_explanations` |
| Experiments / Results | manifests, configs, environment, metrics, routing aggregates | pipeline and analysis |
| Raw Data / Artifacts | allowlisted CSV/JSON files | artifact reader |
| Methodology / Architecture / Limitations | project documentation and current pipeline | docs and package structure |
| Presentation Mode | selected run's saved summary and metrics | saved outputs only |

## Data safety and performance

`src/aex_tfanet/dashboard_data.py` confines run artifacts to the configured results root, parses expected CSV/JSON files, reports malformed/missing data through a domain-specific error, and inventories non-symlink files. The Streamlit app caches reads by path and modification time, caches experiment discovery for five seconds, and loads ML/XAI artifacts only on their pages. Artifact previews are allowlisted and bounded to 500 rows. No frontend field is interpolated into a shell command.

## States and simulation semantics

The app distinguishes saved experiment replay from a process that is currently running. The simulator writes its traces at completion, so the dashboard reports child-process status but does not present simulated intermediate data as live. Replay uses real timestamps in `uav_events.csv` and performs no interpolation. Node detection status and configured attacker ground truth are separately represented.

The current runner uses the Python backend explicitly. The simulator banner says **Simplified Python FANET Model — NOT NS-3**. No REST API is provided; Streamlit's internal health path is not a project data API.
