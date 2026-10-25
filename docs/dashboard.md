# AEX-TFANET dashboard

The dashboard is a Streamlit frontend over the existing Python package and saved experiment artifacts. It does not reimplement trust, detection, routing, ML, SHAP, or metric calculations. The dashboard is read-only for stored results; its optional runner invokes only the existing `aex-tfanet experiment` pipeline with a fixed argument list and one of three repository scenario presets.

The dashboard uses a light background with dark, high-contrast text and icons across its controls, charts, tables, and navigation.

## Start

From the project root in PowerShell, activate the environment and start Streamlit:

```powershell
cd D:\AEX-TFANET
.\.venv\Scripts\Activate.ps1
python -m aex_tfanet dashboard
```

Open the local URL printed by Streamlit (normally `http://localhost:8501`). To select another saved-results root:

```powershell
python -m aex_tfanet dashboard --results results
```

The package launcher binds to `127.0.0.1` in headless mode so the dashboard is local to the machine and does not advertise a network-facing address.

The Streamlit health endpoint is `/_stcore/health`; the project does not expose a separate FastAPI/REST service. All pages run in the same Streamlit application.

## Pages

- **Overview:** run metadata, saved metrics, research boundary, workflow summary.
- **Simulation Monitor:** launch a run from Normal, Packet drop, or Blackhole presets; set seed, UAV count, duration, and packet-drop probability. The runner uses the existing Python pipeline. While it runs, status is process-based; simulation data is not streamed. Stop terminates the child process. The output is discovered after `simulation/summary.json` is written.
- **FANET Topology:** recorded UAV positions and connected neighbor links at an actual saved timestamp, with play/pause, 0.5×/1×/10× replay, previous/next/reset controls, and per-UAV telemetry. Playback visits stored samples only. Trust and detector colors use the latest saved observation at or before that timestamp. An attacker target outline indicates configured ground truth, separately from detector status. No position interpolation or packet animation is performed.
- **Trust Engine:** relational trust history, latest observer-target rows, classification counts, and an observer-target matrix.
- **Threat Detection:** saved detection windows and node-level confusion/metrics when available.
- **Secure Routing:** selected run route-decision trace and saved paired routing aggregates.
- **ML Detection / Explainable AI:** saved held-out ML metrics, feature importance, and SHAP files. Missing evaluations are reported as unavailable; LIME is not implemented.
- **Experiments / Results & Comparison:** run metadata, manifest/config/environment where available, per-run performance, and paired aggregate results.
- **Raw Data / Artifacts:** allowlisted CSV/JSON previews. CSV preview is capped at 500 rows. Arbitrary file paths are not accepted.
- **Methodology, System Architecture, Limitations & Reproducibility:** explains the project flow and current research boundaries.
- **Presentation Mode:** guided, ten-step viva/demo narrative with previous/next controls and saved-run KPIs.

## Artifact integration and provenance

Runs are discovered beneath the configured results root when they contain `simulation/summary.json`. The page loads details lazily from the selected run. Streamlit caches JSON/CSV reads by path and modification time; discovery is cached for five seconds. Path resolution is confined to the configured results root and selected run. Expected artifact names are allowlisted for preview.

Primary consumed artifacts include `simulation/summary.json`, `simulation/uav_events.csv`, `neighbor_events.csv`, `packet_events.csv`, `route_decisions.csv`, `trust/trust_scores.csv`, `detection/detection_events.csv`, `detection/detection_metrics.json`, `metrics/metrics.json`, `manifest.json`, and ML/XAI CSV/JSON outputs. Routing comparison aggregates are loaded from `results/routing_comparison_*/aggregate_routing_metrics.csv`.

Use **View source and provenance** under metrics/charts/tables to see the selected run, source artifact, scenario, seed, and backend. Only values in those artifacts are displayed. Metrics absent from the simulator, including delay and signaling overhead, are labeled not modeled/unavailable.

## Run from the dashboard

The run form accepts only the three supported preset scenarios and bounded numeric inputs. It writes a temporary YAML profile under `results/.dashboard_configs/`, then starts a child process with a fixed argv equivalent to:

```powershell
python -m aex_tfanet experiment --config <generated-preset> --output <new-results-folder>
```

It does not accept shell text or arbitrary config paths. Each run uses a fresh timestamped output folder. Running status means the child process is active; no intermediate simulation counters are claimed. Refresh status manually to inspect completion. A successful run becomes selectable after its summary is written. NS-3 is not offered by this dashboard runner and is never silently replaced.

## Data states and limitations

Selected saved output is marked **SAVED EXPERIMENT REPLAY**. The topology slider steps only through recorded timestamps. The app does not subscribe to a live simulation feed and must not be described as a live monitor. The simulator status is always disclosed as **Simplified Python FANET Model — NOT NS-3** unless a stored run reports its own backend. The implementation does not model PHY/MAC behavior, propagation, contention, interference, retransmission, energy, per-hop/queueing delay, or signaling overhead. See [limitations](limitations.md) and [reproducibility](reproducibility.md).

For CLI details and tests, see the [README](../README.md). The dashboard has no separate project REST endpoints; `/_stcore/health` is Streamlit's own process health route.
