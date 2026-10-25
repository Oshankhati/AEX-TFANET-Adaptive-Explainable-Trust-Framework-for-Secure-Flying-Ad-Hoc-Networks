# AEX-TFANET

**Adaptive Explainable Trust Framework for Secure Flying Ad Hoc Networks**

AEX-TFANET is a research prototype for studying how observed UAV forwarding behavior can inform relational trust, behavioral detection, and online route selection in a mobile ad hoc network. It also includes a separate seed-grouped Random Forest evaluation and model explanations with SHAP.

> **Research boundary:** all current runs use the **Simplified Python FANET Model — NOT NS-3**. Outputs are simulated model results, not field data or radio-level evidence. The model omits wireless PHY/MAC behavior, propagation, interference, retransmissions, and per-hop delay.

## Problem and objectives

FANET routes change as UAVs move, and conventional shortest-hop routing does not express whether relays have recently forwarded traffic reliably. This prototype explores whether auditable, observed behavior can support trust estimates and route preferences while retaining a conventional shortest-hop baseline.

The implemented objectives are to:

- generate reproducible mobility, connectivity, and packet event traces;
- estimate direct, indirect, historical, and adaptive relational trust from observed outcomes;
- detect suspicious forwarding behavior without using ground-truth labels as prediction inputs;
- compare shortest-hop routing with online trust-aware routing under paired seeds;
- evaluate a Random Forest using seed-group holdout and explain its predictions with SHAP;
- report only metrics supported by the saved traces and explicitly record unavailable metrics.

## Architecture and method

```text
UAV mobility/topology → packet send/outcome traces → relational trust history
      → causal detection → baseline or online trust-aware route selection
      → grouped offline ML + SHAP → metrics, plots, manifests, dashboard
```

The trust model is a documented implementation formulation; the source project PDFs do not specify exact trust equations or validated thresholds. Direct trust uses a Beta/Laplace estimate, indirect opinions are recommender-trust-weighted, history uses EWMA, and available components are fused with normalized weights before direction-specific decay/recovery. See [trust model](docs/trust_model.md) and [architecture diagrams](docs/diagrams.md).

The deterministic detector scores rolling observed forwarding outcomes, trust history, forwarding ratio, and link stability. Predictions are written before labels are used by the node-level evaluator. See [detection](docs/detection.md).

The baseline uses deterministic shortest-hop routing. The proposed policy chooses among live simple paths using configured hop, observed forwarding reliability, and link-stability costs. No attacker labels enter route selection. See [routing](docs/routing.md).

The offline Random Forest uses temporal telemetry and trust features; all rows from each seed are grouped into either train or test. Scenario, seed, timestamp, attack type/probability, and labels are excluded from features. SHAP explains the trained model's held-out or actual per-run predictions. LIME is not implemented. See [ML](docs/ml.md) and [XAI](docs/xai.md).

## Experiments and current results

Retained experiment matrices include 20-seed normal topology sensitivity; normal and p=.25/.50/.80 detector validation at 200 m plus historical 250 m runs; 80 paired routing simulations; seed-grouped ML; SHAP; a seed-42 blackhole trace; and full-pipeline demonstrations. Results are model-specific and descriptive. Under p=.8 in the routing study, baseline and trust-aware mean PDR were 0.9167 and 0.9353; attacked-intermediate exposure was 4.43% and 1.94%. At p=.25, the unchanged detector still missed 9/20 attacked-node runs. Read [results](docs/results.md) for metrics, artifacts, and caveats.

## Installation

Python 3.10+ is required. Install core and development dependencies in an isolated environment. Add the optional XAI and dashboard extras only when needed:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev,xai,dashboard]"
```

Core requirements are listed in `requirements.txt`; `requirements-dev.txt` and `requirements-optional.txt` remain available for requirements-file workflows. Isolating the project matters: mixing Streamlit with unrelated FastAPI packages in one environment can create incompatible Starlette constraints. SHAP is optional; if unavailable, the CLI records explicit unavailability rather than fabricated explanation values.

## Run

```powershell
python -m aex_tfanet env
python -m aex_tfanet simulate --config experiments/configs/normal.yaml --backend python
python -m aex_tfanet trust --input results/<run>/simulation --config config.yaml
python -m aex_tfanet detect --input results/<run> --config config.yaml
python -m aex_tfanet experiment --config experiments/configs/packet_drop.yaml
python -m aex_tfanet route --output results/routing_comparison_seed42_61 --seeds 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 --drop-probability 0.8
python -m aex_tfanet ml --input results/phase4_validation_200m --output results/ml_phase4_hardened
python -m aex_tfanet explain --input results/ml_phase4_hardened --output results/xai_phase4_hardened
python -m aex_tfanet dashboard
```

The dashboard is the project's interactive Streamlit frontend. It provides saved-run overview, topology replay, trust and detection views, route/ML/SHAP results, experiment browsing, artifact previews, methodology, limitations, and presentation/demo navigation. Its Simulation Monitor can launch the existing experiment pipeline from a bounded set of scenario presets; it reports process status and loads artifacts after they are written, rather than presenting simulated values as a live feed. The topology replay steps through recorded timestamps only. See [dashboard guide](docs/dashboard.md), [frontend architecture](docs/frontend_architecture.md), and [frontend integration](docs/frontend_integration.md).

Start from the repository root:

```powershell
python -m aex_tfanet dashboard
```

Open the local URL printed by Streamlit (usually `http://localhost:8501`). All saved run results remain labeled **Simplified Python FANET Model — NOT NS-3**. The dashboard does not expose a separate REST API; `/_stcore/health` is Streamlit's process health endpoint.

Each run should use a fresh output directory unless the command explicitly supports refreshing derived aggregates. See [experiments and reproducibility](docs/experiments.md) for the matrix and controlled rerun instructions.

## Testing

```powershell
python -m pytest
```

The suite covers configuration, trace validation, trust equations and edge cases, causal detection and label isolation, routing, metrics, ML seed grouping, SHAP feature alignment, visualizations, CLI behavior, and full-pipeline integration.

## NS-3 status and limitations

NS-3 is unavailable in the validated environment. `simulation/ns3/fanet_simulation.cc` is prepared/unvalidated starter code; it has not been compiled or run. The Python simulator must not be represented as NS-3. Delay and signaling overhead are not measured; delivered application throughput is not PHY throughput. The tested seeds, one malicious-node placement, two implemented attack types, and simplified topology do not establish generalization or universal routing superiority. See [limitations](docs/limitations.md), [reproducibility](docs/reproducibility.md), and [final audit](docs/final_audit.md).

## Project and defense material

- [Thesis material draft](docs/thesis_material.md)
- [Presentation outline](docs/presentation_outline.md)
- [Viva questions and answers](docs/viva_questions.md)
- [Final project scorecard](docs/final_project_scorecard.md)
