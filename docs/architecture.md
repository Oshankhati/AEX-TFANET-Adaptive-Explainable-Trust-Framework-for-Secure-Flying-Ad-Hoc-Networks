# AEX-TFANET Architecture

**Status:** The modular Python research pipeline connects simulation, trust, behavior detection, online trust-aware routing, supervised ML, SHAP, performance analysis, figures, and a Streamlit dashboard. It remains an explicitly simplified model, not NS-3.

AEX-TFANET evaluates UAV behavior, adapts trust, uses trust during route selection, and explains the trained model's decisions. This architecture describes implemented components and their model limitations.

## Specification sources and choices

The project PDFs describe the motivation and methodology: dynamic FANETs, behavioral monitoring, direct/indirect trust, adaptation, secure routing, and explainability. They do not define exact trust equations, EWMA parameters, fusion weights, or classification cutoffs. Phase 3’s Beta/Laplace estimator, recommendation weighting, EWMA, fusion, and decay/recovery equations are documented implementation choices in `docs/trust_engine.md`.

## Runtime and backends

The current host is Windows with Python 3.13.2. NS-3 is unavailable. `simulation/ns3/` contains only an uncompiled starter source. The Python backend is labelled **Simplified Python FANET Model — NOT NS-3** and does not claim radio-level fidelity.

## Logical pipeline

```text
UAV nodes -> FANET communication -> network monitoring -> trust observations
    -> direct / indirect / historical trust -> classification
    -> causal behavior detection -> online trust-aware routing -> ML / SHAP
    -> performance metrics -> figures and read-only dashboard
```

The trust input boundary is the Phase 2 CSV contract. Python or a future NS-3 backend can feed the same processor if it produces compatible `uav_events.csv`, `neighbor_events.csv`, and `packet_events.csv` files.
The detailed implemented data flows are shown in [docs/diagrams.md](diagrams.md).

## Package layout

| Path | Role | Phase |
|---|---|---|
| `src/aex_tfanet/utils/` | config, logging, seed, environment probe | 1 implemented |
| `src/aex_tfanet/pipeline/` | full-run experiment orchestration and legacy scaffold | implemented |
| `src/aex_tfanet/simulation/` | Python mobility, topology, packet events and simulation schemas | 2 implemented |
| `src/aex_tfanet/trust/` | observation processor, direct/indirect/history/adaptive scores, classes, validation | 3 implemented |
| `simulation/ns3/` | NS-3 C++ starter and setup notes | source only; unvalidated |
| `src/aex_tfanet/detection/` | causal behavioral detection and separate evaluator | implemented |
| `src/aex_tfanet/routing/` | shortest-hop and online trust-aware route selection and experiments | implemented |
| `src/aex_tfanet/ml/`, `xai/` | seed-group model training/inference and SHAP explanations | implemented; LIME not implemented |
| `src/aex_tfanet/analysis/`, `visualization/` | simulator audit, performance metrics, and trace-derived figures | implemented |

## Trust relationship model

Trust is retained as `(timestamp, observer_id, target_id)`. The primary trust CSV does not collapse each target into one global score. Summary-only node classes average each observer’s latest score for a target; the underlying rows remain relational. See `docs/trust_engine.md` for the detailed data contract and assumptions.

## Current implementation

- Installable package, configuration, logging, seeding, environment probe, CLI, and experiment scaffold.
- Simplified deterministic Python FANET simulator with changing topology, forwarding/drop events, CSV validation, and summaries.
- Trust processor consumes actual simulation CSVs, derives only observed directed outcomes, and writes validated trust time series and summary JSON.
- NS-3 unavailable; its starter is unvalidated and has produced no NS-3 results.
- Phase 4 deterministic behavioral detection and separate node-level evaluation are implemented.
- Baseline and online trust-aware routing were compared on 80 paired runs (seeds 42–61, normal and p=.8 packet drop).
- ML uses actual temporal simulation/trust features and seed-group holdout; SHAP explanations use the trained Random Forest. No NS-3 results exist.
- Performance analysis and a read-only Streamlit dashboard are implemented; delay and signaling overhead remain unavailable in this model.
