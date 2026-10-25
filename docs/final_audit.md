# Final repository audit

**Audit date:** 2026-10-21. **Workspace:** `D:\AEX-TFANET`. This audit distinguishes checked source behavior from executed evidence. The current directory has no `.git` metadata, so prior edits could not be identified by Git diff; retained results were preserved rather than cleared.

## Inventory and implementation status

| Component | Status | Evidence / boundary |
|---|---|---|
| CLI/config/environment | Implemented | `python -m aex_tfanet --help`, `env`, command dispatch tests. |
| Python FANET simulation | Implemented simplified model | Mobility, distance connectivity, routes, event CSVs, packet-drop and blackhole. Explicitly not NS-3. |
| NS-3 backend | Prepared/unvalidated | `simulation/ns3/fanet_simulation.cc` source starter; not installed/compiled/executed. |
| Trust processing/engine | Implemented | Trace validation, observed relational outcomes, Beta/Laplace direct, weighted indirect, EWMA history, normalized fusion, adaptive decay/recovery. Unit/integration tests. |
| Behavioral detection | Implemented deterministic rule | Causal rolling evidence, label-isolated prediction, node-level evaluation. Unit tests and 80-run 200 m matrix. |
| Routing | Implemented | Shortest-hop baseline and online trust-aware path scoring; paired 80-run study. Labels used only for post-selection exposure evaluation. |
| ML | Implemented offline Random Forest | Temporal features, seed-group split, train-only imputation, metrics including ROC-AUC/AP and per-class support. Held-out set: 16k rows from four test seeds. |
| XAI | SHAP implemented and executed | Real TreeSHAP values on saved model and held-out test rows; local/global CSV and figures. LIME not implemented. |
| Metrics/visualization | Implemented | PDR, loss, delivered application throughput, route hops/changes/exposure, security and ML metrics; delay/signaling remain unavailable. Trace-derived figures. |
| Dashboard | Implemented and health-checked | Saved simulation vs sample/demo isolation, explicit model disclaimer, scenario/trust/detection/routing/ML/XAI and metadata views. |
| Pipeline | Implemented end-to-end | Fresh seed-42 full run produced 24 files spanning configuration, traces, trust, detection, ML, SHAP, metrics, figures, and manifest. |
| Sample data | Isolated demo | Dashboard's sample view is separate and labeled; not used in reported experiment metrics. |

## Tests and executed experiments

The final acceptance suite passed **63 tests** using `python -m pytest --basetemp=.pytest-tmp/release_suite_20261021`. Hardening adds ML ranking/per-class metrics and SHAP feature-alignment coverage. Verified experiments include:

- Phase 4 200 m paired normal and packet-drop p=.25/.50/.80, seeds 42–61; historical 250 m results remain intact.
- 20-seed topology sensitivity at ranges 250/200/180/160 m.
- Routing comparison: 20 seeds × normal/p=.8 × baseline/trust-aware = 80 runs.
- Seed-42 blackhole trace and fresh full packet-drop pipeline.
- ML grouped evaluation, SHAP global/local explanations, and dashboard health check.
- Two full seed-42 p=.8 runs (`results/repro_release_a/`, `results/repro_release_b/`) were compared. Each wrote 24 files; SHA-256 hashes matched across 13 canonical trace, trust, detection, ML, XAI, and metrics artifacts. The output manifests were excluded because they contain run-specific paths/IDs.

## Scientific integrity and validity

- Simulator provenance is named in summaries/manifests: **Simplified Python FANET Model — NOT NS-3**.
- Detector does not accept ground-truth labels; evaluator runs after predictions.
- Route selector receives online trust/topology, not attacker IDs; exposure is post-selection.
- ML features exclude seed, time, scenario, attack configuration and labels; group split prevents same-seed frames crossing the split.
- SHAP uses the persisted model's feature order. It attributes model outputs and is not causal analysis.
- Delay and signaling overhead are not modeled/measured. Throughput is delivered application-byte throughput, not PHY throughput.
- p=.25 detector sensitivity remains limited (9/20 misses); high p=.8 result is limited to tested matrix and model.
- No formal significance test or generalization claim was made.

## Dependencies and packaging

Core project dependencies are in `pyproject.toml` and `requirements.txt`; test, XAI, and dashboard dependencies are optional extras. LIME was removed from the optional dependency set because it is not implemented. The validated host is Windows/Python 3.13.2 with NumPy 2.1.3, pandas 2.3.0, scikit-learn 1.5.2, matplotlib 3.10.0, NetworkX 3.5, PyYAML 6.0.2, joblib 1.5.1, SHAP 0.54.1, and Streamlit 1.66.0. `pip check` finds FastAPI 0.115.5 requires Starlette <0.42 but installed Starlette is 1.9.0. This is an environment-level conflict; project optional packages should be isolated. Dashboard smoke check succeeded despite that unrelated conflict.

## Remaining risks

1. The principal scientific risk is simplified simulator fidelity and narrow scenario coverage.
2. Four independent held-out ML seed groups limit uncertainty claims; row counts overstate independent sample count.
3. Trust/detector parameters are engineering choices and require prospective calibration on a separate test matrix.
4. Shared Python environment has the documented FastAPI/Starlette conflict.
5. NS-3 integration and physical network behavior remain future validation work.

## Final recommendation

The project is defensible as a reproducible final-year **simulation prototype** with traceable model-based results, tested trust/detection/routing, grouped ML, SHAP, and an integrated demonstration. It is not ready to claim radio-level validity, broad detection generalization, or universal routing superiority. A compiled, validated NS-3 backend and independent scenario holdout are the highest-value next research steps.
