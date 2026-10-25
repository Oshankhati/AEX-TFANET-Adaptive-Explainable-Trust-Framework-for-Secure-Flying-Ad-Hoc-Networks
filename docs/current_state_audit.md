# Current state audit (final hardening, 2026-10-21)

The full component audit and final evidence inventory are in [final_audit.md](final_audit.md). The main conclusion is that AEX-TFANET is an integrated and tested simulation prototype, not an NS-3 or radio-realistic system.

## Implementation and tests

The package contains modular simulation, trust, detection, routing, ML, XAI, analysis, visualization, pipeline, CLI, and Streamlit dashboard components. The final test suite passed **63 tests** using Python 3.13.2 and `python -m pytest --basetemp=.pytest-tmp/hardening_suite_20261021`.

The final paired seed-42 p=.8 runs in `results/repro_release_a/` and `results/repro_release_b/` each wrote 24 files. They had byte-identical hashes for 13 canonical outputs: UAV, neighbor, packet, and route traces; summary; trust; detector outputs; ML prediction and metrics; local SHAP and status; and performance metrics. Path/timestamp-bearing manifests were excluded from byte comparison.

## Experimental status

- Detector: 80-run p=.25/.50/.80 + normal matrix at 200 m, seeds 42–61; FNs 9/1/0 and zero FPs in 200 benign node-run cases.
- Routing: 80 paired normal/p=.8 runs; p=.8 mean PDR .9167 baseline vs .9353 trust-aware; attacked-intermediate exposure 4.43% vs 1.94%.
- ML: 64k train rows / 16k test rows with seed groups disjoint; malicious F1 .6794, ROC-AUC .9288, average precision .7380. Test rows span four held-out seeds.
- XAI: SHAP available; actual saved model with held-out global and local examples; LIME was not implemented.
- Attack traces: packet-drop robustness matrix and deterministic blackhole seed-42 demonstration.
- Dashboard: Streamlit health endpoint returned `ok` after hardening changes.

## Provenance, dependencies, and remaining caveats

All runs are from **Simplified Python FANET Model — NOT NS-3**. NS-3 is unavailable; its C++ starter is prepared/unvalidated. Delay and signaling overhead are not modeled/measured. Trust/detection parameters are implementation choices; p=.25 detection still misses 9/20 target runs. The shared user Python environment has a FastAPI/Starlette dependency conflict; isolate optional dependencies. LIME and Sybil/DoS/wormhole attacks are not implemented. See [limitations.md](limitations.md).
