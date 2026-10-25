# Implementation plan

**Current phases completed:** Core phases 0–15 are implemented for the Python fallback, including the simulator relay-coverage gate, paired routing comparison, grouped ML evaluation, SHAP explanation, performance figures, dashboard, and a complete executable pipeline. Phase 3 trust, Phase 4 detector, routing costs, and ML configurations are documented implementation choices where the PDFs do not specify exact formulas.

## Assumptions and scope

1. The PDFs call for behavioral monitoring, direct/indirect trust, adaptation, and classification; they do not specify exact trust equations, EWMA values, component weights, decay/recovery rates, or scientifically validated thresholds.
2. Direct trust uses a configurable Beta/Laplace prior, indirect opinions are weighted by the observer's current direct estimate of each recommender, and history uses EWMA.
3. The event processor uses only actual packet send/outcome pairs and connected-neighbour records. It does not consume malicious-node IDs or attack probability.
4. The simplified Python model is explicitly **Simplified Python FANET Model — NOT NS-3**. It supports development, not research-grade radio claims.
5. NS-3 is unavailable. Its C++ source starter is not compiled or validated.

## Phase checklist

| Phase | Content | Status |
|---|---|---|
| 0 | Audit, architecture, plan | Done |
| 1 | Package, config, logging, seed, CLI, tests | Done |
| 2 | Python FANET simulation, CSV and summaries; NS-3 starter | Done with NS-3 limitation |
| 3 | Trust data processing, direct/indirect/history/adaptive trust, classification | Done |
| 4 | Deterministic behavioral detection and evaluation | Implemented and evaluated at 250 m and 200 m; proceed with low-intensity miss limitation |
| 5 | Additional attack feasibility | Packet drop and deterministic blackhole implemented; blackhole seed-42 trace verified |
| 6 | Trust-aware vs baseline routing | Implemented; paired 20-seed normal and p=.8 routing study completed |
| 7 | ML comparison | Implemented; temporal snapshots, seed-group holdout, evaluation saved |
| 8 | XAI support | SHAP implemented and available after approved installation; LIME not implemented |
| 9–13 | Performance analysis, plots, dashboard, complete evaluation | Implemented and integrated in the full pipeline |
| 14 | Simulator validity and robustness gate | Measured relay/route coverage; normal and three packet-drop levels revalidated at 200 m |
| 15 | Final integration and demonstration | Full CLI pipeline, grouped ML, SHAP, saved metrics/figures, and Streamlit dashboard implemented |

## Phase 3 implementation notes

- `src/aex_tfanet/trust/` validates Phase 2 CSVs and produces directed `(timestamp, observer_id, target_id)` trust observations.
- Phase 2 packet generation events now carry the actual first hop, allowing the trust processor to associate that transmission with its observed outcome.
- The trust engine records unavailable indirect evidence as an empty CSV field plus `indirect_available=false`; its weight is removed and remaining weights are renormalized.
- `trust` writes to a sibling `trust/` directory and does not mutate simulation output. Repeated default runs receive timestamped directories.
- Same-seed demo results show a directional decline in UAV 7's paired trust, but only six drops are observed and its target aggregate remains just over the initial Highly Trusted cutoff. No malicious label is forced.

## Run

```text
python -m aex_tfanet env
python -m aex_tfanet simulate --config experiments/configs/normal.yaml --backend python
python -m aex_tfanet trust --input results/<normal-run>/simulation --config config.yaml
python -m aex_tfanet simulate --config experiments/configs/packet_drop.yaml --backend python
python -m aex_tfanet trust --input results/<packet-drop-run>/simulation --config config.yaml
python -m aex_tfanet detect --input results/<packet-drop-run> --config config.yaml
python -m aex_tfanet validate-detection --output results/phase4_validation_200m --refresh-existing
python -m aex_tfanet route --output results/routing_comparison_seed42_61 --seeds 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 --drop-probability 0.8
python -m aex_tfanet ml --input results/phase4_validation_200m --output results/ml_phase4_hardened
python -m aex_tfanet explain --input results/ml_phase4_hardened --output results/xai_phase4_hardened
python -m aex_tfanet experiment --config experiments/configs/packet_drop.yaml
python -m aex_tfanet dashboard
python -m pytest
```

The legacy Phase 1 scaffold remains available through `experiment --scaffold`. Phase 4 gate evidence and remaining limitations are documented in `docs/detection.md`.
