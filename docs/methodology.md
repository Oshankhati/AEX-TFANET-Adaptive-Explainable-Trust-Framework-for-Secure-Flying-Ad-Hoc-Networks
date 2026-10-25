# Methodology

**Status:** Implemented for the simplified Python fallback. All model-specific limits and unavailable metrics remain explicit.

The implemented evaluation workflow is:

1. Select a reproducible YAML configuration and seed for the **Simplified Python FANET Model — NOT NS-3**.
2. Generate mobility, neighbor/connectivity, and packet-event traces. Packet-drop and deterministic transit blackhole behavior occur only when the attacked node receives a packet as an intermediate relay.
3. Derive relational trust from observed send/outcome pairs; labels are excluded.
4. Score causal detector windows, then evaluate node-level alerts against ground truth only after predictions.
5. Optionally compare shortest-hop and online trust-aware routing using matched seeds, topology and traffic.
6. Train/evaluate a Random Forest using temporal features and seed-group holdout; use SHAP on the saved model and held-out data.
7. Calculate supported PDR, loss, delivered application throughput, route hops, route changes, exposure, and security/ML metrics from the saved traces. Delay and signaling overhead are not modeled/measured.
8. Store config snapshots, environment, seed, traces, processed results, metrics, figures, and manifests under `results/<experiment_id>/`.

Actual paired multi-seed results and provenance are recorded in `docs/results.md`, `results/phase4_validation_200m/`, and `results/routing_comparison_seed42_61/`. Results are not NS-3 evidence. SHAP was selected as the primary explainability method; LIME was not implemented.
