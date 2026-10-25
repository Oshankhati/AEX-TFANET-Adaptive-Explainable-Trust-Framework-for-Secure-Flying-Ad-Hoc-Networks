# Trust data processing and adaptive trust engine

**Status:** The Phase 3 trust subsystem is implemented and integrated with the detector, online routing, ML, SHAP, pipeline, and dashboard. This document covers the trust subsystem and its CSV boundary.

## Supported by the project specification

The project material calls for monitoring packet forwarding and communication behavior, considering direct and indirect trust, adapting trust over time, retaining observer-target relationships, classifying trust, and explaining the project’s methodology. It does not prescribe a direct-trust equation, EWMA parameter, fusion weights, decay/recovery equation, or experimentally validated classification cutoffs.

## Implementation choices

- Direct trust uses a Beta/Laplace estimator with configurable `prior_success` and `prior_failure`.
- Historical trust uses an EWMA controlled by `history_lambda`.
- Direct, indirect, and historical components are fused with normalized configured weights over available evidence.
- Final trust moves toward current fused evidence using `decay_rate` when it falls and `recovery_rate` when it rises.
- Class cutoffs reuse the existing configurable `trust_thresholds` values. They are initial experimental settings, not validated scientific thresholds.

These are transparent project formulations, not formulas attributed to the PDFs.

## Inputs and observation semantics

Run `aex-tfanet trust` on a Phase 2 `simulation/` directory containing:

- `uav_events.csv` for known UAV IDs, timestamps, and input validation;
- `neighbor_events.csv` for directed link availability at each timestamp;
- `packet_events.csv` for actual transmissions and outcomes;
- `summary.json` optionally, for the source backend label.

An observer-target outcome is derived from a generated/forwarded send event with a `next_hop`, and that target’s corresponding `forwarded`, `received`, or `dropped` event for the same packet. The processor verifies the link was connected at that timestamp. Successful target outcomes count as successes; a target `dropped` event counts as failure. Rows without an observable send/outcome pair do not create trust evidence. The Phase 2 generator now records the source’s actual first hop in the generated event so that first-hop outcomes are observable.

The engine never reads `malicious_nodes`, attack labels, or the configured drop probability when calculating trust. It responds to packet events only. Older Phase 2 CSVs whose generated rows have no first-hop target can still provide evidence for later hops, but some first-hop interactions are unavailable.

## Direct trust

For observer `i` and target `j`, let `S` and `F` be accumulated observed successful and failed forwarding outcomes. The implemented estimate is:

```text
D(i,j) = (S + alpha) / (S + F + alpha + beta)
```

`alpha` is `trust.prior_success`; `beta` is `trust.prior_failure`. Both must be positive. The default prior gives 0.5 before evidence, but the engine emits no row for a pair until it has an observed interaction.

## Indirect trust

At each time with a direct observer-target interaction, the observer may use contemporaneous neighbour recommendations. A neighbour `k` recommends its own accumulated direct trust in target `j`; that recommendation is weighted by the observer’s direct trust in recommender `k`:

```text
I(i,j) = sum(D(i,k) * D(k,j)) / sum(D(i,k))
```

Only current neighbours with both direct opinions and recommender trust at least `min_recommender_trust` contribute. `min_recommendations` controls the required count. If there is not enough valid evidence or total weight is zero, indirect trust is unavailable. It is written as an empty CSV field with `indirect_available=false` and excluded from fusion; it is never replaced with perfect trust or copied from direct trust.

## Historical and adaptive trust

History for a pair updates when a new observation arrives:

```text
H_t = lambda * D_t + (1 - lambda) * H_(t-1)
```

The first historical value is the first direct estimate. `history_lambda` is in [0, 1].

For current available components, the engine calculates a normalized weighted average:

```text
E_t = sum(w_c * component_c) / sum(w_c for available components)
```

When indirect trust is unavailable, its weight is excluded from both numerator and denominator. This prevents missing information from increasing trust.

The final score moves toward `E_t` from the previous final score:

```text
T_t = T_(t-1) + r * (E_t - T_(t-1))
r = decay_rate    when E_t < T_(t-1)
r = recovery_rate when E_t >= T_(t-1)
```

The first final value is `E_t`. Scores are clipped to configured bounds. This gives gradual decrease and recovery while preserving the distinct direction-specific update rates.

## Classification

Using existing `trust_thresholds`:

- `trust >= highly_trusted`: Highly Trusted
- `trusted <= trust < highly_trusted`: Trusted
- `suspicious <= trust < trusted`: Suspicious
- `trust < suspicious`: Untrusted / Malicious

The values in `config.yaml` are starting thresholds for experiments, not validated decision boundaries.

## Configuration

The Phase 1 flat `trust` settings are retained for compatibility. `direct_weight`, `indirect_weight`, and `history_weight` are normalized across components available for a score. `prior_success`/`prior_failure` configure the Beta prior. `update_rate` remains for compatibility; `history_lambda` is the explicit Phase 3 EWMA parameter.

Relevant defaults in `config.yaml`:

```yaml
trust:
  direct_weight: 0.60
  indirect_weight: 0.40
  history_weight: 0.30
  prior_success: 1.0
  prior_failure: 1.0
  min_recommendations: 1
  indirect_enabled: true
  min_recommender_trust: 0.0
  history_lambda: 0.30
  decay_rate: 0.25
  recovery_rate: 0.10
  minimum_trust: 0.0
  maximum_trust: 1.0
```

## Output

The command writes `trust/trust_scores.csv` and `trust/trust_summary.json` beside the simulation folder, without changing the simulation outputs. Repeated default runs create a timestamped sibling trust folder rather than overwrite an existing one.

`trust_scores.csv` preserves `(timestamp, observer_id, target_id)` and includes observed packet counts/outcomes, forwarding ratio, link evidence, direct/indirect/historical/final trust, indirect availability, recommender count, and classification. The output is validated for schema, IDs, self-links, numeric values, bounds, and class values before and after serialization.

`trust_summary.json` reports calculated score statistics and classifies nodes for summary purposes by averaging each observer’s latest final score for a target. That summary aggregation does not replace or rewrite the relational records. It also records the trust configuration, input path, and backend label when available.

## Run

```powershell
python -m aex_tfanet simulate --config experiments/configs/normal.yaml --backend python
python -m aex_tfanet trust --input results/<normal-run>/simulation --config config.yaml
python -m aex_tfanet simulate --config experiments/configs/packet_drop.yaml --backend python
python -m aex_tfanet trust --input results/<packet-drop-run>/simulation --config config.yaml
```

Use `--output path` to choose a trust output folder explicitly.

## Limitations

- The simulator is two-dimensional and not NS-3; trust inherits the fidelity limits of its input.
- Trust is only inferred for observer-target interactions with an observable next-hop outcome and a connected link record.
- Packet traces cannot model radio corruption, acknowledgments, interference, or ambiguous link failures.
- The demo has relatively few observed drops. UAV 7’s trust decreases against the same-seed normal case, but its target-level aggregate remains above the initial “Highly Trusted” cutoff in this run. The engine does not force a malicious classification.
- Recommendation trust is derived from other neighbours’ direct interaction histories; no external reputation protocol exists yet.
- Equations, weights, update rates, and thresholds are implementation assumptions for future evaluation, not source-PDF requirements.
