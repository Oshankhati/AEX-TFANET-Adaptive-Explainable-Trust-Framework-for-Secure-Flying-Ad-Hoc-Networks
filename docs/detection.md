# Phase 4: behavioral detection

## Scope and inputs

`detect` consumes the Phase 2 `uav_events.csv` and `packet_events.csv` plus the Phase 3 `trust_scores.csv`. It validates the simulation trace with the Phase 3 processor before scoring. A packet outcome counts for a target only when an actual `generated` or `forwarded` event names that target as its next hop. A source-side no-route drop has no such send intent and is not attributed to the source as malicious behavior.

The detector is deterministic and causal. At each simulation timestamp it uses only packet outcomes up to that timestamp and the latest available trust value per observer-target relationship. It produces a time series for every UAV and keeps `trust_classification` separate from `status` (`NORMAL`, `SUSPICIOUS`, `MALICIOUS`, or `INSUFFICIENT_DATA`). Insufficient data is not represented as normal behavior.

Ground-truth malicious-node metadata is not an argument to the detector. The CLI reads it from `simulation/summary.json` only after predictions are produced, then passes it to the node-level evaluator. With no such metadata, predictions are still written and evaluation is reported as unavailable.

## Score

For each node, observed successes and drops are kept in the configurable rolling `window_s`. The score is the weighted average of available bad-evidence features:

```text
drop evidence        = recent_drops / (recent_successes + recent_drops)
trust evidence       = 1 - mean(latest relational final trust)
forwarding evidence  = 1 - current forwarding_ratio
instability evidence = 1 - current link_stability
```

Default weights are 0.60, 0.25, 0.10, and 0.05. Missing trust or packet evidence is excluded from the weighted average and the remaining weights are renormalized. Scores are not calibrated probabilities. The configured suspicious and malicious cutoffs are 0.25 and 0.65; these are initial engineering thresholds, not values specified or validated by the project PDFs. A node requires at least five observed forwarding outcomes in its 10-second window before it receives a score.

## Run and artifacts

```text
python -m aex_tfanet detect --input results/<run> --config config.yaml
```

The command writes `detection/detection_events.csv`, `detection_summary.json`, and, when labels exist, `detection_metrics.json`. `--input` can also be the simulation directory. Use `--trust-input` to select a trust output folder or CSV, and `--output` to set the destination.

The CSV includes the evidence values, score, current trust classification, status, and a short reason. The summary states which features were used and confirms that labels were excluded from prediction. Evaluation is node-level: a node is predicted positive if any sufficiently observed window is suspicious or malicious. It reports TP/TN/FP/FN, precision, recall, F1, FPR, FNR, class counts, and a confusion matrix.

## Seed-42 demonstration

The existing paired 10-UAV, 100-second runs were evaluated without changing their simulation or trust outputs. The detector produced 9 suspicious time windows, all for UAV 7, in the packet-drop trace; the normal trace produced none. The attack-run node-level evaluation reported TP=1, TN=9, FP=0, FN=0. The normal run reported 10 true negatives and no predicted positives. These are results from one paired seed and one simulated attack, so the apparent perfect scores are not a general performance estimate. The detector marked UAV 7 suspicious; Phase 3 still classified its latest relational trust as Trusted, illustrating the separate outputs.


## Historical Phase 4 robustness validation (250 m)

### Demonstration result

The original seed-42 paired demonstration produced no suspicious windows in normal traffic and nine suspicious windows for UAV 7 in the p=0.8 packet-drop run. Its one-seed node-level counts were TP=1, TN=9, FP=0, FN=0. This remains a demonstration only.

### Multi-seed validation result

The validation runner executed paired normal and packet-drop scenarios for seeds **42–61**. It held simulator, trust, and detector settings fixed within each seed pair and tested packet-drop probabilities **0.25, 0.50, and 0.80**. The existing p=0.80 setting is the high level; lower settings exercise the simulator's existing configurable probability. No detector thresholds were changed during validation.

- **Normal:** 20/20 runs had zero suspicious or malicious windows and zero false positives (200 benign node-run cases; aggregate FPR=0). Precision, recall, F1, and FNR are undefined because there were no positive labels or predictions.
- **p=0.25:** 94 attributed attacker drops total, mean 4.70 ± 3.89 per 1,000 generated packets. UAV 7 was detected in 7/20 runs; TP=7, TN=180, FP=0, FN=13. Mean per-run recall/F1=0.35 and FNR=0.65; pooled F1=0.519.
- **p=0.50:** 193 attributed attacker drops, mean 9.65 ± 8.35 per run. Detected in 14/20; TP=14, TN=180, FP=0, FN=6. Mean per-run recall/F1=0.70 and FNR=0.30; pooled F1=0.824.
- **p=0.80:** 309 attributed attacker drops, mean 15.45 ± 13.40 per run. Detected in 16/20; TP=16, TN=180, FP=0, FN=4. Mean per-run recall/F1=0.80 and FNR=0.20; pooled F1=0.889. Four runs still missed the attacked node.

Across the 20 seeds, attributed attack-event counts increased monotonically with configured probability in 20/20 seed groups, and the attacked node's maximum detector score also increased monotonically in 20/20 groups. Suspicious-window counts averaged 1.65 ± 3.02, 11.85 ± 12.79, and 22.70 ± 18.79 at p=0.25, 0.50, and 0.80. The detector produced no false positives in any of the 80 runs.

The attacked target's full-run mean relational trust was below its same-seed normal baseline in 17/20 p=0.25 runs, 19/20 p=0.50 runs, and 19/20 p=0.80 runs. Mean paired changes were −0.020, −0.039, and −0.061. Trust did **not** consistently decline between the period before the first observed drop and the period spanning observed drops; the trust engine's relational observations and their timing vary by seed. A time-phased recovery experiment was not run: the simulator applies one attack probability for the whole run and has no authentic normal→attack→normal schedule. Existing unit recovery tests use controlled synthetic inputs and are not simulation evidence.

### Label isolation and decision gate

The detector is run before the evaluator reads `summary.json` ground truth. Its Phase 2 trace validation skips simulator summary metadata entirely. A regression test confirms predictions remain unchanged even if the summary is changed or malformed. The evaluator alone receives malicious-node IDs.

This historical matrix received **Gate decision C** because sparse relay opportunities made detector outcomes seed dependent. It remains unchanged under `results/phase4_validation/`.

### Artifacts

The 80 preserved run folders, per-run metrics, aggregates, manifest, summary, and five generated figures are under `results/phase4_validation/`. Standard deviations are population SD over the tested seeds. Per-run and pooled metrics are both included; undefined class-based metrics remain blank/null. `python -m aex_tfanet validate-detection --refresh-existing` rebuilds aggregates and figures from the retained runs without rerunning simulations.

All outputs remain from the **Simplified Python FANET Model — NOT NS-3**. Twenty seeds improve the descriptive evidence but do not establish statistical significance or generalization to radio-realistic FANETs, other attacks, or other node counts.

## Relay coverage and follow-up validation (200 m)

The trace audit measured actual `packet_events.csv` records and found UAV 7 received only **18.85 relay opportunities per 1,000 generated packets on average** at 250 m; one of 20 normal runs had none. The underlying reason was short shortest-hop paths (mean 1.36 hops) combined with randomized source/destination pairs. This is a traffic/topology coverage issue, not detector label leakage or missing fabricated events.

A 20-seed normal traffic sensitivity study varied only `communication_range_m`: at 200 m, mean PDR was 95.03%, mean hops 1.65, 454.05 multi-hop packets per run, and UAV 7 had 41.70 relay opportunities per run (range 10–95; zero zero-opportunity runs). At 180 m, relay opportunities rose to 51.80 but PDR fell to 88.62%; at 160 m, PDR fell to 75.79%. The 200 m value was chosen as a measured trade-off and is now in the standard normal and packet-drop profiles. The 250 m historical results remain available.

The exact paired validation was rerun with seeds **42–61**, normal plus packet-drop probabilities **0.25, 0.50, 0.80**, and detector configuration unchanged. For each probability, all 20 attack runs had 41.70 mean UAV 7 relay opportunities and zero runs without an observed attacker drop. Detection was TP/TN/FP/FN = **11/180/0/9** at p=.25 (pooled F1=.710), **19/180/0/1** at p=.50 (pooled F1=.974), and **20/180/0/0** at p=.80 (pooled F1=1.000). Normal remained at zero false positives. These results support proceeding to routing and ML as research modules while retaining the documented low-intensity misses; they do not justify a universal accuracy claim.

The follow-up matrix and before/after audit are in `results/phase4_validation_200m/`, `results/simulator_validity_before/`, `results/simulator_validity_after_200m/`, and `results/simulator_topology_sensitivity/`. Rebuild the audit with `python -m aex_tfanet audit-simulator --input results/phase4_validation_200m --output results/simulator_validity_after_200m`.
