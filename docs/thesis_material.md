# Thesis material: technically accurate draft outline

This is a structured writing draft based on the code and retained results. It contains no external literature claims or invented citations; add verified references from the student's actual literature review before submission.

## 1. Abstract

This project implements AEX-TFANET, a research prototype that combines observed UAV forwarding outcomes, relational adaptive trust, causal behavioral detection, and online trust-aware route selection. A simplified Python FANET model produces reproducible mobility, connectivity, and packet traces. The detector is evaluated separately from ground-truth labels, routing is compared against deterministic shortest-hop routing over paired seeds, and a Random Forest is evaluated with seeds held out as groups. SHAP explains model predictions. In the tested p=.8 packet-drop routing matrix, trust-aware routing averaged PDR 0.9353 versus 0.9167 for baseline and attacked-intermediate exposure 1.94% versus 4.43%. The low-intensity detector matrix still missed 9/20 attacked-node runs at p=.25. These findings are limited to the simplified model, and are not NS-3 or radio-level results.

## 2. Introduction

FANETs use mobile UAV nodes whose connectivity changes over time. This implementation investigates whether observed forwarding behavior and trust history can influence route selection and support behavior monitoring. The implementation is an executable research prototype, not a deployed protocol or radio testbed.

## 3. Problem statement

Shortest-hop selection can choose a path through a relay with poor observed forwarding reliability. The project asks whether a trust-aware route cost can reduce selection of an attacked intermediate UAV in the implemented simulation while maintaining delivery and while preserving a conventional baseline.

## 4. Objectives

Build a reproducible trace-generating model; calculate direct, indirect, historical, and adaptive trust; detect behavior using causal information; compare routes under matched conditions; evaluate an offline grouped ML baseline; explain its predictions; and report model limits.

## 5. Literature and research motivation

The project PDFs motivate behavioral monitoring, direct/indirect trust, trust adaptation, secure routing, and explainability. They do not specify the equations, weights, or calibrated cutoffs used here. This section must be supplemented with the student's cited, verified literature; no literature findings are asserted by this draft.

## 6. Proposed AEX-TFANET architecture

Mobility/topology and packet events feed monitoring and a CSV contract. Actual send-to-next-hop outcomes feed relational trust. Trust and current link stability influence route choice. Detection predictions are evaluated separately against simulation labels. An offline grouped Random Forest and SHAP path is an auxiliary analysis, not an input to the routing comparison. Artifacts flow to metrics, figures, and a read-only dashboard.

## 7. Trust model

Direct trust is `(S+alpha)/(S+F+alpha+beta)`. Indirect trust is a recommender-trust-weighted mean of neighbor opinions when enough evidence exists. Historical trust is an EWMA. Available components are fused by normalized configured weights; final trust moves toward evidence using separate decrease and recovery rates. Parameters are implementation choices, not source-specification equations. Full definitions and defaults are in `docs/trust_engine.md`.

## 8. Malicious-node detection

The detector uses a rolling window of observed next-hop successes/drops, latest available relational trust, forwarding ratio, and link stability. Evidence weights are normalized when features are missing. It reports four statuses, including insufficient data. The evaluator's positive node definition is any suspicious or malicious window. Labels are not inputs to predictions.

## 9. Trust-aware routing

The baseline finds a deterministic shortest-hop route. The proposed policy scores live simple paths using hop count, online Beta-smoothed forwarding reliability, and Jaccard link stability. The attacked-node label is used only after routing to measure exposure. No delay term is used because delay is not modeled.

## 10. Machine learning

Temporal telemetry/trust snapshots are classified by a Random Forest. Scenario, seed, timestamp, attack identity/probability, and target label are excluded from features. A GroupShuffleSplit keeps all records from each seed in one partition. Median imputation is fit on training rows only. The test set has four seed groups; rows within each run are correlated.

## 11. Explainable AI

SHAP TreeExplainer operates on the actual saved Random Forest and held-out transformed features, with explicit feature names/order. Global mean absolute SHAP values use a deterministic sample of up to 512 held-out rows. Local signed SHAP values describe individual model output attribution and do not establish causal effects. LIME was not implemented; SHAP was selected as the primary method.

## 12. Experimental methodology

Experiments use explicit YAML settings and seeds 42–61. The retained studies include topology sensitivity, normal plus three packet-drop levels for detection, paired baseline/trust-aware routing under normal and p=.8 traffic, ML, SHAP, blackhole demonstration, and one full pipeline. See `docs/experiments.md` and each result manifest.

## 13. Results

At 200 m, normal mean PDR was 95.03% and the target UAV had 41.70 mean relay opportunities per 1,000 generated packets. Detection at p=.25/.50/.80 yielded TP/TN/FP/FN of 11/180/0/9, 19/180/0/1, and 20/180/0/0. Paired p=.8 routing PDR was 0.9167 ± 0.0446 baseline and 0.9353 ± 0.0404 trust-aware; attacker exposure was 4.43% vs 1.94%. Grouped ML malicious F1 was 0.679, ROC-AUC 0.929 and average precision 0.738 on 16,000 held-out rows across four seeds. All values are from the simplified Python model.

## 14. Discussion

The routing matrix is consistent with fewer selected paths traversing the configured attacker and a higher mean delivery ratio in this tested setup, at the cost of slightly longer routes and more path changes. The detector's high-intensity sensitivity is stronger than its low-intensity sensitivity. The ML ranking metrics coexist with a 0.610 malicious recall at the selected threshold. These are descriptive findings; this work performed no formal significance test and cannot establish broad generalization.

## 15. Limitations

The model does not implement PHY/MAC, propagation, interference, retransmissions, energy, or delay. NS-3 is unavailable and its source starter is unvalidated. The attacked node and topology are narrow; trust and detector thresholds are engineering choices; test frames are correlated within four held-out seeds; and LIME is not implemented.

## 16. Future work

Validate the CSV contract with a compiled NS-3 backend; add propagation/MAC-aware delay and control costs; test more topologies, UAV counts, seeds, and attack placements; pre-register threshold selection and reserve a final untouched scenario set; quantify uncertainty at the independent-run level; and evaluate trust attacks such as collusion only after causal implementation and tests.

## 17. Conclusion

AEX-TFANET provides a reproducible, modular prototype linking packet evidence to trust, detection, and route choice, with an honest baseline, grouped ML analysis, SHAP explanations, and traceable artifacts. Its contribution is an integrated and testable workflow plus a measured result within a simplified model, not proof of a deployable or radio-realistic FANET security protocol.
