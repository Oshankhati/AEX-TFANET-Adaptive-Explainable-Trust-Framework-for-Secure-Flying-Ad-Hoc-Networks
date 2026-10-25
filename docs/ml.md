# Behavioral machine learning

The deterministic Phase 4 detector remains the primary causal detector. The additional ML module is a retrospective supervised comparison trained on actual Phase 4 traces.

## Reproduce

```powershell
python -m aex_tfanet ml --input results/phase4_validation_200m --output results/ml_phase4_hardened
```

The module creates one feature snapshot per UAV per simulation timestamp. It uses cumulative packet counters and current telemetry plus the latest trust values observed up to that timestamp. It does not use seed, scenario name, attack probability/type, malicious node ID, or label as features. Ground-truth malicious IDs are read after feature rows are formed and used only as the supervised target.

Features: forwarding ratio, delivery ratio, cumulative forwards and drops, current neighbor count, mobility, link stability, and causal means of direct, indirect, historical, and final trust plus observed trust count. Missing values are median-imputed using training data only. Classifier: `RandomForestClassifier(n_estimators=200, min_samples_leaf=3, class_weight="balanced_subsample", random_state=42)`.

`GroupShuffleSplit` holds out full seed groups; every temporal frame from a seed belongs to one side, preventing correlated node-time frames from crossing the split. In the retained evaluation, training used seeds 44–56, 58, 60, and 61; held-out seeds were 42, 43, 57, and 59. The result is a held-out-seed evaluation of the simulator's fixed attack scenarios, not external generalization. The task is retrospective per-snapshot classification: the features at a timestamp contain only telemetry/trust available through that timestamp.

## Measured result

From 80 Phase 4 runs (80,000 node-time snapshots), the held-out 16,000 snapshots had accuracy **0.9568**, malicious precision **0.7665**, recall **0.6100**, F1 **0.6794**, ROC-AUC **0.9288**, average precision **0.7380**, and macro-F1 **0.8281**. The held-out confusion matrix is `[[14577, 223], [468, 732]]` in labels `[benign, malicious]` order; test support is 14,800 benign and 1,200 malicious rows. The class imbalance makes accuracy alone misleading. ROC-AUC and average precision summarize ranking on the held-out set, not independent-seed generalization; only four held-out seeds exist. This model has not been compared to the deterministic detector at a matched node-level operating point and should not be claimed superior.

Artifacts: `results/ml_phase4_hardened/model.joblib`, `node_features.csv`, `test_predictions.csv`, `feature_importance.csv`, and `ml_metrics.json`. The earlier `results/ml_phase4_200m/` output is retained unchanged. Training output is reproducible from the retained trace matrix; do not treat these simulation results as NS-3 evidence.
