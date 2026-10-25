# Explainable AI

**Status:** SHAP is implemented and verified on the trained Random Forest model. LIME is not implemented.

Run `python -m aex_tfanet explain --input results/ml_phase4_hardened --output results/xai_phase4_hardened`. SHAP is computed for the malicious class using the actual saved Random Forest and held-out seed rows. Global mean absolute SHAP values use a deterministic, evenly spaced sample of up to 512 held-out snapshots for bounded runtime; the local explanation is for an actual held-out snapshot. Each local value includes the signed contribution, while global importance uses absolute contribution. The selected row and its ground truth/model prediction are recorded in `xai_status.json`.

The verified hardened run used SHAP 0.54.1 on Python 3.13.2. Global top features were forwarding ratio, delivery ratio, packets dropped, and indirect trust. A Random Forest impurity importance CSV remains a separate fallback, explicitly **not SHAP**. If import or explanation fails in another environment, the command records `Unavailable in current environment` and writes no fabricated values. **LIME was not implemented; SHAP was selected as the primary explainability method.**
