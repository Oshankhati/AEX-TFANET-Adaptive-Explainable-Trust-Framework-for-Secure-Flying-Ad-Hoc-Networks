# Reproducibility record

## Validated environment

| Item | Recorded value |
|---|---|
| OS | Windows (win32) |
| Python | 3.13.2 |
| NumPy / pandas | 2.1.3 / 2.3.0 |
| scikit-learn / matplotlib | 1.5.2 / 3.10.0 |
| NetworkX / PyYAML / joblib | 3.5 / 6.0.2 / 1.5.1 |
| SHAP / Streamlit | 0.54.1 / 1.66.0 (optional; installed for verified outputs) |
| LIME | Not implemented; not required |
| Backend | Simplified Python FANET Model — NOT NS-3 |
| NS-3 | Not detected; C++ starter is prepared/unvalidated |
| Primary matrix seeds | 42–61 inclusive |
| ML random state | 42 |

See `python -m aex_tfanet env` for a fresh host probe. Dependencies in `pyproject.toml` separate core, development, XAI, and dashboard extras. The project records minimum dependency versions, not a full lockfile; exact versions above describe the validated run environment. Install optional packages in an isolated virtual environment. In the previously used shared environment, `pip check` reports FastAPI 0.115.5 versus Starlette 1.9.0 incompatibility; see `docs/limitations.md`.

## Repeatable workflows

```powershell
python -m aex_tfanet simulate --config experiments/configs/normal.yaml --backend python
python -m aex_tfanet validate-detection --output results/phase4_validation_200m --refresh-existing
python -m aex_tfanet route --output results/routing_comparison_seed42_61 --seeds 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 --drop-probability 0.8
python -m aex_tfanet ml --input results/phase4_validation_200m --output results/ml_phase4_hardened
python -m aex_tfanet explain --input results/ml_phase4_hardened --output results/xai_phase4_hardened
python -m aex_tfanet experiment --config experiments/configs/packet_drop.yaml --output results/<new-run-name> --ml-model results/ml_phase4_hardened/model.joblib
```

The saved YAML and manifest are the authority for run settings. Every experiment should use an explicit seed and a fresh output path. Detection and trust are computed from actual simulation CSV traces. Ground truth is read only after detector/model predictions are saved for evaluation. ML training and held-out evaluation use disjoint seed groups, and imputation is fitted on training rows only.

The retained matrix uses 20 seeds (42–61) for topology sensitivity, detection robustness, and routing comparisons. Its aggregate standard deviations in reports are population SD over the listed runs. They are descriptive summaries, not confidence intervals or formal tests. Historical 250 m results remain separate from 200 m follow-up outputs.

## Determinism and retained evidence

Same-seed simulation output and deterministic detector output are tested for repeatability. The final release check ran `results/repro_release_a/` and `results/repro_release_b/` with the same packet-drop config, seed 42, and saved model; each produced 24 files. SHA-256 matched for 13 canonical artifacts: simulation traces/summary, trust, detection, ML predictions/metrics, local SHAP/status, and performance metrics. Full pipeline reruns can differ in timestamped output path, absolute paths in manifests, or environment metadata; those path-bearing files were excluded. SHAP uses deterministic model and row selection; underlying library/platform variations may affect floating-point serialization.

Preserve existing result directories. Rebuild only derived aggregates when explicitly requested. The completed project stores experiment configs, environment probe, seed, simulator label, source traces, processed outputs, metrics, figures, and manifest. Routing's per-run manifest points to each generated config and run directory.
