# Final hardening status

**Validated as of 2026-10-21.** AEX-TFANET is ready for a B.Tech demonstration and thesis draft as a simplified-model research prototype. It is not an NS-3, radio-realistic, or field-validated network implementation.

- Full test suite: **63 passed** (`python -m pytest --basetemp=.pytest-tmp/release_suite_20261021`).
- Full seed-42 p=.8 pipeline: executed; 24 files; includes config/environment, simulation, trust, detection, ML inference, local SHAP, metrics, figures, and manifest.
- Reproducibility: `results/repro_release_a/` and `results/repro_release_b/` are two same-config, same-seed full runs; SHA-256 matched across 13 canonical artifacts (traces, trust, detection, ML prediction/metrics, SHAP/status, and performance metrics). Path/timestamp-bearing manifest fields were intentionally excluded.
- Detection: 200 m matrix, seeds 42–61; at p=.25/.50/.80, TP/TN/FP/FN = 11/180/0/9, 19/180/0/1, 20/180/0/0. Normal matrix had zero FPs among 200 benign node-runs.
- Routing: paired 80-run matrix; at p=.8, baseline/trust-aware mean PDR .9167/.9353 and attacked-intermediate exposure 4.43%/1.94%. No formal significance test; not a universal superiority claim.
- ML: 64,000 training rows, 16,000 held-out rows from four held-out seeds. Malicious precision .7665, recall .6100, F1 .6794, ROC-AUC .9288, average precision .7380. Seed groups, not rows, are the independent holdout units.
- SHAP: real TreeSHAP on the saved Random Forest; local/global output verified. LIME not implemented.
- Dashboard: updated Streamlit health endpoint returned `ok`; current visible disclaimer identifies Python simulation as non-NS-3/radio-level.
- CLI: `env` and `--help` return successfully. `env` reports NS-3 absent and optional dependencies available.
- Packaging: code/config/pyproject/egg-info versions aligned at 0.2.0. LIME removed from optional extras. An editable pip reinstall was attempted but the sandbox blocked pip's build-tracker temp path; local egg-info was regenerated from `pyproject.toml` without installing dependencies. Source-based CLI, imports, and experiments pass.

**Remaining:** NS-3 unavailable and starter unvalidated; no PHY/MAC, propagation, delay, or signaling cost; trust and detector parameters are implementation choices; p=.25 detector misses 9/20; four held-out ML seeds; shared environment has FastAPI/Starlette conflict. Full scope is in `docs/final_audit.md`, `docs/limitations.md`, and `docs/reproducibility.md`.
