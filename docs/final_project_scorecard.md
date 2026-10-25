# Final project scorecard

Scores are conservative engineering/research-readiness assessments, not grades or a claim of publication readiness. A score of 10 would require substantially broader validation than this prototype has.

| Area | Score / 10 | Reason |
|---|---:|---|
| Architecture | 8 | Clear package boundaries and an integrated pipeline; Python simulator remains an abstraction. |
| Implementation | 7 | Main pipeline and two causal attacks work; NS-3 backend remains only prepared/unvalidated. |
| Security | 6 | Label-isolated detector and routing are tested; attacker model breadth and adversarial trust cases are limited. |
| Trust model | 7 | Bounded equations, missing-evidence handling, temporal behavior, and tests; parameters are not calibrated. |
| Detection | 6 | Causal deterministic scoring and 80-run matrix; low-intensity p=.25 misses 9/20. |
| Routing | 7 | Paired 80-run baseline comparison and traceable exposure; one topology/attacker, no physical delay/cost. |
| ML | 7 | Seed-group holdout, train-only preprocessing, and full class/ranking metrics; only four held-out seed groups. |
| XAI | 7 | Real model-aligned SHAP global/local explanations; attribution is not causal and LIME is absent. |
| Experimental design | 6 | Multiple seeds, attack intensities, paired route policies, and retained artifacts; no preregistered independent final scenario set or formal inference. |
| Reproducibility | 7 | Explicit configs/seeds/manifests and byte-identical rerun evidence; no complete dependency lockfile and shared environment conflict remain. |
| Testing | 8 | Unit, integration, and end-to-end suite; simulator realism cannot be unit-tested into physical validity. |
| Documentation | 8 | Methods, results, limitations, thesis/viva materials and diagrams; add verified outside literature before thesis submission. |
| Dashboard | 7 | Read-only saved-run/sample separation, metrics and SHAP views; dashboard depends on optional Streamlit. |
| Research integrity | 9 | Provenance, label isolation, unavailable metric handling, preserved weaker results; future reports still need careful scope. |

## Overall assessment

- **Strongest aspect:** traceable, paired routing experiment joined to observed relay behavior and preserved per-seed artifacts.
- **Weakest aspect:** simulator fidelity and narrow external validity.
- **Biggest scientific limitation:** all evidence comes from a simplified graph/time-step model with a limited set of seeds, one target/placement, and uncalibrated thresholds.
- **Biggest engineering limitation:** no compiled/operational NS-3 backend; the shared optional-dependency environment also has a FastAPI/Starlette conflict.
- **Highest-value next improvement:** implement and validate the shared trace contract against a real NS-3 scenario, then repeat the preregistered paired matrix over additional topologies and held-out scenarios.

## Readiness

**Ready for a B.Tech demonstration and thesis draft as a simulation prototype**, provided the student presents the simplified-model boundary, low-intensity misses, four-seed ML test limitation, and absence of delay/PHY claims. **Not ready for claims of radio-realistic performance or field deployment.**
