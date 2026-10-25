# Experimental design and reproducibility

The CLI runs the **Simplified Python FANET Model — NOT NS-3** explicitly. Each executed run writes its resolved configuration, environment report, random seed, simulation traces, trust/detection outputs, metrics, figures, and a manifest where applicable. See `docs/results.md` for the retained matrices and measured values.

## Retained matrix

| Study | Conditions | Seeds / runs | Artifacts |
|---|---|---:|---|
| Normal topology sensitivity | ranges 250, 200, 180, 160 m | 20 seeds per range | `results/simulator_topology_sensitivity/` |
| Detection robustness | normal and packet-drop p=.25/.50/.80 | seeds 42–61; 80 runs at 200 m, historical 80 at 250 m | `results/phase4_validation_200m/`, `results/phase4_validation/` |
| Routing comparison | normal and p=.80; baseline and trust-aware | seeds 42–61; 80 runs | `results/routing_comparison_seed42_61/` |
| ML | temporal snapshots from the 80-run 200 m matrix; seed-group split | train seeds 44–56, 58, 60, 61; test seeds 42, 43, 57, 59 | `results/ml_phase4_hardened/` (earlier output retained at `results/ml_phase4_200m/`) |
| Blackhole | configured UAV 7, deterministic transit all-drop | seed 42 demonstration | `results/blackhole_20261021T150544470332Z/` |
| Full pipeline | packet-drop p=.80, seed 42 | one descriptive demonstration | `results/final_demo_seed42_complete/` |
| SHAP | actual trained model, held-out rows and local example | deterministic 512-row global explanation sample | `results/xai_phase4_hardened/` (earlier output retained at `results/xai_phase4_200m/`) |

Normal and packet-drop routing profiles are paired on the same seed and topology; only the attack block and routing policy vary. The runner checks configuration parity outside the attack block. The detector does not receive attack labels. Attack labels are read by the evaluator only after predictions. ML splits by seed, with all temporal rows from a seed held in one partition.

## Run commands

```powershell
python -m aex_tfanet env
python -m aex_tfanet experiment --config experiments/configs/packet_drop.yaml
python -m aex_tfanet validate-detection --output results/phase4_validation_200m --refresh-existing
python -m aex_tfanet route --output results/routing_comparison_seed42_61 --seeds 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 --drop-probability 0.8
python -m aex_tfanet ml --input results/phase4_validation_200m --output results/ml_phase4_hardened
python -m aex_tfanet explain --input results/ml_phase4_hardened --output results/xai_phase4_hardened
python -m aex_tfanet dashboard
```

Use a new output folder for reruns where a command rejects non-empty output. `--refresh-existing` explicitly rebuilds derived Phase 4 summaries and figures from preserved per-run records; it does not rerun or alter the underlying historical simulations. Do not interpret the descriptive seed matrix as a formal significance test. Delay and signaling overhead are not represented by the simulator.
