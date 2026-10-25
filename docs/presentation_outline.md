# Presentation / viva deck outline (15 slides)

1. **Title** — AEX-TFANET, student/advisor/institution; identify the work as a simulation prototype.
2. **Problem** — Dynamic FANET routes can rely on relays with poor observed forwarding behavior.
3. **Motivation** — Combine behavior evidence and trust with route choice while retaining an explicit conventional baseline.
4. **Existing challenge** — Mobility, evidence scarcity, label leakage risk, simulator fidelity; avoid unsupported literature claims until citations are added.
5. **Proposed AEX-TFANET** — Relational trust, causal detector, online trust-aware route policy, offline grouped ML and explanation.
6. **Architecture** — Use the implemented pipeline diagram from `docs/diagrams.md`; highlight separate ground-truth evaluator.
7. **Trust model** — Direct Beta/Laplace, recommender-weighted indirect, EWMA, available-evidence fusion, directional adaptation. State formulas are implementation choices.
8. **Detection** — Rolling observed outcome window, normalized evidence, four statuses, node-level evaluation definition.
9. **Trust-aware routing** — Shortest-hop baseline vs configured hop/trust/link cost; no attacker IDs used in selection.
10. **ML + SHAP** — 12 features, 64k train / 16k test rows, disjoint seed groups; global and local TreeSHAP; LIME not implemented.
11. **Experimental setup** — Simplified Python model, 10 UAVs, 100 s, 200 m, seeds 42–61; packet-drop levels, blackhole demo, paired policies.
12. **Results** — Routing p=.8 PDR .9167 vs .9353 and exposure 4.43% vs 1.94%; ML F1 .679; detection misses 9/20 at p=.25.
13. **Limitations** — Explicit NOT NS-3 label; no PHY/MAC/interference/delay/overhead; one attacker placement, descriptive—not significant.
14. **Future work** — Validated NS-3, more independent scenarios/topologies, preregistered tuning, delay/control cost, measured energy.
15. **Conclusion** — Integrated, tested and traceable prototype; claims remain limited to implemented model and experiments.
