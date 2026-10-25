# Likely viva questions and implementation-aligned answers

### Why FANET?
FANETs use mobile UAV nodes and changing connectivity, making route choice and relay behavior relevant security questions. This prototype studies those questions in a simplified graph model.

### Why trust?
Trust summarizes observed interaction history between an observer and a target. It can inform route cost without treating an externally assigned malicious label as routing input.

### Why adaptive trust?
The final estimate moves toward current evidence with separately configured decrease and recovery rates, so trust can respond to behavior changes. The rates are engineering choices, not calibrated constants.

### Why direct and indirect trust?
Direct trust uses an observer's actual forwarding outcomes. Indirect trust incorporates neighbors' direct opinions weighted by how much the observer trusts each recommender. Indirect evidence is unavailable when requirements are unmet; it is not imputed.

### Why EWMA?
EWMA maintains a compact history that emphasizes recent direct estimates while retaining past evidence. Its smoothing parameter is configurable and was not specified by the source PDFs.

### How is direct trust calculated?
`(successes + alpha) / (successes + failures + alpha + beta)`. Positive priors smooth small samples and keep the estimate bounded in [0,1].

### How are missing trust observations handled?
No observer-target score is created without observed send/outcome evidence. During fusion, unavailable components and their weights are omitted, then remaining weights are normalized.

### How are false positives measured?
At node level, a benign node is a false positive if any scored window is suspicious or malicious. FPR is FP/(FP+TN); results are also recorded as counts.

### What is packet dropping?
The configured UAV probabilistically drops packets it actually receives as an intermediate relay. Its configured probability controls a causal simulator decision; topology no-route drops are not attributed to the attacker.

### What is blackhole behavior?
The configured transit relay drops every packet it actually receives. Source and destination endpoints are not treated as relays. It differs from probabilistic packet-drop in its deterministic all-drop rule.

### How does the detector avoid leakage?
The detector API does not take attacker IDs or attack probability. It predicts from event traces and trust history; the CLI reads summary labels only after prediction output to calculate evaluation metrics.

### How does the routing policy react to low trust?
It assigns higher route cost to paths with low online observed forwarding reliability, while keeping the node eligible if connected. The policy does not read malicious-node labels.

### Why shortest-hop baseline?
It is a simple conventional policy that gives a paired point of comparison under the same seeds, topology, and traffic.

### Why Random Forest?
It supports nonlinear feature interactions, tabular inputs, and TreeSHAP. This project uses it as an offline baseline; it is not asserted to outperform the detector.

### How was ML leakage prevented?
Attack type/probability, attacker ID, seed, scenario, timestamp, and labels are not features. GroupShuffleSplit holds out entire seeds, and the median imputer is fit only on training rows.

### What does the ML result mean?
On 16,000 held-out temporal rows from four seeds, malicious precision was .766, recall .610, F1 .679, ROC-AUC .929, and average precision .738. Rows within a seed are correlated, so four seed groups—not 16,000 independent trials—bound generalization.

### Why SHAP? Why not LIME?
TreeSHAP is implemented against the actual saved Random Forest and produces global and signed local feature attributions. LIME was not implemented; SHAP was selected as the primary explainability method.

### What does a SHAP value mean here?
It is an attribution of a feature's contribution to the model output relative to the TreeExplainer baseline. It is not evidence that changing that feature causes network security outcomes.

### What metrics were used?
PDR, packet loss, delivered application throughput, route hops, route changes, attacked-intermediate exposure, detector confusion metrics, and held-out ML metrics. Throughput is not PHY throughput.

### Why no delay?
Packets are forwarded within a simulation timestep; per-hop transmission and queueing delay are not represented. Delay is reported as not modeled/measured, not zero.

### Why no NS-3?
NS-3 was unavailable in the validated environment, and the included C++ starter was not compiled or run. The Python simulator is explicitly labeled NOT NS-3 and is not a silent substitute.

### What is the strongest measured routing observation?
In the paired 20-seed p=.8 scenario, trust-aware mean PDR was .9353 vs .9167 and attacker-intermediate exposure was 1.94% vs 4.43%. This is descriptive for this simulator and configuration, not universal superiority.

### What is the detector's main limitation?
At p=.25 it missed 9 of 20 attacked-node runs, despite zero false positives in the tested matrix. Sensitivity depends on observed relay opportunities and attack intensity.

### Main contribution?
An integrated, modular and tested workflow that converts actual simulated packet outcomes into relational trust, causal behavior alerts and online route preferences, with a paired baseline, seed-grouped ML, SHAP, and traceable results. It demonstrates a model-based method, not a deployment-ready radio protocol.
