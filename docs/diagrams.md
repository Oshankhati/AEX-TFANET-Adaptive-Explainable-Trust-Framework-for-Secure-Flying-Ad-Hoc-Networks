# AEX-TFANET architecture diagrams

All diagrams describe implemented behavior. The simulation box is the **Simplified Python FANET Model — NOT NS-3**.

## Overall architecture

```mermaid
flowchart LR
  U[UAV nodes and waypoint mobility] --> C[Connectivity and neighbor events]
  C --> P[Packet routes and outcomes]
  P --> M[Monitoring and CSV traces]
  M --> T[Relational adaptive trust]
  T --> D[Causal behavioral detector]
  T --> R[Trust-aware route cost]
  C --> R
  R --> B[Shortest-hop baseline comparison]
  M --> ML[Grouped Random Forest evaluation]
  T --> ML
  ML --> X[SHAP explanation]
  D --> A[Metrics and evaluation]
  B --> A
  X --> A
  A --> F[Figures, manifests, dashboard]
```

## Trust computation flow

```mermaid
flowchart TD
  S[Actual send event names next hop] --> O[Match same packet's relay outcome]
  L[Connected neighbor record] --> O
  O --> D[Direct Beta/Laplace estimate]
  O --> H[EWMA history]
  N[Neighbor direct opinions and recommender trust] --> I[Weighted indirect opinion or unavailable]
  D --> F[Normalize fusion weights over available evidence]
  I --> F
  H --> F
  F --> A[Direction-specific decay or recovery]
  A --> C[Configurable trust class]
```

## Detection flow

```mermaid
flowchart TD
  E[Packet and UAV telemetry] --> W[Causal rolling window per UAV]
  T[Trust observations available by timestamp] --> W
  W --> S[Weighted behavior score]
  S --> P[NORMAL / SUSPICIOUS / MALICIOUS / INSUFFICIENT_DATA]
  P --> Save[Write predictions]
  G[Ground-truth metadata] --> Eval[Node-level evaluator after prediction]
  Save --> Eval
```

## Routing flow

```mermaid
flowchart TD
  G[Current connectivity graph] --> B[Shortest-hop deterministic baseline]
  G --> C[Enumerate eligible simple paths]
  T[Online observed forwarding trust] --> C
  L[Current link stability] --> C
  C --> Cost[Configured weighted route cost]
  Cost --> Pick[Lowest-cost live path]
  B --> Compare[Paired seed-level evaluation]
  Pick --> Compare
  Label[Attacker ID for evaluation only] --> Exposure[Post-selection exposure metric]
  Pick --> Exposure
```

## ML and SHAP flow

```mermaid
flowchart LR
  Trace[Time-indexed telemetry] --> F[Feature snapshots]
  Trust[Trust values up to snapshot time] --> F
  F --> Split[GroupShuffleSplit by seed]
  Split --> Train[Median imputer + Random Forest fit]
  Split --> Test[Held-out predictions and scores]
  Labels[Labels attached as target; excluded from features] --> Train
  Labels --> Eval[Held-out metrics]
  Train --> Model[Saved pipeline]
  Test --> Explain[TreeSHAP local/global attribution]
  Model --> Explain
```

## Complete experimental pipeline

```mermaid
flowchart LR
  Config[YAML + seed] --> Sim[Python FANET run]
  Sim --> Trust[Trust processing]
  Trust --> Detect[Detector then evaluator]
  Sim --> Route[Route decisions]
  Sim --> Infer[ML inference if model supplied]
  Trust --> Infer
  Infer --> SHAP[Optional local SHAP]
  Detect --> Metrics[Trace-derived metrics]
  Route --> Metrics
  SHAP --> Metrics
  Metrics --> Artifacts[CSV / JSON / figures / manifest / dashboard]
```
