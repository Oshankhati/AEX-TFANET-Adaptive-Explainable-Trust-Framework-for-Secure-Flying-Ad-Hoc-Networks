# Trust model

**Status:** Implemented in Phase 3 as a configurable project formulation, not as a formula specified by the project PDFs. See [docs/trust_engine.md](trust_engine.md) for input semantics, equations, config, outputs, tests, and limits.

Direct trust uses a configurable Beta/Laplace estimator. Indirect trust is weighted by the observer's estimate of each recommending neighbour and is unavailable when recommendation evidence is insufficient. Historical trust uses a configurable EWMA. Final trust normalizes component weights across available evidence and applies distinct configured decay/recovery rates. Trust remains relational by observer, target, and timestamp.
