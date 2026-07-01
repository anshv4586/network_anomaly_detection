# Research Directions

Ideas discussed 2026-06-24 for elevating this from demo to research project.

---

## Direction 1 — Explainability with SHAP (most publishable)

Isolation Forest is a black box — it flags anomalies but doesn't say why.
Add SHAP values to explain which features drove each anomaly score.

**Research question:** *Which network features most strongly predict each attack type in unsupervised anomaly detection?*

- Add `shap` library, compute SHAP values per flagged window
- Show feature attribution per anomaly: "this Port Scan was flagged because `n_dst_ports=847` contributed 0.73 to the anomaly score"
- Feed SHAP explanation into the agent — LLM explains mechanistically, not just pattern-matches on type
- Compare feature importance across attack types — does DDoS look different from exfiltration in feature space?

**Output:** Paper — *"Explainable Network Anomaly Detection with Isolation Forest and SHAP"*

**Effort:** Medium. `shap` integrates with sklearn directly.

---

## Direction 2 — Benchmarking IF vs. Other Methods

Use CTU-13 to properly benchmark multiple detectors on the same dataset, same split, same metrics.

| Method | Precision | Recall | F1 | Notes |
|---|---|---|---|---|
| Isolation Forest (current) | 69.5% | 55.5% | - | Baseline |
| One-Class SVM | ? | ? | ? | |
| Autoencoder | ? | ? | ? | |
| LOF (Local Outlier Factor) | ? | ? | ? | |
| Statistical Z-score (v1) | ? | ? | ? | |

Focus on **per attack type** breakdown — no one has done this cleanly on CTU-13.

**Research question:** *Which unsupervised method works best per attack type, and why?*

**Output:** Comparison table + short paper or detailed Medium article.

**Effort:** Low-medium. Same dataset, swap the model.

> Recommended: Do Direction 1 + Direction 2 together. They share the same experimental setup and together make a complete paper.

---

## Direction 3 — Federated Anomaly Detection

Make the detector distributed — each node runs a local Isolation Forest, shares only model parameters (not raw traffic).

- 3 "ground stations" as separate processes (mirrors the Flower federated learning repo)
- Each fits on local traffic
- Central aggregator combines forests
- Evaluate: does federated match centralised performance while keeping traffic private?

**Research question:** *Does federated anomaly detection match centralised performance while preserving traffic privacy?*

**Why this matters:** Connects directly to ISRO/ADRIN satellite edge node work.
No one else applying to OpenAI will have this combination.

**Output:** Paper or conference talk (IEEE S&P workshop, USENIX Security workshop).

**Effort:** High. Do after Direction 1+2.

---

## Direction 4 — Streaming / Real-Time Detection

Current detector is batch (full file in). Make it online / streaming.

- Use `River` library for incremental Isolation Forest (fits one window at a time)
- Agent monitors a live interface or Kafka topic
- Alerts in real-time instead of post-hoc

**Research question:** *How does detection latency and accuracy degrade when moving from batch to streaming Isolation Forest?*

**Effort:** Medium-high. Needs infrastructure (Kafka or live pcap tap).

---

## Recommended Order

1. **Direction 1 + 2** — explainability + benchmarking. Fastest path to a real research output.
2. **Direction 3** — federated. Best story for CV and OpenAI DX role. Do after 1+2.
3. **Direction 4** — streaming. Nice-to-have, more engineering than research.
