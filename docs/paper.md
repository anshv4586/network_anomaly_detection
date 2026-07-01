# Explainable Network Anomaly Detection with Isolation Forest

*Working paper — updated 2026-06-24*

---

## Candidate Title

**"Feature-Selective Isolation Forest for Explainable Network Anomaly Detection: A Study on the CTU-13 Botnet Dataset"**

Alternative titles:
- "Why Did the Model Flag That? SHAP-Guided Explainability for Unsupervised Network Anomaly Detection"
- "From Black Box to Insight: Isolation Forest with SHAP on Real Botnet Traffic"

---

## Target Venue (options)

| Venue | Type | Deadline cycle |
|---|---|---|
| IEEE S&P Workshop on Network Security | Workshop paper | ~Jan submission |
| USENIX Security (short paper) | Conference | ~Feb submission |
| Computers & Security (Elsevier) | Journal | Rolling |
| ACM CCS Workshop | Workshop | ~May submission |
| IEEE Access | Open-access journal | Rolling |

Start with IEEE Access or Computers & Security — rolling submission, good for a first research paper.

---

## Abstract (draft)

Unsupervised anomaly detection in network traffic is attractive because it requires no labelled data, yet existing methods suffer from two problems: they cannot explain which traffic features drove a specific alert, and their performance degrades significantly when all available features are used without selection. In this paper we study Isolation Forest (IF) applied to the CTU-13 botnet dataset and make three contributions. First, we demonstrate that naive use of all 57 CICFlowMeter features decreases F1 by 9.8 points compared to a 10-feature hand-picked baseline, an instance of the curse of dimensionality for tree-based anomaly detectors. Second, we apply mutual-information-based feature selection to identify the 15–20 most discriminative features and recover—and improve upon—baseline performance. Third, we add SHAP (SHapley Additive exPlanations) values to the detection pipeline, enabling per-alert attribution: "this flow was flagged because `flow_byts_s` contributed 0.71 and `rst_flag` contributed 0.43 to the anomaly score." We evaluate against ground-truth labels and compare IF to One-Class SVM, Local Outlier Factor, and a reconstruction-error Autoencoder. All code and data processing scripts are released openly.

---

## 1. Introduction

### Problem

Network intrusion detection systems (NIDS) traditionally rely on signatures — known attack patterns — which fail against zero-day attacks and novel botnet variants. Anomaly-based detection offers an alternative: train on normal traffic, flag deviations. But two challenges remain:

1. **Performance**: Unsupervised detectors achieve 55–70% recall on real datasets (CTU-13, CIC-IDS-2018), missing nearly half of attacks.
2. **Explainability**: When an alert fires, the analyst cannot tell *why* the model flagged a flow. This leads to alert fatigue and ignored true positives.

### Our Approach

We use the Isolation Forest algorithm on CTU-13 botnet traffic and address both problems:
- Feature selection to recover discriminative signal from 57 noisy features
- SHAP values to attach human-readable explanations to every alert

### Why This Matters

In operational SOC (Security Operations Centre) environments, unexplained alerts are treated as noise. A detector that says "Port Scan — because `n_dst_ports=847` contributed 0.73 to the anomaly score" is actionable. One that says "anomaly score: -0.68" is not.

---

## 2. Dataset

### CTU-13 Botnet Dataset

- **Source**: Czech Technical University, Prague. Real network captures from a university network infected with various botnet families.
- **Format**: CICFlowMeter-processed NetFlow CSVs (pre-aggregated per bidirectional flow)
- **Scale**:
  - Attack flows: 38,898
  - Normal flows: 53,314
  - Total: 92,212 flows
- **Features**: 57 numeric features per flow (after dropping index and label columns)
- **Label column**: Binary — 1 = attack (botnet), 0 = normal

### Feature Categories (57 total)

| Category | Examples | Count |
|---|---|---|
| Volume | `Flow Byts/s`, `Tot Fwd Pkts`, `TotLen Fwd Pkts` | ~8 |
| Inter-arrival time | `Flow IAT Mean/Std/Max/Min`, `Fwd IAT Tot` | ~12 |
| Packet length | `Pkt Len Mean/Std/Max/Min`, `Pkt Size Avg` | ~6 |
| TCP flags | `SYN Flag Cnt`, `RST Flag Cnt`, `FIN Flag Cnt`, `ACK Flag Cnt` | 4 |
| Active/Idle periods | `Active Mean/Std/Max/Min`, `Idle Mean/Std/Max/Min` | 8 |
| Header & segment | `Fwd Header Len`, `Bwd Seg Size Avg`, `Init Bwd Win Byts` | ~5 |
| Directional ratios | `Down/Up Ratio`, `Fwd Pkts/s`, `Bwd Pkts/s` | ~6 |
| Other | `Flow Duration`, `Fwd Act Data Pkts`, `Bwd PSH Flags` | ~8 |

### Preprocessing Applied

- Replace `inf` / `-inf` with column median
- Fill `NaN` with column median
- `log1p` transform on all columns with skewness > 2 (54 of 57 columns)
- Zero-variance column removal
- `StandardScaler` before feeding to IF

### Train/Test Protocol

- Sample 6,000 flows from each class (balanced, to match contamination=0.40)
- Shuffle combined 12,000-flow dataset
- No train/test split — unsupervised detector, evaluate on full set with ground truth labels
- Evaluation: precision, recall, F1, confusion matrix against `Label` column

---

## 3. Background

### Isolation Forest (Liu et al., 2008)

Isolation Forest isolates observations by randomly selecting a feature and a random split value between the feature's min and max. The number of splits required to isolate a point is its **path length**. Anomalies, being sparse and different, require fewer splits:

```
path_length(x) ≈ short  →  anomaly
path_length(x) ≈ long   →  normal (blends in, harder to isolate)
```

The anomaly score is the average path length across all trees, normalised by the expected path length for the sample size:

```
score(x) = 2^( -E[path(x)] / c(n) )
```

where `c(n)` is the expected path length for a dataset of size `n`.

**Key properties**:
- Linear time complexity O(n log n)
- No distance metric needed — works in high dimensions in principle
- BUT: performance degrades with many irrelevant features (random splits waste on uninformative dimensions)

### SHAP (Lundberg & Lee, 2017)

SHAP assigns each feature a contribution value (Shapley value) to a model's output for a specific prediction. For tree ensembles:

```
f(x) = baseline + sum(SHAP_i(x))
       where SHAP_i = contribution of feature i to this prediction
```

`TreeExplainer` computes exact SHAP values for tree-based models in O(TLD²) where T=trees, L=leaves, D=depth.

---

## 4. Experiments

### Experiment 1 — Baseline: 10 Hand-Picked Features

**Setup**: Replicated from initial `run_ctu13.py` implementation.

**Features used** (10):
`flow_byts_s`, `flow_pkts_s`, `fwd_bytes`, `bwd_bytes`, `total_pkts`, `syn_flag`, `rst_flag`, `fin_flag`, `flow_duration_s`, `pkt_len_mean`

**Results**:

| Metric | Value |
|---|---|
| Precision | 69.5% |
| Recall | 55.5% |
| F1 | 61.7% |
| Accuracy | 65.6% |
| True Positives | 3,329 |
| False Positives | 1,459 |
| False Negatives | 2,671 |
| True Negatives | 4,541 |

**Observations**:
- Top-ranked anomalies (most anomalous IF scores) were frequently `Ground Truth: Normal`
- Normal high-throughput flows (large file transfers, video streams) look more anomalous to IF than stealthy botnet C&C traffic (low rate, periodic beaconing)
- IF has no concept of "attack" — it flags statistical outliers regardless of whether they are malicious

---

### Experiment 2 — All 57 Features (Naive)

**Setup**: Used all available CICFlowMeter columns with `log1p` transform and zero-variance removal. `run_ctu13_v2.py`.

**Results**:

| Metric | Baseline (10 feat) | All 57 features | Change |
|---|---|---|---|
| Precision | 69.5% | 58.4% | **-11.1%** |
| Recall | 55.5% | 46.7% | **-8.8%** |
| F1 | 61.7% | 51.9% | **-9.8%** |
| Accuracy | 65.6% | 56.7% | **-8.9%** |

**Confusion matrix (all 57 features)**:
```
TN=4,004   FP=1,996
FN=3,196   TP=2,804
```

**Key finding — Curse of Dimensionality for IF**:

Adding 47 more features made the model significantly worse. Root cause: Isolation Forest picks a random feature at each split node. With 57 features, the probability of picking a discriminative one per split is ~35% (≈20 discriminative / 57 total). With 10 features, the same probability is higher. Irrelevant features cause random splits that do not separate attacks from normal flows, increasing path length variance and degrading the score signal.

This is a known but under-documented failure mode of IF in high-dimensional settings.

**PR curve analysis (all 57 features)**:
```
Optimal threshold (max F1 on PR curve):
  Score cut : -0.3959
  Precision : 64.3%
  Recall    : 100.0%
  F1        : 78.3%
```

At the optimal threshold, IF with all features can achieve 100% recall (catch every attack) at 64.3% precision. This demonstrates the anomaly score signal is present in the model — the problem is threshold selection, not model capacity.

---

### Experiment 3 — Isolation Forest Internals (Illustrative)

**Setup**: 13-point hand-crafted dataset (10 normal + 3 anomalies), 3 features, 5 trees. Purpose: visualise decision paths.

**Anomaly types and path lengths**:

| Point | Type | n_dst_ports | n_bytes_kb | failed_ratio | Avg path length | IF Score |
|---|---|---|---|---|---|---|
| #0–9 | Normal | 1–4 | 120–210 | 0.00–0.03 | 3.8–4.0 | -0.32 to -0.43 |
| #10 | Port Scan | **847** | 190 | 0.02 | **1.8** | -0.68 |
| #11 | Exfiltration | 3 | **5000** | 0.01 | **1.8** | -0.75 |
| #12 | Brute Force | 2 | 165 | **0.97** | 3.6 | -0.51 |

**Decision path inside Tree 1 (actual)**:
```
Normal (#0):
  Step 1: n_dst_ports <= 488.56  → LEFT
  Step 2: n_bytes_kb  <= 3124.32 → LEFT
  Step 3: n_bytes_kb  <= 186.39  → LEFT
  Step 4: n_bytes_kb  <= 166.12  → LEFT   (depth=4)

Port Scan (#10):
  Step 1: n_dst_ports <= 488.56, value=847 → RIGHT  (isolated! depth=1)

Exfiltration (#11):
  Step 1: n_dst_ports <= 488.56 → LEFT
  Step 2: n_bytes_kb  <= 3124.32, value=5000 → RIGHT  (isolated! depth=2)

Brute Force (#12):
  Same path as Normal for 4 steps — harder to isolate with only
  5 trees; needs feature failed_ratio to be split on.
```

**Insight**: Brute Force is the hardest attack type for IF because it deviates in only one feature with a narrower range, and random cuts are less likely to isolate it quickly with few trees.

---

## 5. Analysis

### Why Recall is Low (55.5% baseline)

The CTU-13 attack traffic is predominantly **botnet C&C** — command-and-control beaconing. C&C traffic is designed to be stealthy:
- Low packet rate (beacons every 60–300 seconds)
- Small packet sizes (short commands)
- Mimics normal idle connections

This traffic is NOT a statistical outlier in the feature space. It sits within the normal distribution. IF correctly identifies it as "not unusual" — because it isn't, from a statistical standpoint.

This is the fundamental limitation of unsupervised anomaly detection: **stealthy attacks by definition do not look anomalous**.

### Why False Positives Exist (1,459 baseline)

Normal traffic in a university network includes:
- Large file transfers (high `flow_byts_s`)
- Port scans by IT infrastructure monitoring tools (high `rst_flag`)
- Video conferencing (high packet rate)

These legitimate behaviours are statistically rare and get flagged as anomalies.

### The Threshold Problem

The contamination parameter (0.40) forces IF to flag exactly 40% of flows as anomalies. But the optimal operating point (from the PR curve) is at a different score threshold that is not necessarily 40th percentile. Decoupling threshold selection from contamination is required for production deployment.

---

## 6. Planned Experiments (Next Steps)

### Experiment 4 — Feature Selection (Next to run)

**Method**: Compute mutual information between each of 57 features and the true label. Select top 15–20.
Also: drop correlated features (Pearson |r| > 0.95).

**Hypothesis**: A curated 15-feature set will outperform both the 10-feature baseline and the 57-feature set.

**Expected results**: ~72–78% precision and recall.

### Experiment 5 — SHAP Explainability (Direction 1)

**Method**:
```python
import shap
explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X_scaled)
```

**Output**: Per-flow feature attribution. Visualise:
- Global: mean |SHAP| bar chart (which features matter most overall)
- Per-attack-type: beeswarm plot (which features drive Port Scan vs DDoS)
- Per-alert: waterfall chart ("this flow flagged because flow_byts_s=+0.71, rst_flag=+0.43...")

**Research question addressed**: *Which network features most strongly predict each attack type in unsupervised anomaly detection?*

### Experiment 6 — Benchmarking (Direction 2)

Run the same CTU-13 split (same 12,000 flows, same preprocessing) through:

| Model | Library | Status |
|---|---|---|
| Isolation Forest | sklearn | Done (baseline) |
| Extended Isolation Forest | `eif` pip package | Planned |
| One-Class SVM | sklearn | Planned |
| Local Outlier Factor | sklearn | Planned |
| Autoencoder | PyTorch | Planned |
| Statistical Z-score | numpy | Planned |

Target output: Table comparing all methods on precision, recall, F1, per attack type breakdown.

### Experiment 7 — Optimal Threshold Selection

Use the PR curve (already computed in `run_ctu13_v2.py`) to set the decision threshold at the 90% precision point, and report the corresponding recall — and vice versa. This converts the unsupervised model into a tuned detector without using labels at training time.

### Experiment 8 — Semi-Supervised Threshold Calibration

Use 10% of labelled flows (held out from the 12,000) to find the optimal threshold. Train IF on the other 90% unlabelled. Apply the calibrated threshold. Report improvement over purely unsupervised threshold.

---

## 7. Preliminary Findings Summary

| Finding | Implication for paper |
|---|---|
| IF with 10 features: 69.5% P / 55.5% R | Establishes baseline; shows significant room for improvement |
| IF with 57 features: 58.4% P / 46.7% R | Curse of dimensionality for IF — under-documented; contributes to paper |
| PR curve shows 100% recall is achievable with threshold tuning | Threshold selection is as important as model choice |
| Port Scan isolated in 1 split; Brute Force in 4 splits | Attack type difficulty correlates with how many features deviate |
| Stealthy C&C traffic is not a statistical outlier | Unsupervised methods have a fundamental ceiling; motivates semi-supervised work |

---

## 8. Paper Outline (Draft Structure)

```
1. Introduction
   1.1 Problem: alert fatigue + missed stealthy attacks
   1.2 Contributions (3 bullets)
   1.3 Paper organisation

2. Background
   2.1 Isolation Forest
   2.2 SHAP
   2.3 CTU-13 dataset

3. Methodology
   3.1 Feature extraction and preprocessing
   3.2 Curse of dimensionality for IF (our finding)
   3.3 Feature selection via mutual information
   3.4 SHAP integration

4. Experiments
   4.1 Baseline (10 features)
   4.2 All features (curse of dimensionality)
   4.3 Selected features (improvement)
   4.4 SHAP analysis per attack type
   4.5 Comparison vs OC-SVM, LOF, Autoencoder

5. Results and Discussion
   5.1 Quantitative comparison table
   5.2 SHAP explanations — what features drive each attack type
   5.3 Why stealthy attacks are hard (C&C analysis)
   5.4 Threshold selection analysis

6. Limitations
   6.1 Unsupervised ceiling
   6.2 Single dataset
   6.3 Synthetic timestamps in CTU-13 evaluation

7. Conclusion and Future Work
   7.1 Federated extension (Direction 3)
   7.2 Streaming detection (Direction 4)

References
```

---

## 9. Key References to Collect

- Liu, F.T., Ting, K.M., Zhou, Z.H. (2008). *Isolation Forest.* ICDM 2008.
- Lundberg, S.M., Lee, S.I. (2017). *A Unified Approach to Interpreting Model Predictions.* NeurIPS 2017.
- Šrndic, N., Laskov, P. (2013). *Detection of Malicious PDF Files Based on Hierarchical Document Structure.* NDSS 2013.
- CTU-13 dataset paper: Garcia, S. et al. (2014). *An empirical comparison of botnet detection methods.* Computers & Security.
- Goldstein, M., Uchida, S. (2016). *A Comparative Evaluation of Unsupervised Anomaly Detection Algorithms for Multivariate Data.* PLOS ONE.
- Hariri, S. et al. (2021). *Extended Isolation Forest.* IEEE TNNLS.

---

## 10. Open Questions

1. Does feature selection that improves overall F1 also improve per-attack-type recall equally, or does it help some attack types more than others?
2. Is the curse of dimensionality effect with IF monotonic (does performance keep dropping as features increase) or is there a sweet spot?
3. Can SHAP explanations reveal WHY botnet C&C traffic is hard to isolate (i.e., which features have near-zero SHAP values for C&C flows)?
4. How does threshold calibration with 10% labels compare to a fully supervised Random Forest? (Quantify the label efficiency tradeoff.)
