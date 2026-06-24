# Project Progress — Network Anomaly Detection

Last updated: 2026-06-24

---

## Environment

- **Python**: `C:\Users\ADRIN-ISRO\anaconda3\envs\yolov8\python.exe`
  - The base anaconda Python is broken (SRE module mismatch from a bomba_backend editable install)
  - Always use the `yolov8` conda env — it has sklearn 1.7.2, numpy, pandas, matplotlib
- **Run commands from**: `E:\Projects Internet room\anamoly_detection\`

---

## Codebase Map

| File | What it does |
|---|---|
| `anomaly_detector_v2.py` | Core Isolation Forest detector. Accepts PCAP or CSV log. Computes 9 features per (5-min window × src_ip). Rule-based type labelling. |
| `run_ctu13.py` | Runs IF on CTU-13 real botnet data. 10 hand-picked CICFlowMeter features. Has ground-truth precision/recall. **Baseline numbers live here.** |
| `run_ctu13_v2.py` | All-57-features version. Showed that naive "use all features" hurts IF due to curse of dimensionality. |
| `agent.py` | OpenAI GPT-4o tool-calling agent over the detector. Calls `analyze_traffic` + `lookup_cve`. Requires `OPENAI_API_KEY`. |
| `cve_db.py` | Static CVE / MITRE ATT&CK lookup table for 6 attack types. |
| `explain_isolation_forest.py` | Educational script. Hand-crafted 13-point dataset. Shows decision paths, path lengths, feature splits for a single tree. Run this to understand IF internals. |
| `generate_sample_log.py` | Generates synthetic `sample_logs/network_traffic.log` |
| `generate_sample_pcap.py` | Generates synthetic PCAP |

---

## Dataset

**CTU-13** (real botnet capture, CICFlowMeter pre-processed)
- `sample_logs/CTU13_Attack_Traffic.csv` — 38,898 flows, Label=1
- `sample_logs/CTU13_Normal_Traffic.csv` — 53,314 flows, Label=0
- 59 columns total (57 features + `Unnamed: 0` + `Label`)
- Each row = one **flow** (already aggregated by CICFlowMeter, not raw packets)
- Features include: byte rates, packet counts, flag counts (SYN/RST/FIN), inter-arrival times, idle/active periods

---

## Feature Engineering — Two Different Approaches

### In `anomaly_detector_v2.py` (raw log/PCAP input)
Features are **computed by us** from raw packet rows via `build_features()`:
```
Raw data columns: timestamp, src_ip, dst_ip, dst_port, bytes, status
Groupby: (5-min window, src_ip)
Output features:
  n_packets     = count of packets
  n_bytes       = sum of bytes
  avg_bytes     = mean bytes per packet
  std_bytes     = std dev of packet sizes
  n_dst_ports   = nunique(dst_port)   ← catches port scans
  n_dst_ips     = nunique(dst_ip)     ← catches lateral movement
  failed_ratio  = failed / total      ← catches brute force
  hour_sin/cos  = cyclical time encoding
```

### In `run_ctu13.py` (CTU-13 CSV input)
Features are **already in the CSV** (CICFlowMeter computed them):
```
flow_byts_s    <- "Flow Byts/s"
flow_pkts_s    <- "Flow Pkts/s"
fwd_bytes      <- "TotLen Fwd Pkts"
bwd_bytes      <- "TotLen Bwd Pkts"
total_pkts     <- "Tot Fwd Pkts" + "Tot Bwd Pkts"
syn_flag       <- "SYN Flag Cnt"
rst_flag       <- "RST Flag Cnt"
fin_flag       <- "FIN Flag Cnt"
flow_duration_s<- "Flow Duration" / 1e6
pkt_len_mean   <- "Pkt Len Mean"
```

---

## Experiments & Results

### Experiment 1 — Baseline: 10 features (`run_ctu13.py`)

```
Sample: 6,000 attack + 6,000 normal = 12,000 flows
Contamination: 0.40 (matching true ratio)
Features: 10 (hand-picked from CICFlowMeter columns)

Precision : 69.5%
Recall    : 55.5%
F1        : 61.7%
Accuracy  : 65.6%

Confusion matrix:
  TN=4,541   FP=1,459
  FN=2,671   TP=3,329
```

**Key observation**: Top-ranked anomalies (lowest IF score) had `Ground Truth: Normal`.
IF flags statistically unusual normal flows (high byte rate video streams, backups) above actual attacks.

### Experiment 2 — All 57 features (`run_ctu13_v2.py`)

```
Same sample, same contamination
Features: 57 (all CICFlowMeter columns, log1p on 54 skewed cols)

Precision : 58.4%   (-11.1 vs baseline)
Recall    : 46.7%   (-8.8 vs baseline)
F1        : 51.9%   (-9.8 vs baseline)
Accuracy  : 56.7%

TN=4,004   FP=1,996
FN=3,196   TP=2,804
```

**Key finding — Curse of Dimensionality:**
More features hurt because IF picks features randomly at each split. With 57 features,
most splits land on correlated or uninformative columns, diluting the signal from the
10 actually discriminative features.

**PR curve optimal threshold (ignoring fixed contamination):**
```
Score cut: -0.3959
Precision: 64.3%   Recall: 100.0%   F1: 78.3%
```
At the right threshold, every attack can be caught — at the cost of more false alarms.
This shows the score signal is there; the threshold is the bottleneck.

### Experiment 3 — Isolation Forest Internals (educational)

Hand-crafted 13-point dataset (10 normal + 3 anomalies), 5 trees, 3 features.

```
Port Scan   (n_dst_ports=847)  : isolated in 1 split   avg depth=1.8
Exfiltration (n_bytes=5000 KB) : isolated in 2 splits  avg depth=1.8
Brute Force (failed_ratio=0.97): isolated in 4 splits  avg depth=3.6
Normal points                  : isolated in 4 splits  avg depth=4.0
```

Brute Force is hard because it only breaks one feature (failed_ratio) with a narrower
range — random cuts are less likely to hit it quickly.

---

## What We Know Doesn't Work

- **Naive "use all features"**: Hurts IF due to curse of dimensionality. Need feature selection first.
- **Fixed contamination parameter**: PR curve shows optimal threshold differs from contamination-implied one.

---

## Roadmap to 90% Precision + Recall

| Step | What | Expected gain | Status |
|---|---|---|---|
| 1 | Use all 57 features + log1p | Tried — made it worse | Done |
| 2 | Feature selection (top 15-20 by mutual info / RF importance) | +8–12 pts recall | Next |
| 3 | Threshold tuning via PR curve instead of fixed contamination | +5–8 pts | Partially shown |
| 4 | Extended Isolation Forest (fixes linear split bias) | +3–5 pts | Not started |
| 5 | Ensemble: IF + LOF vote | +4–6 pts recall | Not started |
| 6 | SHAP explainability (Direction 1 from RESEARCH.md) | Research output | Not started |
| 7 | Semi-supervised: use 10% labels to calibrate threshold | +8–12 pts both | Not started |

**Honest ceiling estimates:**
- Unsupervised only (steps 2–5): ~75–82% on both metrics
- Semi-supervised (step 7): ~87–92%
- Fully supervised (Random Forest baseline): ~96–99%

---

## Research Directions (from RESEARCH.md)

1. **SHAP Explainability** — Most publishable. Medium effort. `pip install shap`.
2. **Benchmarking** — IF vs OC-SVM vs Autoencoder vs LOF on same CTU-13 split.
3. **Federated Detection** — High effort. Best CV story (ISRO/ADRIN angle).
4. **Streaming** — River library. Medium-high effort.

Recommended: Direction 1 + 2 together (same experimental setup, complete paper).

---

## Next Session Starting Point

Run this to verify env works:
```
C:\Users\ADRIN-ISRO\anaconda3\envs\yolov8\python.exe run_ctu13.py
```

Next task: **Feature selection** — run mutual information between each of 57 features
and the true label, keep top 15–20, re-run IF. Expected to beat baseline.
