#!/usr/bin/env python3
"""
IDS Machine Learning Pipeline
=============================
Handles model training (on CTU-13 data), preprocessing, inference,
SHAP value computation, and packet feature extraction.
"""

import os
import sys
import numpy as np
import pandas as pd
import shap
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier

class IDSPipeline:
    def __init__(self):
        self.scaler = StandardScaler()
        self.if_model = None
        self.aug_scaler = StandardScaler()
        self.xgb_model = None
        self.explainer = None
        
        self.feature_names = [
            "flow_byts_s", "flow_pkts_s", "fwd_bytes", "bwd_bytes", "total_pkts",
            "syn_flag", "rst_flag", "fin_flag", "flow_duration_s", "pkt_len_mean"
        ]
        self.augmented_feature_names = self.feature_names + ["if_anomaly_score"]
        
    def train_baseline(self, attack_csv=None, normal_csv=None, n_samples=500):
        """Train models on CTU-13 data to initialize scaler, Isolation Forest, and XGBoost."""
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        if attack_csv is None:
            attack_csv = os.path.join(base_dir, "data", "ctu13", "CTU13_Attack_Traffic.csv")
        if normal_csv is None:
            normal_csv = os.path.join(base_dir, "data", "ctu13", "CTU13_Normal_Traffic.csv")
        print("[*] IDSPipeline: Training baseline models on CTU-13 data...")
        if not os.path.exists(attack_csv) or not os.path.exists(normal_csv):
            raise FileNotFoundError(f"Missing base CTU-13 logs: {attack_csv} or {normal_csv}")
            
        import gc
        # Load a tiny slice of rows using the python engine to guarantee execution under tight memory
        atk = pd.read_csv(attack_csv, nrows=1000, engine='python').sample(n=min(n_samples, 1000), random_state=42)
        nrm = pd.read_csv(normal_csv, nrows=1000, engine='python').sample(n=min(n_samples, 1000), random_state=42)
        
        atk["true_label"] = 1
        nrm["true_label"] = 0
        df = pd.concat([atk, nrm], ignore_index=True)
        
        del atk
        del nrm
        gc.collect()
        
        # Feature mapping to 10 core features
        X_df = pd.DataFrame()
        X_df["flow_byts_s"]     = pd.to_numeric(df["Flow Byts/s"], errors="coerce").fillna(0).clip(0)
        X_df["flow_pkts_s"]     = pd.to_numeric(df["Flow Pkts/s"], errors="coerce").fillna(0).clip(0)
        X_df["fwd_bytes"]       = pd.to_numeric(df["TotLen Fwd Pkts"], errors="coerce").fillna(0)
        X_df["bwd_bytes"]       = pd.to_numeric(df["TotLen Bwd Pkts"], errors="coerce").fillna(0)
        X_df["total_pkts"]      = (pd.to_numeric(df["Tot Fwd Pkts"], errors="coerce").fillna(0) +
                                   pd.to_numeric(df["Tot Bwd Pkts"], errors="coerce").fillna(0))
        X_df["syn_flag"]        = pd.to_numeric(df["SYN Flag Cnt"], errors="coerce").fillna(0)
        X_df["rst_flag"]        = pd.to_numeric(df["RST Flag Cnt"], errors="coerce").fillna(0)
        X_df["fin_flag"]        = pd.to_numeric(df["FIN Flag Cnt"], errors="coerce").fillna(0)
        X_df["flow_duration_s"] = pd.to_numeric(df["Flow Duration"], errors="coerce").fillna(0) / 1e6
        X_df["pkt_len_mean"]    = pd.to_numeric(df["Pkt Len Mean"], errors="coerce").fillna(0)
        
        y = df["true_label"].values
        
        # Scale baseline features
        X_scaled = self.scaler.fit_transform(X_df)
        
        # Train Unsupervised Isolation Forest
        contam = float(np.mean(y))
        if contam <= 0 or contam >= 1:
            contam = 0.40
            
        self.if_model = IsolationForest(n_estimators=100, contamination=contam, random_state=42, n_jobs=-1)
        self.if_model.fit(X_scaled)
        
        # Generate Isolation Forest Anomaly Scores (negated score_samples so higher is more anomalous)
        if_scores = -self.if_model.score_samples(X_scaled)
        
        # Append score as 11th feature
        X_aug = np.hstack([X_scaled, if_scores.reshape(-1, 1)])
        
        # Fit Augmented Scaler
        X_aug_scaled = self.aug_scaler.fit_transform(X_aug)
        
        # Train XGBoost
        self.xgb_model = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, n_jobs=-1, eval_metric="logloss")
        self.xgb_model.fit(X_aug_scaled, y)
        
        # Init SHAP explainer
        self.explainer = shap.TreeExplainer(self.xgb_model)
        
        print("[+] IDSPipeline: Baseline training completed successfully.")

    def predict_flows(self, df_flows):
        """
        Accepts a DataFrame containing the 10 core features.
        Preprocesses them, runs Isolation Forest & XGBoost, and returns predictions with SHAP explainability.
        """
        if self.xgb_model is None:
            raise RuntimeError("Pipeline has not been trained. Call train_baseline() first.")
            
        # Reorder columns to match expected feature order
        X_raw = df_flows[self.feature_names].copy()
        
        # Fill missing values and scale
        X_raw.fillna(0, inplace=True)
        X_scaled = self.scaler.transform(X_raw)
        
        # Unsupervised anomaly scoring
        if_scores = -self.if_model.score_samples(X_scaled)
        
        # Build augmented features
        X_aug = np.hstack([X_scaled, if_scores.reshape(-1, 1)])
        X_aug_scaled = self.aug_scaler.transform(X_aug)
        
        # Predict class labels and probabilities
        preds = self.xgb_model.predict(X_aug_scaled)
        probs = self.xgb_model.predict_proba(X_aug_scaled)[:, 1]
        
        # Format predictions list
        results = []
        for i in range(len(df_flows)):
            pred_class = int(preds[i])
            pred_prob = float(probs[i])
            if_score = float(if_scores[i])
            
            # Map predictions to human readable strings
            threat_type = "Normal"
            severity = "Low"
            
            # Simple rule-based labeling for anomaly category based on feature outliers
            if pred_class == 1:
                row_raw = df_flows.iloc[i]
                if row_raw["syn_flag"] > 5:
                    threat_type = "Port Scan / Recon"
                    severity = "High"
                elif row_raw["total_pkts"] > 1000 or row_raw["flow_byts_s"] > 5000000:
                    threat_type = "DDoS Volumetric"
                    severity = "Critical"
                elif row_raw["fwd_bytes"] > 1000000 and row_raw["syn_flag"] < 2:
                    threat_type = "Data Exfiltration"
                    severity = "High"
                elif row_raw["pkt_len_mean"] < 80 and row_raw["total_pkts"] > 50:
                    threat_type = "Brute Force"
                    severity = "Medium"
                else:
                    threat_type = "Suspicious Traffic"
                    severity = "Medium"
            
            res_item = {
                "id": i,
                "threat_type": threat_type,
                "severity": severity,
                "probability": pred_prob,
                "if_score": if_score,
                "prediction": pred_class
            }
            results.append(res_item)
            
        return results, X_aug_scaled, if_scores

    def get_shap_explanation(self, X_aug_scaled_row):
        """Calculate local SHAP values for a single row representing an anomaly."""
        if self.explainer is None:
            self.explainer = shap.TreeExplainer(self.xgb_model)
            
        shap_vals = self.explainer(X_aug_scaled_row.reshape(1, -1)).values[0]
        
        explanation = []
        for name, val in zip(self.augmented_feature_names, shap_vals):
            explanation.append({
                "feature": name,
                "impact": float(val)
            })
            
        # Sort by absolute impact descending
        explanation = sorted(explanation, key=lambda x: abs(x["impact"]), reverse=True)
        return explanation

# ── Feature Extraction from Packet Logs / Scapy ──────────────────────────────

def extract_features_from_packets(scapy_packets):
    """
    Groups Scapy packets into bidirectional flows, calculates CICFlowMeter-like
    features, and returns a Pandas DataFrame containing the 10 core features.
    """
    from collections import defaultdict
    flows = defaultdict(list)
    
    for pkt in scapy_packets:
        # Check for IP layer
        if not pkt.haslayer("IP"):
            continue
            
        ip_layer = pkt["IP"]
        src = ip_layer.src
        dst = ip_layer.dst
        
        dport = 0
        syn_val = 0
        rst_val = 0
        fin_val = 0
        
        if pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            dport = tcp.dport
            flags = tcp.flags
            syn_val = 1 if flags & 0x02 else 0
            rst_val = 1 if flags & 0x04 else 0
            fin_val = 1 if flags & 0x01 else 0
        elif pkt.haslayer("UDP"):
            dport = pkt["UDP"].dport
            
        pkt_len = len(pkt)
        timestamp = float(pkt.time)
        
        # Bidirectional grouping key
        if src < dst:
            flow_key = (src, dst, dport)
            direction = "fwd"
        else:
            flow_key = (dst, src, dport)
            direction = "bwd"
            
        flows[flow_key].append({
            "time": timestamp,
            "len": pkt_len,
            "direction": direction,
            "syn": syn_val,
            "rst": rst_val,
            "fin": fin_val
        })
        
    flow_data = []
    for flow_key, pkts in flows.items():
        src_ip, dst_ip, dport = flow_key
        times = [p["time"] for p in pkts]
        t_start = min(times)
        t_end = max(times)
        duration = t_end - t_start
        if duration <= 0:
            duration = 0.0001
            
        # Metrics
        fwd_bytes = sum(p["len"] for p in pkts if p["direction"] == "fwd")
        bwd_bytes = sum(p["len"] for p in pkts if p["direction"] == "bwd")
        total_pkts = len(pkts)
        syn_count = sum(p["syn"] for p in pkts)
        rst_count = sum(p["rst"] for p in pkts)
        fin_count = sum(p["fin"] for p in pkts)
        
        flow_byts_s = (fwd_bytes + bwd_bytes) / duration
        flow_pkts_s = total_pkts / duration
        pkt_len_mean = np.mean([p["len"] for p in pkts])
        
        flow_data.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dport,
            "flow_byts_s": float(flow_byts_s),
            "flow_pkts_s": float(flow_pkts_s),
            "fwd_bytes": float(fwd_bytes),
            "bwd_bytes": float(bwd_bytes),
            "total_pkts": int(total_pkts),
            "syn_flag": int(syn_count),
            "rst_flag": int(rst_count),
            "fin_flag": int(fin_count),
            "flow_duration_s": float(duration),
            "pkt_len_mean": float(pkt_len_mean)
        })
        
    return pd.DataFrame(flow_data)
