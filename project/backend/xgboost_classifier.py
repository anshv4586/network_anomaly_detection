import os
import pickle
import numpy as np
import pandas as pd

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
_xgb_model = None
_aug_scaler = None

def load_xgboost_assets():
    global _xgb_model, _aug_scaler
    if _xgb_model is not None and _aug_scaler is not None:
        return _xgb_model, _aug_scaler
        
    xgb_path = os.path.join(MODELS_DIR, "xgboost.pkl")
    scaler_path = os.path.join(MODELS_DIR, "aug_scaler.pkl")
    
    if not os.path.exists(xgb_path) or not os.path.exists(scaler_path):
        raise FileNotFoundError("XGBoost classifier assets not found. Please train models first.")
        
    with open(xgb_path, "rb") as f:
        _xgb_model = pickle.load(f)
    with open(scaler_path, "rb") as f:
        _aug_scaler = pickle.load(f)
        
    return _xgb_model, _aug_scaler

def predict_flows(X_scaled: np.ndarray, if_scores: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Combines preprocessed features with Isolation Forest anomaly scores,
    scales augmented features, and predicts anomalies using the XGBoost model.
    Returns:
        preds: Class predictions (0 = Normal, 1 = Attack)
        probs: Probability score of being an attack
        X_aug_scaled: Scaled augmented feature matrix for explanation
    """
    xgb_model, aug_scaler = load_xgboost_assets()
    
    # Construct augmented features: stack X_scaled and if_scores horizontally
    X_aug = np.hstack([X_scaled, if_scores.reshape(-1, 1)])
    X_aug_scaled = aug_scaler.transform(X_aug)
    
    preds = xgb_model.predict(X_aug_scaled)
    probs = xgb_model.predict_proba(X_aug_scaled)[:, 1]
    
    return preds, probs, X_aug_scaled

def identify_threat_type(flow_dict: dict) -> tuple[str, str]:
    """
    Classify specific attack type and severity based on flow characteristics.
    """
    syn_flag = flow_dict.get("syn_flag", 0)
    total_pkts = flow_dict.get("total_pkts", 0)
    flow_byts_s = flow_dict.get("flow_byts_s", 0)
    fwd_bytes = flow_dict.get("fwd_bytes", 0)
    pkt_len_mean = flow_dict.get("pkt_len_mean", 0)
    
    if syn_flag > 5:
        return "Port Scan / Recon", "High"
    elif total_pkts > 1000 or flow_byts_s > 5000000:
        return "DDoS Volumetric", "Critical"
    elif fwd_bytes > 1000000 and syn_flag < 2:
        return "Data Exfiltration", "High"
    elif pkt_len_mean < 80 and total_pkts > 50:
        return "Brute Force", "Medium"
    else:
        return "Suspicious Traffic", "Medium"
