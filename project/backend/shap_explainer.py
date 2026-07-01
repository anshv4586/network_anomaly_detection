import os
import pickle
import numpy as np
import shap

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
_explainer = None
_feature_names = None

def load_explainer():
    global _explainer, _feature_names
    if _explainer is not None:
        return _explainer, _feature_names
        
    xgb_path = os.path.join(MODELS_DIR, "xgboost.pkl")
    meta_path = os.path.join(MODELS_DIR, "meta.pkl")
    
    if not os.path.exists(xgb_path) or not os.path.exists(meta_path):
        raise FileNotFoundError("Models or metadata files not found. Train the models first.")
        
    with open(xgb_path, "rb") as f:
        xgb_model = pickle.load(f)
    with open(meta_path, "rb") as f:
        meta = pickle.load(f)
        
    _feature_names = meta["features"] + ["if_anomaly_score"]
    _explainer = shap.TreeExplainer(xgb_model)
    
    return _explainer, _feature_names

def explain_prediction(X_aug_scaled_row: np.ndarray) -> tuple[list[dict], str]:
    """
    Computes local SHAP values for a single flow record.
    Returns:
        contributions: List of dicts representing feature and its SHAP value impact.
        text_explanation: Natural language explanation summarizing main causes of threat.
    """
    explainer, feature_names = load_explainer()
    
    # Compute SHAP values for the single row
    # X_aug_scaled_row should be 1D, shape: (11,)
    row_input = X_aug_scaled_row.reshape(1, -1)
    shap_values = explainer(row_input).values[0]
    
    # Map feature names to user-friendly titles
    pretty_names = {
        "flow_byts_s": "Flow Bytes/s",
        "flow_pkts_s": "Flow Packets/s",
        "fwd_bytes": "Fwd Packet Bytes",
        "bwd_bytes": "Bwd Packet Bytes",
        "total_pkts": "Total Packet Count",
        "syn_flag": "SYN Flag Count",
        "rst_flag": "RST Flag Count",
        "fin_flag": "FIN Flag Count",
        "flow_duration_s": "Flow Duration",
        "pkt_len_mean": "Packet Length Mean",
        "if_anomaly_score": "Isolation Forest Anomaly Score"
    }
    
    contributions = []
    for name, val in zip(feature_names, shap_values):
        contributions.append({
            "feature": name,
            "display_name": pretty_names.get(name, name),
            "impact": float(val)
        })
        
    # Sort contributions by absolute impact descending
    contributions_sorted = sorted(contributions, key=lambda x: abs(x["impact"]), reverse=True)
    
    # Gather top features with positive impacts (which pushed model prediction towards Attack)
    positive_impacts = [c for c in contributions_sorted if c["impact"] > 0.01]
    
    if len(positive_impacts) > 0:
        top_features = [c["display_name"] for c in positive_impacts[:4]]
        if len(top_features) > 1:
            features_text = ", ".join(top_features[:-1]) + f", and {top_features[-1]}"
        else:
            features_text = top_features[0]
        text_explanation = f"The flow was flagged as highly suspicious mainly because {features_text} contributed the most to the threat signature."
    else:
        text_explanation = "The anomaly was detected due to a combination of subtle deviations from the baseline traffic profile."
        
    return contributions_sorted, text_explanation
