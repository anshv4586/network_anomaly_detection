import os
import sys
import pickle
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier

# Add parent path to import correctly
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import database

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
ATTACK_CSV = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "ctu13", "CTU13_Attack_Traffic.csv"))
NORMAL_CSV = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "ctu13", "CTU13_Normal_Traffic.csv"))

FEATURE_NAMES = [
    "flow_byts_s", "flow_pkts_s", "fwd_bytes", "bwd_bytes", "total_pkts",
    "syn_flag", "rst_flag", "fin_flag", "flow_duration_s", "pkt_len_mean"
]

def load_and_preprocess_training_data(n_samples=5000):
    database.add_log("INFO", "Starting model training: loading CTU-13 training datasets...")
    
    if not os.path.exists(ATTACK_CSV) or not os.path.exists(NORMAL_CSV):
        err_msg = f"Training data files missing. Attack CSV: {ATTACK_CSV}, Normal CSV: {NORMAL_CSV}"
        database.add_log("ERROR", err_msg)
        raise FileNotFoundError(err_msg)
        
    # Read normal and attack datasets
    atk = pd.read_csv(ATTACK_CSV, nrows=n_samples * 2, engine="python")
    nrm = pd.read_csv(NORMAL_CSV, nrows=n_samples * 2, engine="python")
    
    # Sample to balance classes
    atk = atk.sample(n=min(n_samples, len(atk)), random_state=42)
    nrm = nrm.sample(n=min(n_samples, len(nrm)), random_state=42)
    
    atk["true_label"] = 1
    nrm["true_label"] = 0
    df = pd.concat([atk, nrm], ignore_index=True)
    
    # Map features
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
    
    # Impute infs and NaNs
    X_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    medians = X_df.median()
    X_df.fillna(medians, inplace=True)
    
    # Apply log1p transform to highly skewed variables to match comparison pipeline
    skew = X_df.skew()
    skewed_cols = skew[skew > 2].index.tolist()
    X_df[skewed_cols] = np.log1p(X_df[skewed_cols].clip(lower=0))
    
    # Keep standard medians for future inference imputations
    medians_dict = medians.to_dict()
    
    return X_df, y, medians_dict, skewed_cols

def train_and_save_models():
    os.makedirs(MODELS_DIR, exist_ok=True)
    
    try:
        X_df, y, medians, skewed_cols = load_and_preprocess_training_data()
        
        # 1. Fit Base Scaler
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_df)
        
        # 2. Fit Isolation Forest
        contam = float(np.mean(y))
        if contam <= 0 or contam >= 1:
            contam = 0.45
            
        database.add_log("INFO", f"Training Isolation Forest model (contamination={contam:.4f})...")
        if_model = IsolationForest(n_estimators=100, contamination=contam, random_state=42, n_jobs=-1)
        if_model.fit(X_scaled)
        
        # 3. Generate Anomaly Scores
        if_scores = -if_model.score_samples(X_scaled)
        
        # 4. Fit Augmented Scaler (Hybrid representation)
        X_aug = np.hstack([X_scaled, if_scores.reshape(-1, 1)])
        aug_scaler = StandardScaler()
        X_aug_scaled = aug_scaler.fit_transform(X_aug)
        
        # 5. Fit XGBClassifier
        database.add_log("INFO", "Training XGBoost Classifier model...")
        xgb_model = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, n_jobs=-1, eval_metric="logloss")
        xgb_model.fit(X_aug_scaled, y)
        
        # 6. Save Pickle Files
        models_data = {
            "scaler.pkl": scaler,
            "aug_scaler.pkl": aug_scaler,
            "isolation_forest.pkl": if_model,
            "xgboost.pkl": xgb_model,
            "meta.pkl": {
                "medians": medians,
                "skewed_cols": skewed_cols,
                "features": FEATURE_NAMES
            }
        }
        
        for name, obj in models_data.items():
            path = os.path.join(MODELS_DIR, name)
            with open(path, "wb") as f:
                pickle.dump(obj, f)
            database.add_log("INFO", f"Saved model asset to {path}")
            
        database.add_log("INFO", "Baseline ML models training and persistence completed successfully.")
        return True
    except Exception as e:
        database.add_log("ERROR", f"Error during model training: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    train_and_save_models()
