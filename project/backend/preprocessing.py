import os
import pickle
import numpy as np
import pandas as pd

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))

_scaler = None
_meta = None

def load_preprocessor_assets():
    global _scaler, _meta
    if _scaler is not None and _meta is not None:
        return _scaler, _meta
        
    scaler_path = os.path.join(MODELS_DIR, "scaler.pkl")
    meta_path = os.path.join(MODELS_DIR, "meta.pkl")
    
    if not os.path.exists(scaler_path) or not os.path.exists(meta_path):
        raise FileNotFoundError("Preprocessor assets missing. Please run model training first.")
        
    with open(scaler_path, "rb") as f:
        _scaler = pickle.load(f)
        
    with open(meta_path, "rb") as f:
        _meta = pickle.load(f)
        
    return _scaler, _meta

def preprocess_features(df_raw: pd.DataFrame) -> tuple[np.ndarray, list[str]]:
    """
    Accepts raw flow DataFrame, extracts and cleans the 10 core features,
    applies log transform to skewed columns, and scales them using StandardScaler.
    Returns:
        X_scaled: Normalized 10-feature numpy array.
        feature_names: List of feature names in correct order.
    """
    scaler, meta = load_preprocessor_assets()
    medians = meta["medians"]
    skewed_cols = meta["skewed_cols"]
    feature_names = meta["features"]
    
    df = pd.DataFrame(index=df_raw.index)
    
    # Map and clean features
    for col in feature_names:
        if col in df_raw.columns:
            df[col] = pd.to_numeric(df_raw[col], errors="coerce").fillna(medians.get(col, 0.0))
        else:
            # Fallback if feature is missing
            df[col] = medians.get(col, 0.0)
            
    # Impute infinities
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    for col in feature_names:
        df[col].fillna(medians.get(col, 0.0), inplace=True)
        
    # Log transform skewed columns
    for col in skewed_cols:
        if col in df.columns:
            df[col] = np.log1p(df[col].clip(lower=0))
            
    # Standard scale
    X_scaled = scaler.transform(df[feature_names])
    
    return X_scaled, feature_names
