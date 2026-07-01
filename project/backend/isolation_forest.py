import os
import pickle
import numpy as np

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
_if_model = None

def load_isolation_forest():
    global _if_model
    if _if_model is not None:
        return _if_model
        
    model_path = os.path.join(MODELS_DIR, "isolation_forest.pkl")
    if not os.path.exists(model_path):
        raise FileNotFoundError("Isolation Forest model file not found. Please train models first.")
        
    with open(model_path, "rb") as f:
        _if_model = pickle.load(f)
        
    return _if_model

def compute_anomaly_scores(X_scaled: np.ndarray) -> np.ndarray:
    """
    Computes unsupervised anomaly scores for preprocessed flow features.
    Higher score indicates a higher likelihood of being anomalous (negated score_samples).
    """
    if_model = load_isolation_forest()
    scores = -if_model.score_samples(X_scaled)
    return scores
