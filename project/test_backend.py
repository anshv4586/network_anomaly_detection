import os
import sys
import unittest
import pandas as pd
import numpy as np

# Ensure backend folder is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "backend")))

import database
import preprocessing
import isolation_forest
import xgboost_classifier
import shap_explainer

class TestIDSBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Initialize database
        database.init_db()

    def test_database_settings(self):
        # Verify default settings are present
        settings = database.get_settings()
        self.assertIn("context_window", settings)
        self.assertIn("model_selection", settings)
        
        # Test updating settings
        database.save_setting("test_key", "test_val")
        self.assertEqual(database.get_setting("test_key"), "test_val")

    def test_model_loading(self):
        # Verify model files exist and load successfully
        try:
            scaler, meta = preprocessing.load_preprocessor_assets()
            self.assertIsNotNone(scaler)
            self.assertIsNotNone(meta)
            
            if_model = isolation_forest.load_isolation_forest()
            self.assertIsNotNone(if_model)
            
            xgb_model, aug_scaler = xgboost_classifier.load_xgboost_assets()
            self.assertIsNotNone(xgb_model)
            self.assertIsNotNone(aug_scaler)
        except FileNotFoundError:
            self.fail("Trained model files are missing from project/models/")

    def test_pipeline_inference(self):
        # Test running a mock data slice through the preprocessor and models
        mock_flow = pd.DataFrame([{
            "flow_byts_s": 50000.0,
            "flow_pkts_s": 100.0,
            "fwd_bytes": 1000.0,
            "bwd_bytes": 2000.0,
            "total_pkts": 15,
            "syn_flag": 1,
            "rst_flag": 0,
            "fin_flag": 0,
            "flow_duration_s": 0.15,
            "pkt_len_mean": 200.0
        }])
        
        # 1. Preprocessing
        X_scaled, feature_names = preprocessing.preprocess_features(mock_flow)
        self.assertEqual(X_scaled.shape, (1, 10))
        
        # 2. Isolation Forest
        if_scores = isolation_forest.compute_anomaly_scores(X_scaled)
        self.assertEqual(len(if_scores), 1)
        
        # 3. XGBoost
        preds, probs, X_aug_scaled = xgboost_classifier.predict_flows(X_scaled, if_scores)
        self.assertEqual(len(preds), 1)
        self.assertEqual(len(probs), 1)
        self.assertEqual(X_aug_scaled.shape, (1, 11))
        
        # 4. SHAP explainability
        contributions, text_explanation = shap_explainer.explain_prediction(X_aug_scaled[0])
        self.assertEqual(len(contributions), 11)
        self.assertTrue(isinstance(text_explanation, str))

    def test_api_endpoints(self):
        # Use TestClient to run endpoints
        try:
            from fastapi.testclient import TestClient
            from main import app
            
            client = TestClient(app)
            
            # Status check
            res = client.get("/api/online/status")
            self.assertEqual(res.status_code, 200)
            self.assertFalse(res.json()["is_running"])
            
            # Settings check
            res = client.get("/api/settings")
            self.assertEqual(res.status_code, 200)
            self.assertIn("model_selection", res.json())
            
            # Health check
            res = client.get("/api/metrics")
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json()["status"], "Green")
        except ImportError:
            # TestClient requires httpx, skip if not installed
            pass

if __name__ == "__main__":
    unittest.main()
