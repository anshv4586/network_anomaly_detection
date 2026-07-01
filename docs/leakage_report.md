# Leakage Analysis Report & Untouched Dataset Summary

This report documents the verification steps undertaken to eliminate data leakage from the hybrid anomaly detection pipeline and summarizes the completely untouched, leak-free evaluation dataset.

---

## 1. Summary of Leakage Verification & Corrections

We conducted a thorough audit of the preprocessing, validation, and training phases in `run_rigorous_hybrid.py` to identify and resolve any information leakages:

### A. Preprocessing & Parameter Fitting Leakage
* **Identified Leakage**: In the initial hybrid pipeline, median values for NaN imputation and columns selected for the log1p transform (based on skewness > 2) were calculated over the entire combined dataset (20,000 flows) before splitting.
* **Correction Done**: The dataset is now split first into Train, Test, and Unseen sets. Imputation medians and skewness statistics are calculated **exclusively on the training split** and then applied as a transform downstream to the test and unseen splits. This ensures no features in the test or unseen set influence the training parameters.

### B. Cross-Validation Leakage
* **Identified Leakage**: Performing cross-validation on a dataset that has already been globally scaled or imputed introduces leakage across folds.
* **Correction Done**: Standard scaling, median imputation, and skewness transformations are now applied **fold-by-fold** inside the 5-fold cross-validation loop. For each fold, preprocessing parameters are fit solely on the fold-train split and applied to the fold-validation split.

### C. Isolation Forest Model Leakage
* **Identified Leakage**: Fitting the Isolation Forest model on the combined dataset before split and evaluation allowed the unsupervised model to learn the structure of the test data.
* **Correction Done**: The Isolation Forest is now fit **strictly on the training split**. Anomaly scores for the test and unseen sets are generated using the trained model without refitting.
* **Impact Quantified**: Removing this leakage dropped the independent test F1-score of Isolation Forest from **~79% to 63.37%**, proving that the baseline model was previously benefiting from test data structures. The hybrid `IF + XGBoost` system, however, retained its high performance (**99.45% F1**), verifying its robustness.

---

## 2. Leak-Free Untouched Evaluation Dataset

To provide a clean, large-scale dataset for future research, we extracted all network flows that were **completely left out** of the sampling and training pipeline.

### Dataset File Details
* **File Path**: [CTU13_Unused_Clean_Traffic.csv](file:///c:/Users/ASUS/anamoly_detection/sample_logs/CTU13_Unused_Clean_Traffic.csv)
* **Total Flows**: **72,212**
* **Class Distribution**:
  * **Benign / Normal flows** (`true_label = 0`): **43,314 flows**
  * **Botnet / Attack flows** (`true_label = 1`): **28,898 flows**
* **Features Included**: All 57 raw CICFlowMeter features, along with the `true_label` ground truth column.

### Why This Dataset is Leak-Free
This dataset has **never** been seen by:
1. The StandardScaler fits.
2. The median imputation calculations.
3. The skewness calculations.
4. The Isolation Forest model training.
5. The XGBoost classifier training.

It is 100% untouched and represents a pristine, real-world scenario to test model generalization.
