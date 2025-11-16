#!/usr/bin/env python3
"""
WinnCore ML Detector - Model Training
Trains LightGBM classifier on extracted features
"""

import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score, confusion_matrix
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType
import os

def load_dataset(csv_path):
    """
    Load features.csv and prepare for training
    
    Returns:
        X: Feature matrix (all columns except 'label')
        y: Labels (0=benign, 1=malware)
    """
    print(f"[+] Loading dataset from {csv_path}")
    df = pd.read_csv(csv_path)
    
    print(f"    Total samples: {len(df):,}")
    print(f"    Benign:        {len(df[df['label'] == 0]):,}")
    print(f"    Malware:       {len(df[df['label'] == 1]):,}")
    print(f"    Features:      {len(df.columns) - 1}")
    
    # Separate features and labels
    X = df.drop('label', axis=1)
    y = df['label']
    
    print(f"\n    Feature columns: {list(X.columns)}")
    
    return X, y

def train_model(X_train, y_train, X_test, y_test):
    """
    Train LightGBM classifier
    
    LightGBM is a gradient boosting framework that uses tree-based learning.
    It's fast, distributed, and has high performance.
    
    Parameters explained:
    - objective='binary': Binary classification (benign vs malware)
    - metric='binary_logloss': Optimization metric
    - num_leaves=31: Max number of leaves in one tree
    - learning_rate=0.05: Shrinkage rate (lower = more conservative)
    - n_estimators=100: Number of boosting rounds (trees)
    - feature_fraction=0.9: Randomly select 90% of features for each tree
    - bagging_fraction=0.8: Randomly select 80% of samples for each tree
    - bagging_freq=5: Perform bagging every 5 iterations
    """
    print("\n[+] Training LightGBM classifier...")
    
    # Create and train model
    model = lgb.LGBMClassifier(
        objective='binary',
        metric='binary_logloss',
        num_leaves=31,
        learning_rate=0.05,
        n_estimators=100,
        feature_fraction=0.9,
        bagging_fraction=0.8,
        bagging_freq=5,
        verbose=-1
    )
    
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        eval_metric='binary_logloss'
    )
    
    return model

def evaluate_model(model, X, y, dataset_name="Dataset"):
    """
    Evaluate model performance with comprehensive metrics
    """
    print(f"\n[+] Evaluating on {dataset_name}...")
    
    # Predict probabilities and classes
    y_pred_proba = model.predict_proba(X)[:, 1]
    y_pred = (y_pred_proba > 0.5).astype(int)
    
    # Calculate metrics
    accuracy = accuracy_score(y, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y, y_pred, average='binary')
    
    try:
        auc = roc_auc_score(y, y_pred_proba)
    except:
        auc = 0.0
    
    # Confusion matrix
    cm = confusion_matrix(y, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    print(f"\n{'='*60}")
    print(f"{dataset_name.upper()} PERFORMANCE")
    print(f"{'='*60}")
    print(f"Accuracy:   {accuracy*100:.2f}%")
    print(f"Precision:  {precision*100:.2f}%  (of flagged malware, % correct)")
    print(f"Recall:     {recall*100:.2f}%  (of actual malware, % detected)")
    print(f"F1 Score:   {f1*100:.2f}%  (harmonic mean)")
    print(f"ROC-AUC:    {auc:.4f}")
    
    print(f"\nConfusion Matrix:")
    print(f"  True Negatives:   {tn:,} (benign correctly identified)")
    print(f"  False Positives:  {fp:,} (benign wrongly flagged as malware)")
    print(f"  False Negatives:  {fn:,} (malware missed)")
    print(f"  True Positives:   {tp:,} (malware correctly detected)")
    
    # Score distribution analysis
    benign_scores = y_pred_proba[y == 0]
    malware_scores = y_pred_proba[y == 1]
    
    print(f"\nScore Distributions:")
    print(f"  Benign average:   {benign_scores.mean():.3f} (should be LOW)")
    print(f"  Malware average:  {malware_scores.mean():.3f} (should be HIGH)")
    print(f"  Separation:       {malware_scores.mean() - benign_scores.mean():.3f}")
    
    separation = malware_scores.mean() - benign_scores.mean()
    if separation > 0.6:
        print(f"  ✅ EXCELLENT - Strong separation between classes")
    elif separation > 0.4:
        print(f"  ✅ GOOD - Moderate separation")
    elif separation > 0.2:
        print(f"  ⚠️  FAIR - Weak separation, may struggle in production")
    else:
        print(f"  ❌ POOR - No clear separation, model not learning")
    
    print(f"{'='*60}\n")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'auc': auc
    }

def export_models(model, X_train, output_dir='models'):
    """
    Export model to both LightGBM and ONNX formats
    
    - .txt format: LightGBM native format (for Python)
    - .onnx format: Open Neural Network Exchange (for Rust/production)
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # Export LightGBM native format
    lgb_path = os.path.join(output_dir, 'gbm_v3_hardened.txt')
    model.booster_.save_model(lgb_path)
    print(f"[+] Saved LightGBM model -> {lgb_path}")
    
    # Export to ONNX for Rust inference
    try:
        initial_type = [('float_input', FloatTensorType([None, X_train.shape[1]]))]
        onnx_model = onnxmltools.convert_lightgbm(
            model, 
            initial_types=initial_type,
            target_opset=12
        )
        
        onnx_path = os.path.join(output_dir, 'gbm_v3_hardened.onnx')
        onnxmltools.utils.save_model(onnx_model, onnx_path)
        print(f"[+] Saved ONNX model -> {onnx_path}")
    except Exception as e:
        print(f"[!] Warning: ONNX export failed: {e}")
        print(f"    Model still available in LightGBM format")

def show_feature_importance(model, feature_names, top_n=10):
    """
    Display most important features for malware detection
    """
    importance = model.feature_importances_
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': importance
    }).sort_values('importance', ascending=False)
    
    print(f"\n{'='*60}")
    print(f"TOP {top_n} MOST IMPORTANT FEATURES")
    print(f"{'='*60}")
    for idx, row in feature_importance.head(top_n).iterrows():
        print(f"  {row['feature']:25s} {row['importance']:>8.0f}")
    print(f"{'='*60}\n")

def main():
    """
    Main training pipeline
    
    Steps:
    1. Load dataset (features.csv)
    2. Split train/test (80/20)
    3. Train LightGBM model
    4. Evaluate on test set
    5. Export to ONNX for Rust
    6. Show feature importance
    """
    
    # Load data
    X, y = load_dataset('features.csv')
    
    # Split train/test
    print("\n[+] Splitting train/test (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, 
        test_size=0.2, 
        random_state=42,
        stratify=y  # Preserve class distribution in both sets
    )
    
    print(f"    Train samples: {len(X_train):,}")
    print(f"    Test samples:  {len(X_test):,}")
    
    # Train model
    model = train_model(X_train, y_train, X_test, y_test)
    
    # Evaluate on test set
    test_metrics = evaluate_model(model, X_test, y_test, "Test Set")
    
    # Also evaluate on full dataset to check for overfitting
    full_metrics = evaluate_model(model, X, y, "Full Dataset")
    
    # Export models
    print("\n[+] Exporting models...")
    export_models(model, X_train)
    
    # Show feature importance
    show_feature_importance(model, X.columns, top_n=10)
    
    # Final summary
    print(f"\n{'='*60}")
    print("TRAINING COMPLETE")
    print(f"{'='*60}")
    print(f"Test Accuracy:  {test_metrics['accuracy']*100:.2f}%")
    print(f"Test F1 Score:  {test_metrics['f1']*100:.2f}%")
    print(f"Test ROC-AUC:   {test_metrics['auc']:.4f}")
    print(f"\nModels saved to: models/")
    print(f"  - gbm_v3_hardened.txt (LightGBM format)")
    print(f"  - gbm_v3_hardened.onnx (for Rust inference)")
    print(f"\nNext steps:")
    print(f"  1. Review performance metrics above")
    print(f"  2. Deploy ONNX model to WinnCoreAV:")
    print(f"     cp models/gbm_v3_hardened.onnx ~/projects/WinnCoreAV/models/")
    print(f"  3. Rebuild WinnCoreAV with new model:")
    print(f"     cd ~/projects/WinnCoreAV && cargo build --release")
    print(f"{'='*60}\n")

if __name__ == '__main__':
    main()
