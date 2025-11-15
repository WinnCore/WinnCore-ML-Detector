#!/usr/bin/env python3
"""
Train LightGBM malware classifier on ARM64 binary features.

This script:
1. Loads features from JSONL files
2. Splits into train/test sets
3. Trains a LightGBM binary classifier
4. Evaluates with ROC-AUC, PR-AUC, FPR@TPR metrics
5. Exports the model to ONNX format
6. Generates evaluation report
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import lightgbm as lgb
# import matplotlib.pyplot as plt
import numpy as np
import onnxmltools
import pandas as pd
# import seaborn as sns
from sklearn.metrics import (
    average_precision_score,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split


def load_features(jsonl_path: Path) -> pd.DataFrame:
    """Load features from JSONL file into DataFrame."""
    print(f"Loading features from {jsonl_path}...")
    
    records = []
    with open(jsonl_path, "r") as f:
        for line_num, line in enumerate(f, 1):
            try:
                record = json.loads(line)
                records.append(record)
            except json.JSONDecodeError as e:
                print(f"Warning: Skipping invalid JSON at line {line_num}: {e}")
    
    if not records:
        raise ValueError(f"No valid records found in {jsonl_path}")
    
    print(f"Loaded {len(records)} records")
    return pd.DataFrame(records)


def prepare_dataset(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Prepare features and labels for training.
    
    Returns:
        X: Feature matrix (numerical features only)
        y: Label vector (0=benign, 1=malicious)
    """
    # Drop metadata columns that aren't features
    metadata_cols = ["sha256", "arch", "source", "timestamp"]
    feature_cols = [col for col in df.columns if col not in metadata_cols and col != "label"]
    
    X = df[feature_cols].copy()
    y = df["label"].copy()
    
    # Convert boolean columns to int (LightGBM expects numerical)
    for col in X.columns:
        if X[col].dtype == bool:
            X[col] = X[col].astype(int)
    
    print(f"Features: {len(feature_cols)} columns")
    print(f"Samples: {len(X)} total")
    print(f"  - Benign (label=0): {(y == 0).sum()}")
    print(f"  - Malicious (label=1): {(y == 1).sum()}")
    
    return X, y


def calculate_fpr_at_tpr(y_true: np.ndarray, y_scores: np.ndarray, target_tpr: float) -> float:
    """
    Calculate FPR (False Positive Rate) at a specific TPR (True Positive Rate).
    
    This is a critical metric for AV systems:
    - FPR@TPR=95% = false positives when catching 95% of malware
    - FPR@TPR=99% = false positives when catching 99% of malware
    
    Lower FPR is better (fewer false alarms on benign files).
    """
    fpr, tpr, thresholds = roc_curve(y_true, y_scores)
    
    # Find the threshold where TPR is closest to target
    idx = np.argmin(np.abs(tpr - target_tpr))
    
    return fpr[idx]


def train_model(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
) -> lgb.LGBMClassifier:
    """
    Train LightGBM binary classifier.
    
    LightGBM params are tuned for:
    - Low false positive rate (precision matters in AV)
    - Fast inference (real-time scanning)
    - Small model size (deploy to edge devices)
    """
    print("\nTraining LightGBM classifier...")
    
    model = lgb.LGBMClassifier(
        objective="binary",
        metric="binary_logloss",
        boosting_type="gbdt",
        num_leaves=31,
        max_depth=6,
        learning_rate=0.05,
        n_estimators=200,
        min_child_samples=20,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=0.1,  # L1 regularization
        reg_lambda=0.1,  # L2 regularization
        random_state=42,
        n_jobs=-1,
        verbose=-1,
    )
    
    # Train with early stopping
    model.fit(
        X_train,
        y_train,
        eval_set=[(X_test, y_test)],
        eval_metric="auc",
        callbacks=[lgb.early_stopping(stopping_rounds=20, verbose=False)],
    )
    
    print(f"Training complete - used {model.n_estimators} trees")
    return model


def evaluate_model(
    model: lgb.LGBMClassifier,
    X_test: pd.DataFrame,
    y_test: pd.Series,
) -> Dict[str, float]:
    """
    Evaluate model and calculate all key metrics.
    
    Returns dict with:
    - roc_auc: Area under ROC curve
    - pr_auc: Area under Precision-Recall curve (average precision)
    - fpr_at_tpr_95: False positive rate at 95% true positive rate
    - fpr_at_tpr_99: False positive rate at 99% true positive rate
    """
    print("\nEvaluating model...")
    
    # Get prediction probabilities
    y_proba = model.predict_proba(X_test)[:, 1]
    
    # Calculate metrics
    metrics = {
        "roc_auc": roc_auc_score(y_test, y_proba),
        "pr_auc": average_precision_score(y_test, y_proba),
        "fpr_at_tpr_95": calculate_fpr_at_tpr(y_test, y_proba, 0.95),
        "fpr_at_tpr_99": calculate_fpr_at_tpr(y_test, y_proba, 0.99),
    }
    
    print("\nMetrics:")
    print(f"  ROC-AUC:           {metrics['roc_auc']:.4f}")
    print(f"  Average Precision: {metrics['pr_auc']:.4f}")
    print(f"  FPR@TPR=95%:       {metrics['fpr_at_tpr_95']:.4f} ({metrics['fpr_at_tpr_95']*100:.2f}%)")
    print(f"  FPR@TPR=99%:       {metrics['fpr_at_tpr_99']:.4f} ({metrics['fpr_at_tpr_99']*100:.2f}%)")
    
    return metrics


# def plot_evaluation(
#     model: lgb.LGBMClassifier,
#     X_test: pd.DataFrame,
#     y_test: pd.Series,
#     output_dir: Path,
# ):
#     """Generate evaluation plots."""
#     print("\nGenerating plots...")
#     
#     y_proba = model.predict_proba(X_test)[:, 1]
#     
#     # Create figure with subplots
#     fig, axes = plt.subplots(2, 2, figsize=(12, 10))
#     
#     # ROC Curve
#     fpr, tpr, _ = roc_curve(y_test, y_proba)
#     roc_auc = roc_auc_score(y_test, y_proba)
#     axes[0, 0].plot(fpr, tpr, label=f"ROC (AUC = {roc_auc:.3f})")
#     axes[0, 0].plot([0, 1], [0, 1], "k--", label="Random")
#     axes[0, 0].set_xlabel("False Positive Rate")
#     axes[0, 0].set_ylabel("True Positive Rate")
#     axes[0, 0].set_title("ROC Curve")
#     axes[0, 0].legend()
#     axes[0, 0].grid(True, alpha=0.3)
#     
#     # Precision-Recall Curve
#     precision, recall, _ = precision_recall_curve(y_test, y_proba)
#     pr_auc = average_precision_score(y_test, y_proba)
#     axes[0, 1].plot(recall, precision, label=f"PR (AUC = {pr_auc:.3f})")
#     axes[0, 1].set_xlabel("Recall (TPR)")
#     axes[0, 1].set_ylabel("Precision")
#     axes[0, 1].set_title("Precision-Recall Curve")
#     axes[0, 1].legend()
#     axes[0, 1].grid(True, alpha=0.3)
#     
#     # Feature Importance (top 20)
#     feature_importance = pd.DataFrame({
#         "feature": X_test.columns,
#         "importance": model.feature_importances_,
#     }).sort_values("importance", ascending=False).head(20)
#     
#     axes[1, 0].barh(range(len(feature_importance)), feature_importance["importance"])
#     axes[1, 0].set_yticks(range(len(feature_importance)))
#     axes[1, 0].set_yticklabels(feature_importance["feature"])
#     axes[1, 0].set_xlabel("Importance")
#     axes[1, 0].set_title("Top 20 Feature Importances")
#     axes[1, 0].invert_yaxis()
#     
#     # Score Distribution
#     axes[1, 1].hist(y_proba[y_test == 0], bins=50, alpha=0.5, label="Benign", color="blue")
#     axes[1, 1].hist(y_proba[y_test == 1], bins=50, alpha=0.5, label="Malicious", color="red")
#     axes[1, 1].set_xlabel("Prediction Score")
#     axes[1, 1].set_ylabel("Count")
#     axes[1, 1].set_title("Score Distribution")
#     axes[1, 1].legend()
#     axes[1, 1].grid(True, alpha=0.3)
#     
#     plt.tight_layout()
#     plot_path = output_dir / "evaluation_plots.png"
#     plt.savefig(plot_path, dpi=150, bbox_inches="tight")
#     print(f"Saved plots to {plot_path}")
# 

def export_onnx(model: lgb.LGBMClassifier, feature_names: List[str], output_path: Path):
    """
    Export LightGBM model to ONNX format.
    
    ONNX allows the model to be loaded in Rust using the `ort` crate
    for fast inference in the WinnCoreAV engine.
    """
    print(f"\nExporting model to ONNX: {output_path}...")
    
    # Convert to ONNX
    onnx_model = onnxmltools.convert_lightgbm(
        model,
        initial_types=[("input", onnxmltools.convert.common.data_types.FloatTensorType([None, len(feature_names)]))],
    )
    
    # Save ONNX model
    onnxmltools.utils.save_model(onnx_model, output_path)
    
    # Check file size
    size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"Model exported successfully ({size_mb:.2f} MB)")


def generate_report(
    metrics: Dict[str, float],
    model: lgb.LGBMClassifier,
    output_path: Path,
):
    """Generate markdown evaluation report."""
    print(f"\nGenerating report: {output_path}...")
    
    report = f"""# WinnCore ARM64 AV Evaluation Report

## Model Performance

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| ROC-AUC | {metrics['roc_auc']:.4f} | ≥ 0.95 | {'✅' if metrics['roc_auc'] >= 0.95 else '⚠️'} |
| Average Precision | {metrics['pr_auc']:.4f} | ≥ 0.90 | {'✅' if metrics['pr_auc'] >= 0.90 else '⚠️'} |
| FPR@TPR=95% | {metrics['fpr_at_tpr_95']:.4f} ({metrics['fpr_at_tpr_95']*100:.2f}%) | ≤ 1% | {'✅' if metrics['fpr_at_tpr_95'] <= 0.01 else '⚠️'} |
| FPR@TPR=99% | {metrics['fpr_at_tpr_99']:.4f} ({metrics['fpr_at_tpr_99']*100:.2f}%) | ≤ 5% | {'✅' if metrics['fpr_at_tpr_99'] <= 0.05 else '⚠️'} |

## Model Configuration

- **Algorithm:** LightGBM (Gradient Boosted Decision Trees)
- **Trees:** {model.n_estimators}
- **Max Depth:** {model.max_depth}
- **Learning Rate:** {model.learning_rate}

## Interpretation

### ROC-AUC = {metrics['roc_auc']:.4f}
The model achieves {metrics['roc_auc']*100:.1f}% separation between benign and malicious samples.

### FPR@TPR=95% = {metrics['fpr_at_tpr_95']*100:.2f}%
When configured to catch 95% of malware, the model will flag {metrics['fpr_at_tpr_95']*100:.2f}% of benign files as malicious (false positives).

### FPR@TPR=99% = {metrics['fpr_at_tpr_99']*100:.2f}%
When configured to catch 99% of malware, the model will flag {metrics['fpr_at_tpr_99']*100:.2f}% of benign files as malicious.

## Next Steps

1. Collect more training data to improve metrics
2. Experiment with additional features (strings, control flow graph)
3. Ensemble with YARA signatures for hybrid detection
4. Integrate ONNX model into WinnCoreAV Rust engine
"""
    
    with open(output_path, "w") as f:
        f.write(report)
    
    print(f"Report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Train WinnCore ARM64 malware classifier")
    parser.add_argument(
        "--features",
        type=Path,
        required=True,
        help="Input JSONL file with extracted features",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output path for ONNX model (e.g., models/gbm_v0.onnx)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Output path for evaluation report (markdown)",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Proportion of data to use for testing (default: 0.2)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility",
    )
    
    args = parser.parse_args()
    
    # Validate inputs
    if not args.features.exists():
        print(f"Error: Feature file not found: {args.features}")
        sys.exit(1)
    
    # Set up output directory
    output_dir = args.output.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if args.report is None:
        args.report = output_dir / "evaluation_report.md"
    
    eval_dir = args.report.parent
    eval_dir.mkdir(parents=True, exist_ok=True)
    
    # Load and prepare data
    df = load_features(args.features)
    X, y = prepare_dataset(df)
    
    # Split train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )
    
    print(f"\nTrain set: {len(X_train)} samples")
    print(f"Test set:  {len(X_test)} samples")
    
    # Train model
    model = train_model(X_train, y_train, X_test, y_test)
    
    # Evaluate
    metrics = evaluate_model(model, X_test, y_test)
    
    # Generate visualizations
    plot_evaluation(model, X_test, y_test, eval_dir)
    
    # Export to ONNX
    export_onnx(model, X.columns.tolist(), args.output)
    
    # Generate report
    generate_report(metrics, model, args.report)
    
    print("\n✅ Training complete!")
    print(f"   Model: {args.output}")
    print(f"   Report: {args.report}")


if __name__ == "__main__":
    main()
