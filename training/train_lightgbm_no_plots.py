#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

import lightgbm as lgb
import numpy as np
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score, roc_curve
from sklearn.model_selection import train_test_split

def load_features(jsonl_path):
    records = []
    with open(jsonl_path, "r") as f:
        for line in f:
            try:
                records.append(json.loads(line))
            except:
                pass
    
    print(f"Loaded {len(records)} records")
    
    # Extract features
    metadata_cols = ["sha256", "arch", "source", "timestamp", "label"]
    
    X = []
    y = []
    for record in records:
        features = []
        for key, value in record.items():
            if key not in metadata_cols:
                features.append(float(value) if isinstance(value, (int, float, bool)) else 0.0)
        X.append(features)
        y.append(record["label"])
    
    return np.array(X), np.array(y)

def calculate_fpr_at_tpr(y_true, y_scores, target_tpr):
    fpr, tpr, _ = roc_curve(y_true, y_scores)
    idx = np.argmin(np.abs(tpr - target_tpr))
    return fpr[idx]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, default=None)
    args = parser.parse_args()
    
    # Load data
    X, y = load_features(args.features)
    
    print(f"Features: {X.shape[1]} columns")
    print(f"Samples: {len(X)} total")
    print(f"  Benign: {(y == 0).sum()}")
    print(f"  Malicious: {(y == 1).sum()}")
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print(f"\nTrain: {len(X_train)}")
    print(f"Test: {len(X_test)}")
    
    # Train
    print("\nTraining LightGBM...")
    model = lgb.LGBMClassifier(
        objective="binary",
        num_leaves=31,
        max_depth=6,
        learning_rate=0.05,
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        verbose=-1,
    )
    
    model.fit(X_train, y_train, eval_set=[(X_test, y_test)])
    
    # Evaluate
    print("\nEvaluating...")
    y_proba = model.predict_proba(X_test)[:, 1]
    
    metrics = {
        "roc_auc": roc_auc_score(y_test, y_proba),
        "pr_auc": average_precision_score(y_test, y_proba),
        "fpr_at_tpr_95": calculate_fpr_at_tpr(y_test, y_proba, 0.95),
        "fpr_at_tpr_99": calculate_fpr_at_tpr(y_test, y_proba, 0.99),
    }
    
    print(f"\nROC-AUC: {metrics['roc_auc']:.4f}")
    print(f"PR-AUC: {metrics['pr_auc']:.4f}")
    print(f"FPR@TPR=95%: {metrics['fpr_at_tpr_95']*100:.2f}%")
    print(f"FPR@TPR=99%: {metrics['fpr_at_tpr_99']*100:.2f}%")
    
    # Export ONNX
    print(f"\nExporting to {args.output}...")
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType
    
    args.output.parent.mkdir(parents=True, exist_ok=True)
    
    initial_type = [("input", FloatTensorType([None, X.shape[1]]))]
    onnx_model = onnxmltools.convert_lightgbm(model, initial_types=initial_type)
    onnxmltools.utils.save_model(onnx_model, str(args.output))
    
    print(f"✅ Model saved: {args.output}")
    
    # Save report
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with open(args.report, "w") as f:
            f.write(f"""# WinnCore ML Detector - Training Report

## Metrics

| Metric | Value |
|--------|-------|
| ROC-AUC | {metrics['roc_auc']:.4f} |
| PR-AUC | {metrics['pr_auc']:.4f} |
| FPR@TPR=95% | {metrics['fpr_at_tpr_95']*100:.2f}% |
| FPR@TPR=99% | {metrics['fpr_at_tpr_99']*100:.2f}% |

## Dataset

- Total samples: {len(X)}
- Training: {len(X_train)}
- Testing: {len(X_test)}
- Benign: {(y == 0).sum()}
- Malicious: {(y == 1).sum()}

## Model

- Algorithm: LightGBM
- Trees: {model.n_estimators}
- Max Depth: {model.max_depth}

Training complete!
""")
        print(f"✅ Report saved: {args.report}")

if __name__ == "__main__":
    main()
