import os, sys, json, joblib, warnings
import numpy  as np
import pandas as pd
warnings.filterwarnings("ignore")

from sklearn.metrics import (classification_report,
                             confusion_matrix,
                             accuracy_score, f1_score)

HERE         = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
DATA_DIR     = os.path.join(PROJECT_ROOT, "data")
MODEL_DIR    = os.path.join(PROJECT_ROOT, "model")

TEST_CSV     = os.path.join(DATA_DIR, "test.csv")
COLS_PATH    = os.path.join(MODEL_DIR, "feature_cols.pkl")
LABEL_ENC    = os.path.join(MODEL_DIR, "label_encoder.pkl")
REPORT_PATH  = os.path.join(MODEL_DIR, "evaluation_report.json")
LABEL_COL    = "label"

MODEL_FILES  = {
    "Random Forest" : "rf_model.pkl",
    "XGBoost"       : "xgb_model.pkl",
    "MLP Neural Net": "mlp_model.pkl",
}


def load_test():
    feat_cols = joblib.load(COLS_PATH)
    le        = joblib.load(LABEL_ENC)
    test      = pd.read_csv(TEST_CSV)
    X_te      = test[feat_cols].values
    y_te      = le.transform(test[LABEL_COL].values)
    return X_te, y_te, le, feat_cols


def print_confusion(cm, classes):
    """Pretty-print a confusion matrix."""
    w = 9
    print(f"\n  {'':8s}", end="")
    for c in classes: print(f"{c[:8]:>9s}", end="")
    print()
    for i, row in enumerate(cm):
        print(f"  {classes[i][:8]:8s}", end="")
        for j, val in enumerate(row):
            col = "\033[0;32m" if i==j else ("\033[0;31m" if val>0 else "")
            print(f"{col}{val:>9d}\033[0m", end="")
        print()


def main():
    print("=" * 55)
    print("Phase 2 — Model evaluation")
    print("=" * 55)

    X_te, y_te, le, feat_cols = load_test()
    print(f"\nTest set: {len(X_te):,} rows  |  Classes: {list(le.classes_)}")

    results = {}
    for name, fname in MODEL_FILES.items():
        path = os.path.join(MODEL_DIR, fname)
        if not os.path.exists(path):
            print(f"\n  [SKIP] {name} — {fname} not found")
            continue

        clf  = joblib.load(path)
        pred = clf.predict(X_te)
        acc  = accuracy_score(y_te, pred)
        f1   = f1_score(y_te, pred, average="weighted")
        cm   = confusion_matrix(y_te, pred)
        results[name] = {"acc": acc, "f1": f1}

        print(f"\n{'─'*55}")
        print(f"  {name}")
        print(f"{'─'*55}")
        print(f"  Accuracy : {acc*100:.2f}%")
        print(f"  F1 Score : {f1*100:.2f}%  (weighted)")
        print(f"\n  Per-class results:")
        print(classification_report(
            y_te, pred, target_names=le.classes_,
            digits=3
        ))
        print(f"  Confusion matrix  (row=actual, col=predicted):")
        print_confusion(cm, list(le.classes_))

    # ── Summary comparison ────────────────────────────────────
    if results:
        print(f"\n{'═'*55}")
        print("  MODEL COMPARISON SUMMARY")
        print(f"{'═'*55}")
        print(f"  {'Model':20s}  {'Accuracy':>10s}  {'F1 Score':>10s}")
        print(f"  {'─'*20}  {'─'*10}  {'─'*10}")
        best = max(results, key=lambda k: results[k]["f1"])
        for name, r in sorted(results.items(),
                               key=lambda x: x[1]["f1"], reverse=True):
            star = " ← BEST" if name == best else ""
            print(f"  {name:20s}  {r['acc']*100:9.2f}%  "
                  f"{r['f1']*100:9.2f}%{star}")
        print(f"{'═'*55}")
        print(f"\n  Best model : {best}")
        print(f"  Use this for live inference in predict.py")


if __name__ == "__main__":
    main()
