import os, sys, json, warnings, joblib, time
import numpy  as np
import pandas as pd
warnings.filterwarnings("ignore")

from sklearn.ensemble        import RandomForestClassifier
from sklearn.neural_network  import MLPClassifier
from sklearn.metrics         import (classification_report,
                                     confusion_matrix,
                                     accuracy_score, f1_score)
from sklearn.preprocessing   import LabelEncoder

# ── paths ─────────────────────────────────────────────────────
HERE         = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
DATA_DIR     = os.path.join(PROJECT_ROOT, "data")
MODEL_DIR    = os.path.join(PROJECT_ROOT, "model")
os.makedirs(MODEL_DIR, exist_ok=True)

TRAIN_CSV    = os.path.join(DATA_DIR, "train.csv")
TEST_CSV     = os.path.join(DATA_DIR, "test.csv")
SCALER_PATH  = os.path.join(MODEL_DIR, "scaler.pkl")
ENCODERS_PATH= os.path.join(MODEL_DIR, "encoders.pkl")
COLS_PATH    = os.path.join(MODEL_DIR, "feature_cols.pkl")
REPORT_PATH  = os.path.join(MODEL_DIR, "evaluation_report.json")
BEST_MODEL   = os.path.join(MODEL_DIR, "best_model.pkl")
LABEL_ENC    = os.path.join(MODEL_DIR, "label_encoder.pkl")

LABEL_COL    = "label"
LABEL_ORDER  = ["normal","dos","probe","r2l","u2r"]

# ═══════════════════════════════════════════════════════════════
def load_data():
    for path in (TRAIN_CSV, TEST_CSV):
        if not os.path.exists(path):
            print(f"[ERROR] {path} not found.")
            print("        Run preprocess.py first.")
            sys.exit(1)

    feature_cols = joblib.load(COLS_PATH)
    train = pd.read_csv(TRAIN_CSV)
    test  = pd.read_csv(TEST_CSV)

    X_tr = train[feature_cols].values
    y_tr = train[LABEL_COL].values
    X_te = test[feature_cols].values
    y_te = test[LABEL_COL].values

    # Encode string labels to integers for sklearn
    le = LabelEncoder()
    le.fit(LABEL_ORDER)          # fix the class ordering
    y_tr = le.transform(y_tr)
    y_te = le.transform(y_te)
    joblib.dump(le, LABEL_ENC)

    print(f"  Train: {X_tr.shape[0]:,} rows × {X_tr.shape[1]} features")
    print(f"  Test : {X_te.shape[0]:,} rows × {X_te.shape[1]} features")
    print(f"  Classes: {list(le.classes_)}")
    return X_tr, y_tr, X_te, y_te, le


def train_random_forest(X_tr, y_tr):
    print("\n  Training Random Forest ...")
    t0 = time.time()
    clf = RandomForestClassifier(
        n_estimators  = 200,      # 200 trees
        max_depth     = None,     # grow fully
        min_samples_split = 5,
        class_weight  = "balanced",  # handles class imbalance
        n_jobs        = -1,       # use all CPU cores
        random_state  = 42,
    )
    clf.fit(X_tr, y_tr)
    print(f"  Done in {time.time()-t0:.1f}s")
    return clf


def train_xgboost(X_tr, y_tr):
    try:
        from xgboost import XGBClassifier
    except ImportError:
        print("  [SKIP] xgboost not installed — pip install xgboost")
        return None
    print("\n  Training XGBoost ...")
    t0 = time.time()
    clf = XGBClassifier(
        n_estimators     = 200,
        max_depth        = 6,
        learning_rate    = 0.1,
        subsample        = 0.8,
        colsample_bytree = 0.8,
        use_label_encoder= False,
        eval_metric      = "mlogloss",
        n_jobs           = -1,
        random_state     = 42,
        verbosity        = 0,
    )
    clf.fit(X_tr, y_tr)
    print(f"  Done in {time.time()-t0:.1f}s")
    return clf


def train_mlp(X_tr, y_tr):
    print("\n  Training MLP Neural Network ...")
    t0 = time.time()
    clf = MLPClassifier(
        hidden_layer_sizes = (128, 64, 32),  # 3 hidden layers
        activation         = "relu",
        solver             = "adam",
        learning_rate_init = 0.001,
        max_iter           = 300,
        early_stopping     = True,
        validation_fraction= 0.1,
        random_state       = 42,
        verbose            = False,
    )
    clf.fit(X_tr, y_tr)
    print(f"  Done in {time.time()-t0:.1f}s  "
          f"(iters={clf.n_iter_})")
    return clf


def evaluate(name, clf, X_te, y_te, le):
    """Evaluate a model and return metrics dict."""
    if clf is None:
        return None
    y_pred = clf.predict(X_te)
    acc    = accuracy_score(y_te, y_pred)
    f1     = f1_score(y_te, y_pred, average="weighted")
    report = classification_report(
        y_te, y_pred,
        target_names = le.classes_,
        output_dict  = True,
    )
    cm = confusion_matrix(y_te, y_pred).tolist()

    print(f"\n  ── {name} ──────────────────────────────")
    print(f"  Accuracy : {acc*100:.2f}%")
    print(f"  F1 score : {f1*100:.2f}%  (weighted)")
    print(f"\n  Per-class report:")
    print(classification_report(y_te, y_pred,
                                target_names=le.classes_))

    print(f"  Confusion matrix (rows=actual, cols=predicted):")
    print(f"  Labels: {list(le.classes_)}")
    cm_arr = np.array(cm)
    for i, row in enumerate(cm_arr):
        print(f"  {le.classes_[i]:8s}: {row.tolist()}")

    return {"name":name, "accuracy":acc, "f1":f1,
            "report":report, "confusion_matrix":cm}


def feature_importance(clf, feature_cols):
    """Print top-10 most important features."""
    if not hasattr(clf, "feature_importances_"):
        return
    imp  = clf.feature_importances_
    idxs = np.argsort(imp)[::-1][:10]
    print(f"\n  Top-10 most important features:")
    for rank, i in enumerate(idxs, 1):
        bar = "█" * int(imp[i]*200)
        print(f"  {rank:2d}. {feature_cols[i]:35s} {imp[i]:.4f}  {bar}")


# ═══════════════════════════════════════════════════════════════
def main():
    print("=" * 55)
    print("Phase 2 — Model training")
    print("=" * 55)

    feature_cols = joblib.load(COLS_PATH)

    # ── Load data ─────────────────────────────────────────────
    print("\n[1/4] Loading preprocessed data ...")
    X_tr, y_tr, X_te, y_te, le = load_data()

    # ── Train models ──────────────────────────────────────────
    print("\n[2/4] Training models ...")
    models = {
        "Random Forest" : train_random_forest(X_tr, y_tr),
        "XGBoost"       : train_xgboost(X_tr, y_tr),
        "MLP Neural Net": train_mlp(X_tr, y_tr),
    }

    # ── Evaluate ──────────────────────────────────────────────
    print("\n[3/4] Evaluating on test set ...")
    results = {}
    for name, clf in models.items():
        r = evaluate(name, clf, X_te, y_te, le)
        if r:
            results[name] = r

    # ── Pick best and save ────────────────────────────────────
    print("\n[4/4] Saving best model ...")
    best_name = max(results, key=lambda k: results[k]["f1"])
    best_clf  = models[best_name]
    best_f1   = results[best_name]["f1"]

    print(f"\n  Best model: {best_name}  (F1={best_f1*100:.2f}%)")

    # save best model
    joblib.dump(best_clf, BEST_MODEL)
    print(f"  Saved → {BEST_MODEL}")

    # save each model individually
    name_map = {
        "Random Forest" : "rf_model.pkl",
        "XGBoost"       : "xgb_model.pkl",
        "MLP Neural Net": "mlp_model.pkl",
    }
    for name, clf in models.items():
        if clf is not None:
            path = os.path.join(MODEL_DIR, name_map[name])
            joblib.dump(clf, path)
            print(f"  Saved → {path}")

    # feature importance from RF
    if models.get("Random Forest"):
        feature_importance(models["Random Forest"], feature_cols)

    # save full report
    report = {
        "best_model"  : best_name,
        "best_f1"     : best_f1,
        "models"      : {k:{"accuracy":v["accuracy"],"f1":v["f1"]}
                         for k,v in results.items()},
        "label_classes": list(le.classes_),
    }
    with open(REPORT_PATH,"w") as f:
        json.dump(report, f, indent=2)
    print(f"  Report → {REPORT_PATH}")

    print("\n" + "=" * 55)
    print("Model training complete")
    print(f"Best: {best_name}  F1={best_f1*100:.2f}%")
    print("Next: python3 predict.py  (live inference)")
    print("=" * 55)


if __name__ == "__main__":
    main()
