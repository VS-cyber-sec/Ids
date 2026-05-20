import os, sys, glob, joblib, warnings
import numpy  as np
import pandas as pd
from sklearn.preprocessing  import LabelEncoder, MinMaxScaler
from sklearn.utils          import resample

warnings.filterwarnings("ignore")

# ── paths ─────────────────────────────────────────────────────
HERE         = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
DATA_DIR     = os.path.join(PROJECT_ROOT, "data")
FEATURES_DIR = os.path.join(DATA_DIR, "features")
MODEL_DIR    = os.path.join(PROJECT_ROOT, "model")
os.makedirs(MODEL_DIR, exist_ok=True)

# output paths
OUT_TRAIN    = os.path.join(DATA_DIR, "train.csv")
OUT_TEST     = os.path.join(DATA_DIR, "test.csv")
SCALER_PATH  = os.path.join(MODEL_DIR, "scaler.pkl")
ENCODERS_PATH= os.path.join(MODEL_DIR, "encoders.pkl")
COLS_PATH    = os.path.join(MODEL_DIR, "feature_cols.pkl")

# ── NSL-KDD column types ─────────────────────────────────────
CAT_COLS  = ["protocol_type", "service", "flag"]
LABEL_COL = "label"

# All 41 NSL-KDD feature columns
FEATURE_COLS = [
    "duration","protocol_type","service","flag",
    "src_bytes","dst_bytes","land","wrong_fragment","urgent",
    "hot","num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login",
    "count","srv_count",
    "serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate",
    "dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate",
]

NUM_COLS = [c for c in FEATURE_COLS if c not in CAT_COLS]

# ── valid label set ───────────────────────────────────────────
VALID_LABELS = {"normal","dos","probe","r2l","u2r"}

# ═══════════════════════════════════════════════════════════════
def load_data() -> pd.DataFrame:
    """Load all capture_*.csv files from features dir."""
    csvs = sorted(glob.glob(os.path.join(FEATURES_DIR, "capture_*.csv")))

    # Also accept labeled_dataset.csv if label_csv.py was run
    labeled = os.path.join(FEATURES_DIR, "labeled_dataset.csv")
    if os.path.exists(labeled):
        csvs.append(labeled)

    if not csvs:
        print(f"[ERROR] No CSV files found in {FEATURES_DIR}")
        print("        Run the sniffer and attack script first.")
        sys.exit(1)

    frames = []
    for c in csvs:
        try:
            df = pd.read_csv(c)
            frames.append(df)
            print(f"  Loaded {os.path.basename(c):45s} {len(df):>6,} rows")
        except Exception as e:
            print(f"  [WARN] Could not read {c}: {e}")

    df = pd.concat(frames, ignore_index=True)
    print(f"\n  Total raw rows: {len(df):,}")
    return df


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """Drop invalid rows and unknown labels."""
    before = len(df)

    # Keep only rows with a valid attack label
    df = df[df[LABEL_COL].isin(VALID_LABELS)].copy()
    dropped_label = before - len(df)
    if dropped_label:
        print(f"  Dropped {dropped_label:,} rows with unknown/invalid labels")

    # Drop rows missing any feature column
    missing_cols = [c for c in FEATURE_COLS if c not in df.columns]
    if missing_cols:
        print(f"  [WARN] Missing columns (will fill with 0): {missing_cols}")
        for c in missing_cols:
            df[c] = 0

    # Drop rows that have NaN in critical columns
    before2 = len(df)
    df = df.dropna(subset=FEATURE_COLS)
    if len(df) < before2:
        print(f"  Dropped {before2 - len(df):,} rows with NaN values")

    # Fix categorical values — lowercase and strip
    for c in CAT_COLS:
        df[c] = df[c].astype(str).str.lower().str.strip()

    # Fix protocol_type — only allow tcp/udp/icmp
    valid_proto = {"tcp","udp","icmp"}
    df.loc[~df["protocol_type"].isin(valid_proto), "protocol_type"] = "tcp"

    # Clip numeric values to sensible ranges (remove sensor glitches)
    df["src_bytes"] = df["src_bytes"].clip(lower=0)
    df["dst_bytes"] = df["dst_bytes"].clip(lower=0)
    df["duration"]  = df["duration"].clip(lower=0)
    for rate_col in [c for c in NUM_COLS if "rate" in c]:
        df[rate_col] = df[rate_col].clip(0.0, 1.0)

    print(f"  Clean rows remaining: {len(df):,}")
    return df


def encode_categoricals(df: pd.DataFrame, fit: bool = True,
                         encoders: dict = None) -> tuple:
    """
    Label-encode protocol_type, service, flag.
    If fit=True:  fits new encoders and returns them.
    If fit=False: uses provided encoders (for inference).
    Returns (df_encoded, encoders_dict)
    """
    if encoders is None:
        encoders = {}

    for col in CAT_COLS:
        if fit:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            encoders[col] = le
        else:
            le = encoders[col]
            # Handle unseen categories gracefully
            known = set(le.classes_)
            df[col] = df[col].apply(
                lambda x: x if x in known else le.classes_[0]
            )
            df[col] = le.transform(df[col].astype(str))

    return df, encoders


def scale_numerics(df: pd.DataFrame, fit: bool = True,
                   scaler=None):
    """
    MinMax scale all numeric columns to [0, 1].
    If fit=True:  fits new scaler and returns it.
    If fit=False: uses provided scaler (for inference).
    Returns (df_scaled, scaler)
    """
    if fit:
        scaler = MinMaxScaler()
        df[NUM_COLS] = scaler.fit_transform(df[NUM_COLS])
    else:
        df[NUM_COLS] = scaler.transform(df[NUM_COLS])
    return df, scaler


def balance_classes(df: pd.DataFrame) -> pd.DataFrame:
    """
    Balance the dataset so no class overwhelms others.
    Strategy:
      - Find the majority class count
      - Upsample minority classes to match (with replacement)
      - Downsample majority class if > 3x the median
    This gives the model equal exposure to all attack types.
    """
    counts = df[LABEL_COL].value_counts()
    print(f"\n  Label counts before balancing:")
    for lbl, cnt in counts.items():
        bar = "█" * min(40, int(cnt/max(counts)*40))
        print(f"    {lbl:8s} {cnt:6,}  {bar}")

    median_count = int(counts.median())
    target = min(int(counts.max()), median_count * 3)

    frames = []
    for label in counts.index:
        subset = df[df[LABEL_COL] == label]
        if len(subset) < target:
            # upsample minority
            subset = resample(subset, replace=True,
                              n_samples=target, random_state=42)
        elif len(subset) > target:
            # downsample majority
            subset = resample(subset, replace=False,
                              n_samples=target, random_state=42)
        frames.append(subset)

    balanced = pd.concat(frames).sample(frac=1, random_state=42)
    print(f"\n  Label counts after balancing (target={target:,}):")
    for lbl, cnt in balanced[LABEL_COL].value_counts().items():
        print(f"    {lbl:8s} {cnt:6,}")

    return balanced


def split_train_test(df: pd.DataFrame, test_size: float = 0.2):
    """Stratified train/test split."""
    from sklearn.model_selection import train_test_split
    X = df[FEATURE_COLS]
    y = df[LABEL_COL]
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=42
    )
    train = pd.concat([X_tr, y_tr], axis=1)
    test  = pd.concat([X_te, y_te], axis=1)
    return train, test


# ═══════════════════════════════════════════════════════════════
def main():
    print("=" * 55)
    print("Phase 2 — Preprocessing pipeline")
    print("=" * 55)

    # ── Step 1: Load ──────────────────────────────────────────
    print("\n[1/6] Loading raw captured CSV files ...")
    df = load_data()

    # ── Step 2: Clean ─────────────────────────────────────────
    print("\n[2/6] Cleaning data ...")
    df = clean(df)

    if len(df) == 0:
        print("[ERROR] No valid rows after cleaning.")
        print("        Make sure attacks were run and labels are set.")
        sys.exit(1)

    # ── Step 3: Encode categoricals ───────────────────────────
    print("\n[3/6] Encoding categorical columns ...")
    print(f"  protocol_type values: {sorted(df['protocol_type'].unique())}")
    print(f"  service values      : {sorted(df['service'].unique())[:10]}")
    print(f"  flag values         : {sorted(df['flag'].unique())}")
    df, encoders = encode_categoricals(df, fit=True)
    print(f"  Encoded {len(CAT_COLS)} categorical columns")

    # ── Step 4: Balance ───────────────────────────────────────
    print("\n[4/6] Balancing class distribution ...")
    df = balance_classes(df)

    # ── Step 5: Scale ─────────────────────────────────────────
    print("\n[5/6] Scaling numeric columns to [0,1] ...")
    df, scaler = scale_numerics(df, fit=True)
    print(f"  Scaled {len(NUM_COLS)} numeric columns")
    print(f"  src_bytes after scale: "
          f"min={df['src_bytes'].min():.3f}  "
          f"max={df['src_bytes'].max():.3f}")

    # ── Step 6: Split and save ────────────────────────────────
    print("\n[6/6] Splitting train/test and saving ...")
    train, test = split_train_test(df, test_size=0.2)

    train.to_csv(OUT_TRAIN, index=False)
    test.to_csv(OUT_TEST,   index=False)
    joblib.dump(scaler,   SCALER_PATH)
    joblib.dump(encoders, ENCODERS_PATH)
    joblib.dump(FEATURE_COLS, COLS_PATH)

    print(f"\n  train.csv       → {OUT_TRAIN}  ({len(train):,} rows)")
    print(f"  test.csv        → {OUT_TEST}   ({len(test):,} rows)")
    print(f"  scaler.pkl      → {SCALER_PATH}")
    print(f"  encoders.pkl    → {ENCODERS_PATH}")
    print(f"  feature_cols.pkl→ {COLS_PATH}")

    print("\n" + "=" * 55)
    print("Preprocessing complete — ready for model training")
    print("Next: python3 train_model.py")
    print("=" * 55)


if __name__ == "__main__":
    main()
