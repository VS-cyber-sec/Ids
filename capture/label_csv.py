import os, sys, glob, pandas as pd
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEATURES_DIR = os.path.join(PROJECT_ROOT, "data", "features")
ATTACK_LOG   = os.path.join(PROJECT_ROOT, "data", "attack_session.log")
OUT_FILE     = os.path.join(FEATURES_DIR, "labeled_dataset.csv")

# ── parse attack_session.log ────────────────────────────────
def parse_log(path):
    windows = []   # [(start_dt, stop_dt, label)]
    active  = {}   # label → start_dt
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            parts = line.split()
            if len(parts) < 3: continue
            ts_str, action, label = parts[0], parts[1], parts[2]
            try:
                ts = datetime.fromisoformat(ts_str)
            except ValueError:
                continue
            if action == "START":
                active[label] = ts
            elif action == "STOP" and label in active:
                windows.append((active.pop(label), ts, label))
    return windows

# ── assign label to a timestamp ─────────────────────────────
def assign(ts, windows):
    for start, stop, label in windows:
        if start <= ts <= stop:
            return label
    return "normal"

# ── main ────────────────────────────────────────────────────
def main():
    if not os.path.exists(ATTACK_LOG):
        print(f"ERROR: attack log not found: {ATTACK_LOG}")
        sys.exit(1)

    windows = parse_log(ATTACK_LOG)
    print(f"Parsed {len(windows)} attack windows from {ATTACK_LOG}")
    for s,e,l in windows:
        print(f"  {l:8s}  {s.strftime('%H:%M:%S')} → {e.strftime('%H:%M:%S')}")

    # load all CSVs in features/
    csvs = sorted(glob.glob(os.path.join(FEATURES_DIR, "capture_*.csv")))
    if not csvs:
        print(f"ERROR: no capture_*.csv files in {FEATURES_DIR}")
        sys.exit(1)

    print(f"\nLoading {len(csvs)} CSV file(s) ...")
    frames = []
    for c in csvs:
        df = pd.read_csv(c)
        frames.append(df)
        print(f"  {os.path.basename(c)}  — {len(df):,} rows")

    df = pd.concat(frames, ignore_index=True)
    print(f"\nTotal rows: {len(df):,}")

    # parse timestamps
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # assign labels
    df["label"] = df["timestamp"].apply(lambda t: assign(t, windows))

    print("\nLabel distribution:")
    print(df["label"].value_counts().to_string())

    # save
    df.to_csv(OUT_FILE, index=False)
    print(f"\nLabeled dataset saved → {OUT_FILE}")
    print(f"Rows: {len(df):,}  |  Columns: {len(df.columns)}")

if __name__ == "__main__":
    main()
