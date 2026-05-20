import os, sys, csv, time, glob, joblib, warnings
import numpy  as np
import pandas as pd
warnings.filterwarnings("ignore")

HERE         = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

DATA_DIR     = os.path.join(PROJECT_ROOT, "data")
MODEL_DIR    = os.path.join(PROJECT_ROOT, "model")
FEATURES_DIR = os.path.join(DATA_DIR, "features")
PRED_LOG     = os.path.join(DATA_DIR, "predictions.log")

MODEL_PATH    = os.path.join(MODEL_DIR, "best_model.pkl")
SCALER_PATH   = os.path.join(MODEL_DIR, "scaler.pkl")
ENCODERS_PATH = os.path.join(MODEL_DIR, "encoders.pkl")
COLS_PATH     = os.path.join(MODEL_DIR, "feature_cols.pkl")
LABEL_ENC     = os.path.join(MODEL_DIR, "label_encoder.pkl")

LABEL_COL       = "label"
CAT_COLS        = ["protocol_type", "service", "flag"]
POLL_SECS       = 1.0
ALERT_THRESHOLD = 0.85
BLOCK_THRESHOLD = 0.90

# ── colours ───────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
CYN='\033[0;36m'; BLD='\033[1m';    NC ='\033[0m'
ATTACK_COL = {"normal":GRN,"dos":RED,"probe":YLW,"r2l":CYN,"u2r":RED}

# ── invalid IP set ────────────────────────────────────────────
INVALID_IPS = {"0.0.0.0","","None","nan","127.0.0.1","none"}

def _valid_ip(ip: str) -> bool:
    if not ip or ip.strip() in INVALID_IPS:
        return False
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
        return nums[0] != 0 and all(0 <= n <= 255 for n in nums)
    except ValueError:
        return False

# ── import Phase 3 modules ────────────────────────────────────
try:
    from alert import send_slack, send_email
    ALERTS_ENABLED = True
    print(f"{GRN}[OK]{NC}  alert.py loaded — email + Slack enabled")
except ImportError:
    ALERTS_ENABLED = False
    print(f"{YLW}[WARN]{NC} alert.py not found — alerts disabled")
    def send_slack(l,c,s,d): pass
    def send_email(l,c,s,d): pass

try:
    from blocker import block_ip as _block
    BLOCKING_ENABLED = True
    print(f"{GRN}[OK]{NC}  blocker.py loaded — auto-block enabled")
except ImportError:
    BLOCKING_ENABLED = False
    print(f"{YLW}[WARN]{NC} blocker.py not found — auto-block disabled")
    def _block(s,l,c): return False

# ═══════════════════════════════════════════════════════════════
def load_artifacts():
    for p in (MODEL_PATH,SCALER_PATH,ENCODERS_PATH,COLS_PATH,LABEL_ENC):
        if not os.path.exists(p):
            print(f"{RED}[ERROR]{NC} Missing: {p}")
            print("        Run preprocess.py and train_model.py first.")
            sys.exit(1)
    model     = joblib.load(MODEL_PATH)
    scaler    = joblib.load(SCALER_PATH)
    encoders  = joblib.load(ENCODERS_PATH)
    feat_cols = joblib.load(COLS_PATH)
    le        = joblib.load(LABEL_ENC)
    print(f"{GRN}[OK]{NC}  Model     : {type(model).__name__}")
    print(f"{GRN}[OK]{NC}  Classes   : {list(le.classes_)}")
    print(f"{GRN}[OK]{NC}  Features  : {len(feat_cols)}")
    return model, scaler, encoders, feat_cols, le


def preprocess_row(row, scaler, encoders, feat_cols):
    df = pd.DataFrame([row])
    for c in feat_cols:
        if c not in df.columns:
            df[c] = 0
    df = df[feat_cols].copy()
    for col in CAT_COLS:
        if col not in df.columns:
            continue
        df[col] = df[col].astype(str).str.lower().str.strip()
        le_col  = encoders[col]
        known   = set(le_col.classes_)
        df[col] = df[col].apply(
            lambda x: x if x in known else le_col.classes_[0])
        df[col] = le_col.transform(df[col])
    num_cols = [c for c in feat_cols if c not in CAT_COLS]
    df[num_cols] = scaler.transform(df[num_cols])
    return df[feat_cols].values


def predict_row(row, model, scaler, encoders, feat_cols, le):
    X = preprocess_row(row, scaler, encoders, feat_cols)
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)[0]
        idx   = int(np.argmax(probs))
        conf  = float(probs[idx])
        label = le.inverse_transform([idx])[0]
    else:
        idx   = int(model.predict(X)[0])
        label = le.inverse_transform([idx])[0]
        conf  = 1.0
    return label, conf


def print_pred(ts, src, dst, pred, conf, true_label):
    col    = ATTACK_COL.get(pred, NC)
    is_atk = pred != "normal"
    tag    = f"  {BLD}*** ATTACK ***{NC}" if is_atk else ""
    bad_ip = f"  {YLW}[bad src IP]{NC}"  if (is_atk and not _valid_ip(src)) else ""
    print(
        f"{col}[{ts[11:23]}]  "
        f"{src:>15s} → {dst:<15s}  "
        f"PRED={pred.upper():8s}  "
        f"CONF={conf*100:5.1f}%  "
        f"TRUE={true_label:8s}"
        f"{tag}{bad_ip}{NC}"
    )


# ═══════════════════════════════════════════════════════════════
# Phase 3 — single clean entry point
# ═══════════════════════════════════════════════════════════════

def run_phase3(pred: str, conf: float, src: str, dst: str):
    """
    Triggers alert and block for attack predictions.

    Design:
      - IP validated once at the top — invalid IP → skip everything
      - send_slack() manages its own cooldown inside alert.py
      - send_email() manages its own cooldown inside alert.py
      - No duplicate cooldown messages here — alert.py prints them
      - block_ip() manages its own already-blocked set in blocker.py
    """
    if pred == "normal" or conf < ALERT_THRESHOLD:
        return

    # ── Validate IP ───────────────────────────────────────────
    if not _valid_ip(src):
        print(
            f"{YLW}[SKIP]{NC} Invalid src_ip={src!r} — "
            f"check sniffer IP extraction"
        )
        return

    # ── Slack — alert.py handles its own cooldown ─────────────
    if ALERTS_ENABLED:
        send_slack(pred, conf, src, dst)

    # ── Email — alert.py handles its own cooldown ─────────────
    if ALERTS_ENABLED:
        send_email(pred, conf, src, dst)

    # ── Block — blocker.py handles already-blocked set ────────
    if BLOCKING_ENABLED and conf >= BLOCK_THRESHOLD:
        blocked = _block(src, pred, conf)
        if blocked:
            print(
                f"{RED}[BLOCKED]{NC} {src} — "
                f"{pred.upper()} ({conf*100:.0f}%)"
            )


# ═══════════════════════════════════════════════════════════════
# CSV watcher
# ═══════════════════════════════════════════════════════════════

def watch_csv(model, scaler, encoders, feat_cols, le):
    seen      = {}
    counts    = {c:0 for c in le.classes_}
    total     = 0
    attacks   = 0

    print(f"\n{BLD}{'─'*72}{NC}")
    print(
        f"{'Timestamp':14s}  {'Src IP':>15s}   {'Dst IP':<15s}  "
        f"{'Prediction':10s}  {'Conf':7s}  {'True':10s}"
    )
    print(f"{'─'*72}")

    os.makedirs(DATA_DIR, exist_ok=True)
    log_fh = open(PRED_LOG, "w", newline="")
    log_wr = csv.writer(log_fh)
    log_wr.writerow([
        "timestamp","src_ip","dst_ip","src_port","dst_port",
        "predicted","confidence","true_label"
    ])

    try:
        while True:
            csvs = sorted(glob.glob(
                os.path.join(FEATURES_DIR, "capture_*.csv")))

            for csv_path in csvs:
                fname = os.path.basename(csv_path)
                n_seen = seen.get(fname, 0)
                try:
                    df = pd.read_csv(csv_path)
                except Exception:
                    continue
                new = df.iloc[n_seen:]
                if new.empty:
                    continue

                for _, row in new.iterrows():
                    try:
                        pred, conf = predict_row(
                            row.to_dict(),
                            model, scaler, encoders, feat_cols, le
                        )
                        true_lbl = str(row.get(LABEL_COL, "unknown"))
                        ts  = str(row.get("timestamp",""))
                        src = str(row.get("src_ip",""))
                        dst = str(row.get("dst_ip",""))
                        sp  = str(row.get("src_port",""))
                        dp  = str(row.get("dst_port",""))

                        total += 1
                        counts[pred] = counts.get(pred,0) + 1
                        if pred != "normal":
                            attacks += 1

                        # terminal output
                        print_pred(ts,src,dst,pred,conf,true_lbl)

                        # Phase 3
                        run_phase3(pred, conf, src, dst)

                        # log
                        log_wr.writerow([
                            ts,src,dst,sp,dp,
                            pred,f"{conf:.4f}",true_lbl
                        ])
                        log_fh.flush()

                    except Exception:
                        pass

                seen[fname] = n_seen + len(new)

            # stats every 100 rows
            if total > 0 and total % 100 == 0:
                rate = round(attacks/total*100,1)
                print(
                    f"\n{BLD}── Stats{NC}  "
                    f"total={total}  attacks={attacks}  "
                    f"rate={rate}%  {dict(counts)}\n"
                )

            time.sleep(POLL_SECS)

    except KeyboardInterrupt:
        pass
    finally:
        log_fh.close()


def main():
    print("=" * 55)
    print("IDS — Live inference  (Phase 2 + Phase 3)")
    print("=" * 55)
    print(f"\n[*] Loading model ...")
    model, scaler, encoders, feat_cols, le = load_artifacts()
    print(f"\n[*] Phase 3:")
    print(f"    Alerts   : {'ON'  if ALERTS_ENABLED  else 'OFF'}")
    print(f"    Blocking : {'ON'  if BLOCKING_ENABLED else 'OFF'}")
    print(f"    Alert at : {ALERT_THRESHOLD*100:.0f}% confidence")
    print(f"    Block at : {BLOCK_THRESHOLD*100:.0f}% confidence")
    print(f"[*] Press Ctrl+C to stop\n")
    watch_csv(model, scaler, encoders, feat_cols, le)
    print(f"\n[*] Stopped. Log: {PRED_LOG}")


if __name__ == "__main__":
    if BLOCKING_ENABLED and os.geteuid() != 0:
        print(f"{YLW}[WARN]{NC} Not root — iptables will fail.")
        print(f"       Run: sudo python3 predict.py")
    main()
