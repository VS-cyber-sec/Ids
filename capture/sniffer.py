import os, sys, csv, signal, argparse, datetime, threading, time, logging

HERE         = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)

FEATURES_DIR = os.path.join(PROJECT_ROOT, "data", "features")
LOGS_DIR     = os.path.join(PROJECT_ROOT, "data", "logs")
ATTACK_LOG   = os.path.join(PROJECT_ROOT, "data", "attack_session.log")
LABEL_FILE   = os.path.join(PROJECT_ROOT, "data", "current_label.txt")
PID_FILE     = os.path.join(PROJECT_ROOT, "data", "sniffer.pid")

for d in (FEATURES_DIR, LOGS_DIR, os.path.dirname(ATTACK_LOG)):
    os.makedirs(d, exist_ok=True)

_logfile = os.path.join(
    LOGS_DIR,
    f"sniffer_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout),
              logging.FileHandler(_logfile)],
)
log = logging.getLogger("sniffer")

sys.path.insert(0, HERE)

try:
    from scapy.all import sniff, IP, TCP, UDP, conf
    conf.verb = 0
    import logging as _sl
    _sl.getLogger("scapy.runtime").setLevel(_sl.ERROR)
except ImportError:
    log.error("scapy not found — activate venv first")
    sys.exit(1)

try:
    from flow_tracker      import FlowTracker
    from feature_extractor import extract_features, WindowStats, NSL_KDD_COLUMNS
except ImportError as e:
    log.error(f"Cannot import pipeline modules: {e}")
    sys.exit(1)

# ── config ────────────────────────────────────────────────────
DEFAULT_IFACE    = "ens36"
BPF_FILTER       = "ip"
CSV_FLUSH_SECS   = 5
STATS_SECS       = 60
MAX_ROWS_PER_CSV = 100_000
FLOW_TIMEOUT     = 120

CSV_FIELDS = (["timestamp","src_ip","dst_ip","src_port","dst_port","label"]
              + NSL_KDD_COLUMNS)

# ── globals ───────────────────────────────────────────────────
tracker = None
window  = None

_csv_lock = threading.Lock()
_csv_fh   = None
_csv_wr   = None
_csv_path = None
_csv_rows = 0
_csv_idx  = 0
_running  = True
_start_ts = None

_n_total = 0; _n_ip = 0; _n_feat = 0; _n_err = 0

# ── label file ────────────────────────────────────────────────
def _write_label(label):
    """Attack script calls this by writing to LABEL_FILE."""
    with open(LABEL_FILE, "w") as f:
        f.write(label)

def _read_label():
    """Sniffer reads current label from LABEL_FILE every packet."""
    try:
        with open(LABEL_FILE) as f:
            return f.read().strip() or "normal"
    except FileNotFoundError:
        return "normal"

# ── CSV helpers ───────────────────────────────────────────────
def _open_csv():
    global _csv_idx
    os.makedirs(FEATURES_DIR, exist_ok=True)
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(FEATURES_DIR, f"capture_{ts}_{_csv_idx:03d}.csv")
    fh   = open(path, "w", newline="", buffering=1)
    wr   = csv.DictWriter(fh, fieldnames=CSV_FIELDS,
                          extrasaction="ignore", lineterminator="\n")
    wr.writeheader()
    _csv_idx += 1
    log.info(f"CSV  → {path}")
    return fh, wr, path

def _write_row(row):
    global _csv_fh, _csv_wr, _csv_path, _csv_rows
    with _csv_lock:
        if _csv_rows >= MAX_ROWS_PER_CSV:
            _csv_fh.flush(); _csv_fh.close()
            log.info(f"CSV rotated after {_csv_rows} rows")
            _csv_fh, _csv_wr, _csv_path = _open_csv()
            _csv_rows = 0
        _csv_wr.writerow(row)
        _csv_rows += 1

def _flush_loop():
    while _running:
        time.sleep(CSV_FLUSH_SECS)
        with _csv_lock:
            if _csv_fh and not _csv_fh.closed:
                _csv_fh.flush()

def _close_csv():
    with _csv_lock:
        if _csv_fh and not _csv_fh.closed:
            _csv_fh.flush(); _csv_fh.close()
            log.info(f"CSV closed — {_csv_rows} rows → {_csv_path}")

# ── packet callback ───────────────────────────────────────────
def _port(pkt, d):
    if TCP in pkt: return pkt[TCP].sport if d=="src" else pkt[TCP].dport
    if UDP in pkt: return pkt[UDP].sport if d=="src" else pkt[UDP].dport
    return 0

def _on_packet(pkt):
    global _n_total, _n_ip, _n_feat, _n_err
    _n_total += 1
    if IP not in pkt: return
    _n_ip += 1
    try:
        key, flow = tracker.update(pkt)
        if flow is None: return
        feats = extract_features(pkt, flow, window)
        if feats is None: return
        ip  = pkt[IP]
        # Read label from file — attack script keeps this updated
        label = _read_label()
        row = {
            "timestamp": datetime.datetime.now().isoformat(
                             timespec="milliseconds"),
            "src_ip":   ip.src,
            "dst_ip":   ip.dst,
            "src_port": _port(pkt,"src"),
            "dst_port": _port(pkt,"dst"),
            "label":    label,
        }
        row.update(feats)
        _write_row(row)
        _n_feat += 1
    except Exception as exc:
        _n_err += 1
        if _n_err % 200 == 1:
            log.warning(f"Callback error #{_n_err}: {exc}")

# ── stats ─────────────────────────────────────────────────────
def _stats_loop():
    while _running:
        time.sleep(STATS_SECS)
        if not _running: break
        el = time.time() - _start_ts
        label = _read_label()
        log.info(
            f"STATS | pkts={_n_total:,}  ip={_n_ip:,}  "
            f"rows={_n_feat:,}  err={_n_err}  "
            f"label={label!r}  flows={tracker.active_count()}  "
            f"pps={_n_total/max(el,1):.0f}"
        )

# ── signals ───────────────────────────────────────────────────
def _sig_stop(s, f):
    global _running
    log.info("Stop signal — shutting down ...")
    _running = False

# ── interface ─────────────────────────────────────────────────
def _enable_promisc(iface):
    try:
        import subprocess
        subprocess.run(["ip","link","set",iface,"promisc","on"],
                       check=True, capture_output=True)
        log.info(f"Promiscuous ON → {iface}")
    except Exception as e:
        log.warning(f"Could not set promiscuous: {e}")

def _check_promisc(iface):
    try:
        with open(f"/sys/class/net/{iface}/flags") as f:
            flags = int(f.read().strip(), 16)
        st = "ON" if flags & 0x100 else "OFF ← WARNING"
        log.info(f"Promiscuous check: {st}")
    except Exception:
        pass

def _detect_iface():
    try:
        import subprocess
        out = subprocess.run(["ip","-4","addr","show"],
                             capture_output=True, text=True, timeout=5).stdout
        lines = out.splitlines()
        for i, line in enumerate(lines):
            if "inet 192.168.100." in line:
                for prev in reversed(lines[:i]):
                    parts = prev.strip().split(":")
                    if len(parts) >= 2:
                        name = parts[1].strip().split("@")[0].split()[0]
                        if name and name != "lo":
                            log.info(f"Auto-detected iface: {name}")
                            return name
    except Exception:
        pass
    return DEFAULT_IFACE

# ── args ──────────────────────────────────────────────────────
def _args():
    p = argparse.ArgumentParser()
    p.add_argument("--iface","-i", default=None)
    p.add_argument("--filter","-f", default=BPF_FILTER)
    p.add_argument("--daemon","-d", action="store_true")
    p.add_argument("--no-promisc", action="store_true")
    return p.parse_args()

def _daemonise():
    if os.fork() > 0: sys.exit(0)
    os.setsid()
    if os.fork() > 0: sys.exit(0)
    log.info(f"Daemonised — PID {os.getpid()}")

# ── main ──────────────────────────────────────────────────────
def main():
    global tracker, window
    global _csv_fh, _csv_wr, _csv_path
    global _start_ts, _running

    args = _args()
    if args.daemon: _daemonise()

    with open(PID_FILE,"w") as f: f.write(str(os.getpid()))
    log.info(f"PID file → {PID_FILE}")

    iface = args.iface or _detect_iface()
    if not args.no_promisc: _enable_promisc(iface)
    _check_promisc(iface)

    # Write initial label
    _write_label("normal")

    tracker = FlowTracker(timeout=FLOW_TIMEOUT)
    window  = WindowStats()
    _csv_fh, _csv_wr, _csv_path = _open_csv()

    signal.signal(signal.SIGINT,  _sig_stop)
    signal.signal(signal.SIGTERM, _sig_stop)

    _start_ts = time.time()
    threading.Thread(target=_flush_loop, daemon=True).start()
    threading.Thread(target=_stats_loop, daemon=True).start()

    log.info("=" * 55)
    log.info("IDS SNIFFER STARTED")
    log.info(f"  PID        : {os.getpid()}")
    log.info(f"  Interface  : {iface}")
    log.info(f"  CSV dir    : {FEATURES_DIR}")
    log.info(f"  Label file : {LABEL_FILE}")
    log.info(f"  Log file   : {_logfile}")
    log.info("  Label is controlled by attack script automatically")
    log.info(f"  Stop with  : sudo kill {os.getpid()}")
    log.info("=" * 55)

    try:
        sniff(
            iface       = iface,
            prn         = _on_packet,
            filter      = args.filter,
            store       = False,
            stop_filter = lambda _: not _running,
        )
    except PermissionError:
        log.error("Permission denied — run with: sudo python3 sniffer.py")
        sys.exit(1)
    except OSError as e:
        log.error(f"Interface error on '{iface}': {e}")
        log.error("Check interface name: ip link show")
        sys.exit(1)

    _running = False
    tracker.stop()
    _write_label("normal")
    _close_csv()
    try: os.remove(PID_FILE)
    except FileNotFoundError: pass

    el = time.time() - _start_ts
    log.info("=" * 55)
    log.info("SNIFFER STOPPED")
    log.info(f"  Duration : {el:.0f}s")
    log.info(f"  Rows     : {_n_feat:,}")
    log.info(f"  CSV      : {_csv_path}")
    log.info("=" * 55)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: sudo python3 sniffer.py")
        sys.exit(1)
    main()
