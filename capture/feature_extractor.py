import time
from collections import deque

# ── port → service name ──────────────────────────────────────
PORT_SVC = {
    20:"ftp_data", 21:"ftp", 22:"ssh", 23:"telnet",
    25:"smtp", 53:"domain", 70:"gopher", 79:"finger",
    80:"http", 110:"pop_3", 111:"sunrpc", 113:"auth",
    119:"nntp", 123:"ntp_u", 137:"netbios_ns",
    138:"netbios_dgm", 139:"netbios_ssn", 143:"imap4",
    161:"snmp", 179:"bgp", 194:"IRC", 389:"ldap",
    443:"http_443", 514:"shell", 515:"printer",
    543:"klogin", 544:"kshell", 1433:"sql_net",
    1521:"sql_net", 3306:"sql_net", 5432:"sql_net",
    6000:"X11", 6667:"IRC", 8080:"http_8001",
}

# ── ordered column list (use for CSV header) ─────────────────
NSL_KDD_COLUMNS = [
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


# ── WindowStats ──────────────────────────────────────────────
class WindowStats:
    """
    Sliding 2-second time window + 100-connection host window
    for computing NSL-KDD rate features (cols 23-41).
    """
    TIME_WIN  = 2.0
    HOST_WIN  = 100

    def __init__(self):
        self._tw  = deque()          # (ts, dst_ip, svc, sport, serr, rerr)
        self._hw  = {}               # dst_ip -> deque of records

    def record(self, dst_ip, svc, sport, serr, rerr):
        now = time.time()
        rec = (now, dst_ip, svc, sport, serr, rerr)
        self._tw.append(rec)
        self._hw.setdefault(dst_ip, deque(maxlen=self.HOST_WIN)).append(rec)
        cutoff = now - self.TIME_WIN
        while self._tw and self._tw[0][0] < cutoff:
            self._tw.popleft()

    def time_stats(self, dst_ip, svc):
        w  = list(self._tw)
        if not w:
            return self._zt()
        sh = [r for r in w if r[1] == dst_ip]
        ss = [r for r in w if r[2] == svc]
        n  = max(len(sh), 1)
        ns = max(len(ss), 1)
        def r(s, tot, idx):
            return round(sum(1 for x in s if x[idx])/max(tot,1), 4)
        ssh = [x for x in sh if x[2]==svc]
        return dict(
            count=len(sh), srv_count=len(ss),
            serror_rate=r(sh,n,4), srv_serror_rate=r(ss,ns,4),
            rerror_rate=r(sh,n,5), srv_rerror_rate=r(ss,ns,5),
            same_srv_rate=round(len(ssh)/n,4),
            diff_srv_rate=round(1-len(ssh)/n,4),
            srv_diff_host_rate=round(
                len([x for x in ss if x[1]!=dst_ip])/ns,4),
        )

    def host_stats(self, dst_ip, svc, sport):
        hw = list(self._hw.get(dst_ip, []))
        if not hw:
            return self._zh()
        n  = len(hw)
        ss = [r for r in hw if r[2]==svc]
        ns = max(len(ss),1)
        def r(s, tot, idx=None):
            if idx is None: return round(len(s)/max(tot,1),4)
            return round(sum(1 for x in s if x[idx])/max(tot,1),4)
        return dict(
            dst_host_count=n,
            dst_host_srv_count=len(ss),
            dst_host_same_srv_rate=r(ss,n),
            dst_host_diff_srv_rate=round(1-r(ss,n),4),
            dst_host_same_src_port_rate=r(
                [x for x in hw if x[3]==sport],n),
            dst_host_srv_diff_host_rate=0.0,
            dst_host_serror_rate=r(ss,n,4),
            dst_host_srv_serror_rate=r(ss,ns,4),
            dst_host_rerror_rate=r(ss,n,5),
            dst_host_srv_rerror_rate=r(ss,ns,5),
        )

    @staticmethod
    def _zt():
        return dict(count=0,srv_count=0,serror_rate=0.0,
            srv_serror_rate=0.0,rerror_rate=0.0,srv_rerror_rate=0.0,
            same_srv_rate=1.0,diff_srv_rate=0.0,srv_diff_host_rate=0.0)

    @staticmethod
    def _zh():
        return dict(dst_host_count=1,dst_host_srv_count=1,
            dst_host_same_srv_rate=1.0,dst_host_diff_srv_rate=0.0,
            dst_host_same_src_port_rate=1.0,dst_host_srv_diff_host_rate=0.0,
            dst_host_serror_rate=0.0,dst_host_srv_serror_rate=0.0,
            dst_host_rerror_rate=0.0,dst_host_srv_rerror_rate=0.0)


# ── helpers ──────────────────────────────────────────────────
def _svc(pkt):
    from scapy.all import TCP, UDP
    if TCP in pkt:
        l = pkt[TCP]
    elif UDP in pkt:
        l = pkt[UDP]
    else:
        return "other"
    return PORT_SVC.get(l.dport) or PORT_SVC.get(l.sport) or "other"

def _flag(flow, pkt):
    from scapy.all import TCP
    if TCP not in pkt:
        return "SF"
    s,sa,f,r = (flow.get(k,False) for k in
                ("saw_syn","saw_synack","saw_fin","saw_rst"))
    est = flow.get("established", False)
    if s and sa and f and not r: return "SF"
    if s and sa and not f and not r: return "S1"
    if s and not sa and not r: return "S0"
    if s and not sa and r: return "REJ"
    if est and r: return "RSTO"
    if s and f and not sa: return "SH"
    return "OTH"

def _port(pkt, d):
    from scapy.all import TCP, UDP
    if TCP in pkt: return pkt[TCP].sport if d=="src" else pkt[TCP].dport
    if UDP in pkt: return pkt[UDP].sport if d=="src" else pkt[UDP].dport
    return 0


# ── main extractor ───────────────────────────────────────────
def extract_features(pkt, flow: dict, window: WindowStats):
    """
    Returns dict of all 41 NSL-KDD features, or None if not IP.
    """
    from scapy.all import IP
    if IP not in pkt or flow is None:
        return None

    ip      = pkt[IP]
    now     = time.time()
    svc     = _svc(pkt)
    sport   = _port(pkt,"src")
    dport   = _port(pkt,"dst")
    proto   = flow.get("protocol","tcp")
    dur     = int(now - flow.get("start_time", now))
    serr    = flow.get("serror_count",0) > 0
    rerr    = flow.get("rerror_count",0) > 0

    window.record(ip.dst, svc, sport, serr, rerr)
    ts = window.time_stats(ip.dst, svc)
    hs = window.host_stats(ip.dst, svc, sport)

    feats = {
        # basic (1-9)
        "duration":          dur,
        "protocol_type":     proto,
        "service":           svc,
        "flag":              _flag(flow, pkt),
        "src_bytes":         int(flow.get("src_bytes",0)),
        "dst_bytes":         int(flow.get("dst_bytes",0)),
        "land":              1 if ip.src==ip.dst and sport==dport else 0,
        "wrong_fragment":    int(flow.get("wrong_fragment",0)),
        "urgent":            int(flow.get("urgent_count",0)),
        # content (10-22) — DPI placeholders
        "hot":0,"num_failed_logins":0,"logged_in":0,
        "num_compromised":0,"root_shell":0,"su_attempted":0,
        "num_root":0,"num_file_creations":0,"num_shells":0,
        "num_access_files":0,"num_outbound_cmds":0,
        "is_host_login":0,"is_guest_login":0,
        # time-window (23-31)
        "count":             ts["count"],
        "srv_count":         ts["srv_count"],
        "serror_rate":       ts["serror_rate"],
        "srv_serror_rate":   ts["srv_serror_rate"],
        "rerror_rate":       ts["rerror_rate"],
        "srv_rerror_rate":   ts["srv_rerror_rate"],
        "same_srv_rate":     ts["same_srv_rate"],
        "diff_srv_rate":     ts["diff_srv_rate"],
        "srv_diff_host_rate":ts["srv_diff_host_rate"],
        # host-window (32-41)
        **hs,
    }

    assert len(feats) == 41, f"Expected 41 got {len(feats)}"
    return feats


# ── self-test ────────────────────────────────────────────────
if __name__ == "__main__":
    from scapy.all import Ether, IP, TCP, UDP, ICMP
    from flow_tracker import FlowTracker
    t = FlowTracker(); w = WindowStats()

    def _run(pkt):
        k,f = t.update(pkt); return extract_features(pkt,f,w)

    # TCP SYN → http, S0
    p = Ether()/IP(src="10.0.0.1",dst="10.0.0.2")/TCP(sport=5000,dport=80,flags="S")
    r = _run(p)
    assert r["protocol_type"]=="tcp"
    assert r["service"]=="http"
    assert r["flag"]=="S0"
    assert len(r)==41
    print(f"  TCP SYN  → svc={r['service']}  flag={r['flag']}  cols={len(r)}")

    # UDP DNS → domain, SF
    p = Ether()/IP(src="10.0.0.1",dst="10.0.0.2")/UDP(sport=9000,dport=53)
    r = _run(p)
    assert r["protocol_type"]=="udp"
    assert r["service"]=="domain"
    assert r["flag"]=="SF"
    print(f"  UDP DNS  → svc={r['service']}  flag={r['flag']}")

    # ICMP → other, SF
    p = Ether()/IP(src="10.0.0.1",dst="10.0.0.2")/ICMP()
    r = _run(p)
    assert r["protocol_type"]=="icmp"
    print(f"  ICMP     → svc={r['service']}  flag={r['flag']}")

    # column name check
    missing = [c for c in NSL_KDD_COLUMNS if c not in r]
    assert not missing, f"Missing: {missing}"
    print(f"  All 41 NSL-KDD columns present")

    t.stop()
    print("feature_extractor.py — ALL TESTS PASSED")
