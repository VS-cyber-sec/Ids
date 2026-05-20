import time
import threading

FLOW_TIMEOUT = 120     # seconds idle before flow expires
MAX_FLOWS    = 50_000  # memory cap — evict oldest if exceeded


class FlowTracker:
    def __init__(self, timeout=FLOW_TIMEOUT):
        self.timeout = timeout
        self.flows   = {}
        self._lock   = threading.Lock()
        self._running = True
        t = threading.Thread(target=self._reap_loop, daemon=True)
        t.start()

    # ── public ──────────────────────────────────────────────

    def update(self, pkt):
        """
        Call once per packet.
        Returns (key, flow_snapshot_dict) or (None, None).
        """
        from scapy.all import IP
        if IP not in pkt:
            return None, None
        key = self._make_key(pkt)
        if key is None:
            return None, None
        now = time.time()
        with self._lock:
            if key not in self.flows:
                if len(self.flows) >= MAX_FLOWS:
                    self._evict_oldest()
                self.flows[key] = self._new_flow(pkt, now, key)
            self._update_flow(self.flows[key], pkt, now)
            return key, dict(self.flows[key])

    def active_count(self):
        with self._lock:
            return len(self.flows)

    def stop(self):
        self._running = False

    # ── key ─────────────────────────────────────────────────

    @staticmethod
    def _make_key(pkt):
        from scapy.all import IP, TCP, UDP, ICMP
        ip = pkt[IP]
        if TCP in pkt:
            proto = "tcp"; sp = pkt[TCP].sport; dp = pkt[TCP].dport
        elif UDP in pkt:
            proto = "udp"; sp = pkt[UDP].sport; dp = pkt[UDP].dport
        elif ICMP in pkt:
            proto = "icmp"; sp = pkt[ICMP].type; dp = pkt[ICMP].code
        else:
            proto = "other"; sp = 0; dp = 0
        if (ip.src, sp) <= (ip.dst, dp):
            return (ip.src, ip.dst, sp, dp, proto)
        return (ip.dst, ip.src, dp, sp, proto)

    # ── flow lifecycle ───────────────────────────────────────

    @staticmethod
    def _new_flow(pkt, now, key):
        from scapy.all import IP
        return dict(
            key=key, src_ip=pkt[IP].src, dst_ip=pkt[IP].dst,
            protocol=key[4], start_time=now, last_seen=now,
            src_bytes=0, dst_bytes=0,
            pkt_count=0, src_pkts=0, dst_pkts=0,
            syn_count=0, ack_count=0, fin_count=0,
            rst_count=0, urg_count=0, psh_count=0,
            wrong_fragment=0, urgent_count=0,
            serror_count=0, rerror_count=0,
            saw_syn=False, saw_synack=False,
            saw_fin=False, saw_rst=False,
            established=False, closed=False,
        )

    def _update_flow(self, flow, pkt, now):
        from scapy.all import IP, TCP
        ip   = pkt[IP]
        plen = len(pkt)
        flow["last_seen"]  = now
        flow["pkt_count"] += 1
        if ip.src == flow["key"][0]:
            flow["src_bytes"] += plen; flow["src_pkts"] += 1
        else:
            flow["dst_bytes"] += plen; flow["dst_pkts"] += 1
        if ip.frag:
            flow["wrong_fragment"] += 1
        if TCP in pkt:
            f = pkt[TCP].flags
            syn = bool(f & 0x02); ack = bool(f & 0x10)
            fin = bool(f & 0x01); rst = bool(f & 0x04)
            urg = bool(f & 0x20); psh = bool(f & 0x08)
            if syn: flow["syn_count"] += 1
            if ack: flow["ack_count"] += 1
            if fin: flow["fin_count"] += 1
            if rst: flow["rst_count"] += 1
            if urg: flow["urg_count"] += 1
            if psh: flow["psh_count"] += 1
            if syn and not ack:
                flow["saw_syn"] = True
                flow["serror_count"] += 1
            if syn and ack:
                flow["saw_synack"] = True
                flow["serror_count"] = max(0, flow["serror_count"] - 1)
            if fin: flow["saw_fin"] = True
            if rst:
                flow["saw_rst"] = True
                if flow["saw_syn"] and not flow["saw_synack"]:
                    flow["rerror_count"] += 1
            if flow["saw_syn"] and flow["saw_synack"]:
                flow["established"] = True
            if flow["established"] and (fin or rst):
                flow["closed"] = True
            if urg and pkt[TCP].urgptr > 0:
                flow["urgent_count"] += 1

    def _evict_oldest(self):
        if self.flows:
            k = min(self.flows, key=lambda x: self.flows[x]["last_seen"])
            del self.flows[k]

    def _reap_loop(self):
        while self._running:
            time.sleep(30)
            now = time.time()
            with self._lock:
                dead = [k for k, f in self.flows.items()
                        if now - f["last_seen"] > self.timeout]
                for k in dead:
                    del self.flows[k]


# ── self-test ────────────────────────────────────────────────
if __name__ == "__main__":
    from scapy.all import Ether, IP, TCP
    t = FlowTracker(timeout=5)
    syn    = Ether()/IP(src="10.0.0.1",dst="10.0.0.2")/TCP(sport=1234,dport=80,flags="S")
    synack = Ether()/IP(src="10.0.0.2",dst="10.0.0.1")/TCP(sport=80,dport=1234,flags="SA")
    k1,f1 = t.update(syn)
    k2,f2 = t.update(synack)
    assert k1 == k2
    assert f2["pkt_count"] == 2
    assert f2["established"] == True
    assert f2["src_bytes"] > 0
    t.stop()
    print("flow_tracker.py  — ALL TESTS PASSED")
