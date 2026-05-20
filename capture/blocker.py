

import subprocess, datetime, os

BLOCKED_IPS = set()
BLOCK_LOG   = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "data", "blocked_ips.log"
)
CONF_MIN    = 0.90
WHITELIST   = {"192.168.100.20", "127.0.0.1", "0.0.0.0"}
ATTACK_TYPES= {"dos", "probe", "r2l", "u2r"}


def block_ip(src_ip: str, label: str, conf: float) -> bool:
    """
    Add an iptables DROP rule for src_ip.
    Returns True if newly blocked, False if skipped.
    """
    if src_ip in WHITELIST:
        return False
    if src_ip in BLOCKED_IPS:
        return False
    if label not in ATTACK_TYPES:
        return False
    if conf < CONF_MIN:
        return False

    try:
        subprocess.run(
            ["iptables", "-I", "INPUT", "1",
             "-s", src_ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        BLOCKED_IPS.add(src_ip)
        _log(src_ip, label, conf, "BLOCKED")
        _save_rules()
        return True
    except subprocess.CalledProcessError as e:
        print(f"[BLOCK] iptables error: {e.returncode} — {e.stderr.decode()}")
        return False


def unblock_ip(src_ip: str) -> bool:
    """Remove the DROP rule for src_ip."""
    if src_ip not in BLOCKED_IPS:
        return False
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT",
             "-s", src_ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        BLOCKED_IPS.discard(src_ip)
        _log(src_ip, "manual", 1.0, "UNBLOCKED")
        _save_rules()
        return True
    except subprocess.CalledProcessError as e:
        print(f"[UNBLOCK] iptables error: {e.returncode}")
        return False


def list_blocked() -> list:
    return list(BLOCKED_IPS)


def _save_rules():
    try:
        os.makedirs("/etc/iptables", exist_ok=True)
        with open("/etc/iptables/rules.v4", "w") as f:
            subprocess.run(["iptables-save"], stdout=f, check=True)
    except Exception:
        pass


def _log(ip: str, label: str, conf: float, action: str):
    os.makedirs(os.path.dirname(BLOCK_LOG), exist_ok=True)
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    with open(BLOCK_LOG, "a") as f:
        f.write(f"{ts}  {action:10s}  {ip:18s}  "
                f"{label:8s}  {conf*100:.0f}%\n")
