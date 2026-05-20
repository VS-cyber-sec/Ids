import smtplib
import datetime
import requests
from email.mime.text      import MIMEText
from email.mime.multipart import MIMEMultipart

# ══════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════
SLACK_WEBHOOK = "https://hooks.slack.com/services/your/slack/webhook/url"   # REPLACE with your Slack webhook URL

# Brevo SMTP — use your account login email (not the smtp alias)
BREVO_LOGIN   = "your_email@example.com"    # email you used to sign up at brevo
BREVO_PASS    = "your_xsmtpsib_key"     # the xsmtpsib- key from Brevo dashboard
SEND_TO       = "your_email@example.com"    # email to send alerts to

THRESHOLD     = 0.85
COOLDOWN_SECS = 60

# ══════════════════════════════════════════════════════════════
# Cooldown helpers
# ══════════════════════════════════════════════════════════════
_slack_sent = {}
_email_sent = {}

def _cooldown_ok(tracker: dict, ip: str) -> bool:
    last = tracker.get(ip)
    if last is None:
        return True
    return (datetime.datetime.now() - last).total_seconds() >= COOLDOWN_SECS

def _cooldown_remaining(tracker: dict, ip: str) -> int:
    last = tracker.get(ip)
    if last is None:
        return 0
    return max(0, int(COOLDOWN_SECS -
               (datetime.datetime.now() - last).total_seconds()))

# ══════════════════════════════════════════════════════════════
# Slack
# ══════════════════════════════════════════════════════════════
def send_slack(label: str, conf: float, src_ip: str, dst_ip: str):
    if conf < THRESHOLD:
        return
    if not _cooldown_ok(_slack_sent, src_ip):
        print(f"[SLACK] cooldown {_cooldown_remaining(_slack_sent, src_ip)}s left for {src_ip}")
        return
    try:
        text = (
            f":warning: *IDS ALERT — {label.upper()}*\n"
            f"Confidence : {conf*100:.1f}%\n"
            f"Source IP  : {src_ip}\n"
            f"Target IP  : {dst_ip}\n"
            f"Time       : {datetime.datetime.now().strftime('%H:%M:%S')}"
        )
        r = requests.post(SLACK_WEBHOOK,
                          json={"text": text}, timeout=10)
        if r.status_code == 200 and r.text.strip() == "ok":
            _slack_sent[src_ip] = datetime.datetime.now()
            print(f"[SLACK] Sent OK  {label.upper()} {src_ip} ({conf*100:.0f}%)")
        else:
            print(f"[SLACK] Failed  HTTP {r.status_code}: {r.text}")
    except requests.exceptions.ConnectionError:
        print("[SLACK] No internet — add NAT adapter to IDS VM")
    except requests.exceptions.Timeout:
        print("[SLACK] Timeout")
    except Exception as exc:
        print(f"[SLACK] Error: {type(exc).__name__}: {exc}")

# ══════════════════════════════════════════════════════════════
# Email  —  FIXED except block order
# ══════════════════════════════════════════════════════════════
def send_email(label: str, conf: float, src_ip: str, dst_ip: str):
    if conf < THRESHOLD:
        return
    if not _cooldown_ok(_email_sent, src_ip):
        print(f"[EMAIL] cooldown {_cooldown_remaining(_email_sent, src_ip)}s left for {src_ip}")
        return
    try:
        msg            = MIMEMultipart()
        msg["From"]    = BREVO_LOGIN
        msg["To"]      = SEND_TO
        msg["Subject"] = f"IDS ALERT — {label.upper()} detected"
        body = (
            f"Attack detected on your network\n\n"
            f"Type       : {label.upper()}\n"
            f"Confidence : {conf*100:.1f}%\n"
            f"Source IP  : {src_ip}\n"
            f"Target IP  : {dst_ip}\n"
            f"Time       : {datetime.datetime.now()}\n"
        )
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP("smtp-relay.brevo.com", 587, timeout=15) as s:
            s.ehlo()
            s.starttls()
            s.login(BREVO_LOGIN, BREVO_PASS)
            s.send_message(msg)

        _email_sent[src_ip] = datetime.datetime.now()
        print(f"[EMAIL] Sent OK  {label.upper()} {src_ip} ({conf*100:.0f}%)")

    # ── FIX: specific exceptions BEFORE broad Exception ──────
    except smtplib.SMTPAuthenticationError as exc:
        print(f"[EMAIL] Auth failed: {exc}")
        print("        Check BREVO_LOGIN = your Brevo account email")
        print("        Check BREVO_PASS  = the xsmtpsib- key from Brevo dashboard")
    except smtplib.SMTPException as exc:
        print(f"[EMAIL] SMTP error: {exc}")
    except Exception as exc:
        # broad Exception is LAST — catches anything not caught above
        print(f"[EMAIL] Error: {type(exc).__name__}: {exc}")

# ══════════════════════════════════════════════════════════════
# Combined
# ══════════════════════════════════════════════════════════════
def alert(label: str, conf: float, src_ip: str, dst_ip: str):
    if label == "normal" or conf < THRESHOLD:
        return
    send_slack(label, conf, src_ip, dst_ip)
    send_email(label, conf, src_ip, dst_ip)

# ══════════════════════════════════════════════════════════════
# Self test
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 45)
    print("alert.py — self test")
    print("=" * 45)

    print("\n[1] Slack only:")
    send_slack("dos", 0.97, "192.168.100.10", "192.168.100.30")

    print("\n[2] Email only:")
    send_email("dos", 0.97, "192.168.100.10", "192.168.100.30")

    print("\n[3] Both together via alert():")
    alert("probe", 0.91, "192.168.100.11", "192.168.100.30")

    print("\n[4] Repeat same IP — cooldown:")
    alert("probe", 0.91, "192.168.100.11", "192.168.100.30")

    print("\n[5] Below threshold — no output:")
    alert("dos", 0.80, "192.168.100.12", "192.168.100.30")
    print("   (no output = correct)")

    print("\n" + "=" * 45)
    print("Check Slack + email inbox")
    print("=" * 45)
