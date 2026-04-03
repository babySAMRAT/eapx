"""
identity.py — Enhanced EAP identity harvesting with anonymous
identity detection, domain hint extraction, and OUI vendor lookup.
"""

from scapy.all import sniff, Raw
import datetime
import os
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOOT_DIR = os.path.join(BASE_DIR, "loot")

# ── Minimal OUI table (~200 common vendors) ──
OUI_TABLE = {
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0A:27": "Apple",
    "00:0A:95": "Apple", "00:0D:93": "Apple", "00:10:FA": "Apple",
    "00:11:24": "Apple", "00:14:51": "Apple", "00:16:CB": "Apple",
    "00:17:F2": "Apple", "00:19:E3": "Apple", "00:1B:63": "Apple",
    "00:1C:B3": "Apple", "00:1D:4F": "Apple", "00:1E:52": "Apple",
    "00:1F:5B": "Apple", "00:1F:F3": "Apple", "00:21:E9": "Apple",
    "00:22:41": "Apple", "00:23:12": "Apple", "00:23:32": "Apple",
    "00:23:6C": "Apple", "00:23:DF": "Apple", "00:24:36": "Apple",
    "00:25:00": "Apple", "00:25:4B": "Apple", "00:25:BC": "Apple",
    "00:26:08": "Apple", "00:26:4A": "Apple", "00:26:B0": "Apple",
    "00:26:BB": "Apple", "00:3E:E1": "Apple", "00:50:E4": "Apple",
    "00:61:71": "Apple", "04:0C:CE": "Apple", "04:15:52": "Apple",
    "04:26:65": "Apple", "04:F1:3E": "Apple", "08:66:98": "Apple",
    "08:74:02": "Apple", "10:40:F3": "Apple", "10:9A:DD": "Apple",
    "14:10:9F": "Apple", "18:AF:8F": "Apple", "20:78:F0": "Apple",
    "24:A0:74": "Apple", "28:6A:BA": "Apple", "2C:B4:3A": "Apple",
    "34:36:3B": "Apple", "38:C9:86": "Apple", "3C:15:C2": "Apple",
    "40:33:1A": "Apple", "44:D8:84": "Apple", "48:60:BC": "Apple",
    "4C:57:CA": "Apple", "50:32:75": "Apple", "54:26:96": "Apple",
    "58:55:CA": "Apple", "5C:F7:E6": "Apple", "60:03:08": "Apple",
    "64:A3:CB": "Apple", "68:5B:35": "Apple", "6C:40:08": "Apple",
    "70:DE:E2": "Apple", "74:E2:F5": "Apple", "78:31:C1": "Apple",
    "7C:D1:C3": "Apple", "80:E6:50": "Apple", "84:38:35": "Apple",
    "88:66:A5": "Apple", "8C:85:90": "Apple", "90:27:E4": "Apple",
    "94:94:26": "Apple", "98:01:A7": "Apple", "9C:20:7B": "Apple",
    "A0:99:9B": "Apple", "A4:D1:D2": "Apple", "A8:20:66": "Apple",
    "AC:BC:32": "Apple", "B0:34:95": "Apple", "B4:18:D1": "Apple",
    "B8:17:C2": "Apple", "BC:52:B7": "Apple", "C0:63:94": "Apple",
    "C4:2C:03": "Apple", "C8:69:CD": "Apple", "CC:08:E0": "Apple",
    "D0:E1:40": "Apple", "D4:F4:6F": "Apple", "D8:BB:2C": "Apple",
    "DC:2B:2A": "Apple", "E0:B9:BA": "Apple", "E4:25:E7": "Apple",
    "F0:B4:79": "Apple", "F4:5C:89": "Apple",
    # Intel
    "00:02:B3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel",
    "00:07:E9": "Intel", "00:0C:F1": "Intel", "00:0E:0C": "Intel",
    "00:0E:35": "Intel", "00:11:11": "Intel", "00:12:F0": "Intel",
    "00:13:02": "Intel", "00:13:20": "Intel", "00:13:CE": "Intel",
    "00:13:E8": "Intel", "00:15:00": "Intel", "00:15:17": "Intel",
    "00:16:6F": "Intel", "00:16:76": "Intel", "00:16:EA": "Intel",
    "00:16:EB": "Intel", "00:18:DE": "Intel", "00:19:D1": "Intel",
    "00:19:D2": "Intel", "00:1B:21": "Intel", "00:1B:77": "Intel",
    "00:1C:BF": "Intel", "00:1D:E0": "Intel", "00:1D:E1": "Intel",
    "00:1E:64": "Intel", "00:1E:65": "Intel", "00:1F:3B": "Intel",
    "00:1F:3C": "Intel", "00:20:7B": "Intel", "00:21:5C": "Intel",
    "00:21:5D": "Intel", "00:21:6A": "Intel", "00:21:6B": "Intel",
    "00:22:FA": "Intel", "00:22:FB": "Intel", "00:24:D6": "Intel",
    "00:24:D7": "Intel", "00:27:10": "Intel",
    # Samsung
    "00:00:F0": "Samsung", "00:02:78": "Samsung", "00:07:AB": "Samsung",
    "00:09:18": "Samsung", "00:0D:AE": "Samsung", "00:12:47": "Samsung",
    "00:12:FB": "Samsung", "00:13:77": "Samsung", "00:15:99": "Samsung",
    "00:16:32": "Samsung", "00:16:6B": "Samsung", "00:16:DB": "Samsung",
    "00:17:C9": "Samsung", "00:17:D5": "Samsung", "00:18:AF": "Samsung",
    "00:1A:8A": "Samsung", "00:1B:98": "Samsung", "00:1C:43": "Samsung",
    "00:1D:25": "Samsung", "00:1D:F6": "Samsung", "00:1E:7D": "Samsung",
    "00:1F:CC": "Samsung", "00:1F:CD": "Samsung", "00:21:19": "Samsung",
    "00:21:D1": "Samsung", "00:21:D2": "Samsung", "00:23:39": "Samsung",
    "00:23:3A": "Samsung", "00:23:99": "Samsung", "00:23:D6": "Samsung",
    "00:23:D7": "Samsung", "00:24:54": "Samsung", "00:24:90": "Samsung",
    "00:24:91": "Samsung", "00:25:66": "Samsung", "00:25:67": "Samsung",
    "00:26:37": "Samsung",
    # Dell
    "00:06:5B": "Dell", "00:08:74": "Dell", "00:0B:DB": "Dell",
    "00:0D:56": "Dell", "00:0F:1F": "Dell", "00:11:43": "Dell",
    "00:12:3F": "Dell", "00:13:72": "Dell", "00:14:22": "Dell",
    "00:15:C5": "Dell", "00:18:8B": "Dell", "00:19:B9": "Dell",
    "00:1A:A0": "Dell", "00:1C:23": "Dell", "00:1D:09": "Dell",
    "00:1E:4F": "Dell", "00:1E:C9": "Dell", "00:21:70": "Dell",
    "00:21:9B": "Dell", "00:22:19": "Dell", "00:23:AE": "Dell",
    "00:24:E8": "Dell", "00:25:64": "Dell", "00:26:B9": "Dell",
    # Lenovo / ThinkPad
    "00:06:1B": "Lenovo", "00:09:2D": "Lenovo", "00:0A:E4": "Lenovo",
    "00:12:FE": "Lenovo", "00:14:5E": "Lenovo", "00:16:D4": "Lenovo",
    "00:1A:6B": "Lenovo", "00:1E:4C": "Lenovo", "00:21:CC": "Lenovo",
    "00:22:4D": "Lenovo", "00:24:7E": "Lenovo", "00:26:2D": "Lenovo",
    # HP
    "00:01:E6": "HP", "00:01:E7": "HP", "00:02:A5": "HP",
    "00:04:EA": "HP", "00:08:02": "HP", "00:08:83": "HP",
    "00:0A:57": "HP", "00:0B:CD": "HP", "00:0D:9D": "HP",
    "00:0E:7F": "HP", "00:0F:20": "HP", "00:0F:61": "HP",
    "00:10:83": "HP", "00:11:0A": "HP", "00:11:85": "HP",
    "00:12:79": "HP", "00:13:21": "HP", "00:14:38": "HP",
    "00:14:C2": "HP", "00:15:60": "HP", "00:16:35": "HP",
    "00:17:08": "HP", "00:17:A4": "HP", "00:18:71": "HP",
    "00:18:FE": "HP", "00:19:BB": "HP", "00:1A:4B": "HP",
    "00:1B:78": "HP", "00:1C:C4": "HP", "00:1D:31": "HP",
    "00:1D:B3": "HP", "00:1E:0B": "HP", "00:1F:29": "HP",
    "00:1F:FE": "HP", "00:21:5A": "HP", "00:22:64": "HP",
    "00:23:7D": "HP", "00:24:81": "HP", "00:25:B3": "HP",
    "00:26:55": "HP",
    # Cisco
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:01:43": "Cisco",
    "00:01:63": "Cisco", "00:01:64": "Cisco", "00:01:96": "Cisco",
    "00:01:97": "Cisco", "00:01:C7": "Cisco", "00:01:C9": "Cisco",
    "00:02:17": "Cisco", "00:02:3D": "Cisco", "00:02:4A": "Cisco",
    "00:02:4B": "Cisco", "00:02:7D": "Cisco", "00:02:7E": "Cisco",
    "00:02:B9": "Cisco", "00:02:BA": "Cisco", "00:02:FC": "Cisco",
    "00:02:FD": "Cisco",
    # Microsoft / Surface
    "00:03:FF": "Microsoft", "00:0D:3A": "Microsoft",
    "00:12:5A": "Microsoft", "00:15:5D": "Microsoft",
    "00:17:FA": "Microsoft", "00:1D:D8": "Microsoft",
    "00:22:48": "Microsoft", "00:25:AE": "Microsoft",
    "28:18:78": "Microsoft", "7C:1E:52": "Microsoft",
    # TP-Link
    "00:27:19": "TP-Link", "10:FE:ED": "TP-Link",
    "14:CC:20": "TP-Link", "14:CF:92": "TP-Link",
    "18:A6:F7": "TP-Link", "1C:FA:68": "TP-Link",
    "24:69:68": "TP-Link", "30:B5:C2": "TP-Link",
    "50:C7:BF": "TP-Link", "54:C8:0F": "TP-Link",
    "60:E3:27": "TP-Link", "64:56:01": "TP-Link",
    "64:70:02": "TP-Link", "6C:E8:73": "TP-Link",
    "78:44:76": "TP-Link", "90:F6:52": "TP-Link",
    "A4:2B:B0": "TP-Link", "B0:4E:26": "TP-Link",
    "C0:25:E9": "TP-Link", "C4:6E:1F": "TP-Link",
    "D8:07:B6": "TP-Link", "E8:DE:27": "TP-Link",
    "EC:08:6B": "TP-Link", "F4:EC:38": "TP-Link",
    # Huawei
    "00:1E:10": "Huawei", "00:18:82": "Huawei",
    "00:25:9E": "Huawei", "00:46:4B": "Huawei",
    "04:02:1F": "Huawei", "04:B0:E7": "Huawei",
    "08:63:61": "Huawei", "0C:37:DC": "Huawei",
    "10:47:80": "Huawei", "14:B9:68": "Huawei",
    "20:A6:80": "Huawei", "24:09:95": "Huawei",
    "28:3C:E4": "Huawei", "2C:AB:00": "Huawei",
    "30:D1:7E": "Huawei", "34:CD:BE": "Huawei",
    # Qualcomm / Atheros
    "00:03:7F": "Qualcomm", "00:0E:6D": "Qualcomm",
    "00:13:74": "Qualcomm", "00:26:CB": "Qualcomm",
    # Broadcom
    "00:10:18": "Broadcom", "00:1B:E9": "Broadcom",
    "00:25:00": "Broadcom",
    # Realtek
    "00:E0:4C": "Realtek", "48:5D:60": "Realtek",
    "52:54:00": "Realtek",
    # Xiaomi
    "00:9E:C8": "Xiaomi", "04:CF:8C": "Xiaomi",
    "0C:1D:AF": "Xiaomi", "10:2A:B3": "Xiaomi",
    "14:F6:5A": "Xiaomi", "18:59:36": "Xiaomi",
    "20:82:C0": "Xiaomi", "28:6C:07": "Xiaomi",
    "34:80:B3": "Xiaomi", "38:A4:ED": "Xiaomi",
    "3C:BD:3E": "Xiaomi", "50:64:2B": "Xiaomi",
    "58:44:98": "Xiaomi", "64:CC:2E": "Xiaomi",
    "7C:1D:D9": "Xiaomi", "84:F3:EB": "Xiaomi",
    # Google
    "00:1A:11": "Google", "3C:5A:B4": "Google",
    "54:60:09": "Google", "94:EB:2C": "Google",
    "F4:F5:D8": "Google", "F4:F5:E8": "Google",
}

# ── Known anonymous identity patterns ──
ANONYMOUS_PATTERNS = [
    "anonymous", "anon@", "anonymous@",
    "user@", "eap@", "peap@",
]

harvested = {}


def oui_lookup(mac):
    """Look up the vendor name from the first 3 octets of a MAC address."""
    if not mac or mac == "unknown":
        return "Unknown"
    prefix = mac.upper()[:8]
    return OUI_TABLE.get(prefix, "Unknown")


def is_anonymous_identity(identity):
    """Check if an EAP identity is an anonymous/outer identity."""
    lower = identity.lower()
    for pattern in ANONYMOUS_PATTERNS:
        if lower.startswith(pattern):
            return True
    return False


def extract_domain(identity):
    """Extract domain hint from user@domain.com or DOMAIN\\user."""
    if "@" in identity:
        return identity.split("@", 1)[1]
    elif "\\" in identity:
        return identity.split("\\", 1)[0]
    return None


def identity_handler(pkt):
    if pkt.haslayer(Raw):
        raw = pkt[Raw].load
        if len(raw) > 5 and raw[0] == 0x02 and raw[4] == 0x01:
            try:
                identity = raw[5:].decode("utf-8", errors="ignore").strip()
                if identity and len(identity) > 2:
                    mac = pkt.addr2 if hasattr(pkt, "addr2") else "unknown"
                    if identity not in harvested:
                        vendor = oui_lookup(mac)
                        anon = is_anonymous_identity(identity)
                        domain = extract_domain(identity)

                        harvested[identity] = {
                            "mac":       mac,
                            "vendor":    vendor,
                            "domain":    domain,
                            "anonymous": anon,
                            "time":      str(datetime.datetime.now()),
                        }

                        # Display with extra context
                        tag = "ANON" if anon else "IDENTITY"
                        vendor_str = f" [{vendor}]" if vendor != "Unknown" else ""
                        domain_str = f" @{domain}" if domain else ""

                        print(f"[{tag}] {identity:<35} | MAC: {mac}{vendor_str}{domain_str}")

                        if anon:
                            print(f"    ↳ Anonymous outer identity — real username is inside PEAP tunnel")

                        # Write to loot
                        os.makedirs(LOOT_DIR, exist_ok=True)
                        with open(os.path.join(LOOT_DIR, "identities.txt"), "a") as f:
                            f.write(
                                f"{datetime.datetime.now()} | {identity} | "
                                f"{mac} | vendor={vendor} | "
                                f"domain={domain or 'N/A'} | "
                                f"anonymous={anon}\n"
                            )
            except Exception:
                pass


def harvest_identities(iface, duration=60):
    is_daemon = (duration == 0)
    dur_str = "∞ (daemon)" if is_daemon else f"{duration}s"
    print(f"\n[*] Harvesting EAP identities on {iface}")
    print(f"[*] Duration: {dur_str} | Saving to loot/identities.txt")
    print(f"[*] OUI vendor lookup enabled ({len(OUI_TABLE)} vendors)")
    print("[*] Press Ctrl+C to stop early\n")

    try:
        sniff(
            iface=iface,
            prn=identity_handler,
            store=0,
            timeout=None if is_daemon else duration,
            filter="ether proto 0x888e"
        )
    except (KeyboardInterrupt, OSError):
        pass

    print(f"\n[+] Harvested {len(harvested)} unique identities")

    anon_count = sum(1 for v in harvested.values() if v.get("anonymous"))
    real_count = len(harvested) - anon_count

    if anon_count > 0:
        print(f"    ⚠  {anon_count} anonymous (outer) identities")
        print(f"    ✓  {real_count} real identities")

    for identity, info in harvested.items():
        vendor = info.get("vendor", "")
        vendor_str = f" [{vendor}]" if vendor and vendor != "Unknown" else ""
        print(f"    {identity} → {info['mac']}{vendor_str}")

    # Save summary as JSON for reporter
    if harvested:
        os.makedirs(LOOT_DIR, exist_ok=True)
        with open(os.path.join(LOOT_DIR, "identities_summary.json"), "w") as f:
            json.dump(harvested, f, indent=2)

    return harvested
