

#CURRENTLY UNDER WORKING PHASE ⚠️⚠️⚠️⚠️⚠️


# EAPx — WPA2-Enterprise Attack Framework

```
███████╗ █████╗ ██████╗ ██╗  ██╗
██╔════╝██╔══██╗██╔══██╗╚██╗██╔╝
█████╗  ███████║██████╔╝ ╚███╔╝
██╔══╝  ██╔══██║██╔═══╝  ██╔██╗
███████╗██║  ██║██║     ██╔╝ ██╗
╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝
```

**EAPx** is an all-in-one WPA2-Enterprise (802.1X/EAP) penetration testing framework built for authorized red-team engagements. It automates the full attack chain — from network discovery, RADIUS certificate cloning, and EAP fingerprinting to evil twin deployment, real-time credential capture, multi-stage hash cracking, and report generation.

> ⚠️ **Legal Disclaimer:** This tool is intended for **authorized security testing only**. Unauthorized use against networks you do not own or have explicit permission to test is **illegal**. The author assumes no liability for misuse.

---

## Table of Contents

- [Features](#features)
- [hostapd-wpe Integration](#hostapd-wpe-integration)
- [Dual-Interface Architecture](#dual-interface-architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
  - [menu](#menu--interactive-guided-mode)
  - [setup](#setup--generate-certs--check-dependencies)
  - [scan](#scan--discover-enterprise-networks)
  - [attack](#attack--full-attack-pipeline)
  - [deauth](#deauth--deauthentication-attack)
  - [channel-hop](#channel-hop--channel-hopping-deauth)
  - [harvest](#harvest--passive-identity-harvesting)
  - [karma](#karma--karma-attack)
  - [portal](#portal--hostile-captive-portal)
  - [crack](#crack--multi-stage-hash-cracking)
  - [report](#report--generate-pentest-report)
- [Attack Workflow](#attack-workflow)
- [Project Structure](#project-structure)
- [Output & Loot](#output--loot)
- [Author](#author)

---

## Features

| Module | Description |
|--------|-------------|
| **Scanner** | Discovers WPA2-Enterprise (MGT) networks via `airodump-ng` |
| **Cert Clone** | Probes the real AP's RADIUS cert and mirrors its CN/O/OU/SAN fields |
| **Evil Twin AP** | Spawns a rogue AP with hostapd-wpe/hostapd + real-time credential parsing |
| **EAP Probe** | Fingerprints EAP methods, detects EAP-TLS, identifies PEAP version |
| **Deauth** | 802.11 deauthentication attack to force client reconnection |
| **Channel-Hop Deauth** | Multi-channel deauth for enterprise APs spanning multiple channels |
| **Identity Harvester** | Captures EAP identities with OUI vendor lookup & anonymous detection |
| **KARMA** | Auto-spawns fake APs with enterprise SSID filtering |
| **Hostile Portal** | Captive portal phishing page that harvests domain credentials |
| **AutoCrack** | Multi-stage cracking pipeline (hashcat + ASLEAP) with custom wordlists |
| **Cert Wizard** | Generates fake CA + server certs with SAN, cloned fields, and DH params |
| **PCAP Capture** | Runs tcpdump alongside attacks for full packet capture |
| **Reporter** | Generates Markdown + JSON reports with device fingerprinting |

---

## hostapd-wpe Integration

EAPx auto-detects `hostapd-wpe` (WPE = Wireless Pwnage Edition) — the patched hostapd binary with built-in credential-logging hooks. This is the same engine used by EAPHammer.

| Feature | Vanilla `hostapd` | `hostapd-wpe` |
|---------|-------------------|---------------|
| Rogue AP | ✅ | ✅ |
| EAP identities (stdout parsing) | ✅ Limited | ✅ Full |
| GTC plaintext passwords | ⚠️ Partial | ✅ |
| MSCHAPv2 challenge/response hashes | ❌ | ✅ |
| TTLS-PAP passwords | ❌ | ✅ |
| Auto-log to file | ❌ | ✅ `/var/log/hostapd-wpe.log` |

**How it works:**
- On startup, EAPx checks for `hostapd-wpe` in `$PATH`
- If found → uses it automatically (full credential capture)
- If not found → falls back to vanilla `hostapd` with stdout parsing (limited but functional)
- A warning is printed when falling back to vanilla mode

**To install hostapd-wpe:**
```bash
# Option 1: apt (if available in your repos)
sudo apt install hostapd-wpe

# Option 2: Compile from source
git clone https://github.com/s0lst1c3/hostapd-eaphammer
cd hostapd-eaphammer
./build.sh
```

---

## Dual-Interface Architecture

EAPx uses **two separate wireless interfaces** for its full attack pipeline.

| Interface | Flag | Role | Example |
|-----------|------|------|---------|
| **AP Interface** | `-a` / `--iface-ap` | Runs the rogue AP (hostapd) + identity harvesting | `wlan1` |
| **Monitor Interface** | `-m` / `--iface-mon` | Deauth, scanning, EAP probing, PCAP capture | `wlan0mon` |

```
  ┌──────────────────────────────────────────────────┐
  │              YOUR ATTACK MACHINE                 │
  │                                                  │
  │   ┌──────────────────┐  ┌──────────────────────┐ │
  │   │   Adapter #1     │  │    Adapter #2        │ │
  │   │   wlan1 (-a)     │  │    wlan0mon (-m)     │ │
  │   │                  │  │                      │ │
  │   │  ► Rogue AP      │  │  ► Cert clone probe  │ │
  │   │  ► hostapd-wpe   │  │  ► Deauth / Ch-hop   │ │
  │   │  ► Creds capture │  │  ► Scan              │ │
  │   │  ► Identity      │  │  ► EAP Probe         │ │
  │   │    Harvest       │  │  ► PCAP capture      │ │
  │   └──────────────────┘  └──────────────────────┘ │
  └──────────────────────────────────────────────────┘
```

> **Note:** Identity harvesting runs on the **AP interface** (where clients connect), not the monitor interface. It launches as a background daemon thread alongside the rogue AP.

> **Note:** Single-purpose subcommands (`scan`, `deauth`, `channel-hop`, `harvest`, `karma`, `portal`) only need **one** interface via `-i`.

> **Runtime Validation:** EAPx validates that the two interfaces are **physically distinct** and **exist on the system** before starting.

---

## Installation

### Requirements

- **OS:** Kali Linux (recommended) or any Debian-based distro
- **Hardware:** **Two** wireless adapters with **monitor mode** and **packet injection**
- **Python:** 3.10+
- **Privileges:** Root access
- **Recommended:** `hostapd-wpe` for full credential capture (auto-detected, optional)

### Quick Install

```bash
git clone https://github.com/babySAMRAT/eapx.git
cd eapx
sudo bash install.sh
```

The installer will automatically attempt to install `hostapd-wpe`. If unavailable in your repos, it falls back to vanilla `hostapd` with a note on compiling from source.

### Manual Install

```bash
sudo apt install -y hostapd aircrack-ng openssl iw net-tools \
  dnsmasq macchanger hashcat tmux python3 python3-pip \
  python3-scapy python3-flask python3-netaddr python3-colorama wordlists

# Optional but STRONGLY recommended:
sudo apt install -y hostapd-wpe

sudo python3 eapx.py setup
```

---

## Quick Start

### 1. Prepare Your Adapters

```bash
# Put one adapter in monitor mode for scanning/deauth
sudo airmon-ng start wlan0
# → wlan0mon

# The second adapter (wlan1) will be used as the rogue AP
# It does NOT need monitor mode — hostapd manages it
```

### 2. Run via Menu

```bash
sudo python3 eapx.py menu
```

### 3. Or Use CLI

```bash
# Full auto attack — cert clone + probe + deauth + evil twin + crack
sudo python3 eapx.py attack -a wlan1 -m wlan0mon

# GTC downgrade (captures plaintext passwords)
sudo python3 eapx.py attack -a wlan1 -m wlan0mon \
  --essid "CorpWiFi" --negotiate gtc-downgrade

# Skip cert cloning
sudo python3 eapx.py attack -a wlan1 -m wlan0mon --no-cert-clone
```

---

## CLI Reference

### `menu` — Interactive Guided Mode

```bash
sudo python3 eapx.py menu
```

11-option menu covering all attack modes. Prompts for dual interfaces where needed.

---

### `setup` — Generate Certs & Check Dependencies

```bash
sudo python3 eapx.py setup
```

Generates CA + server certificates **and DH parameters** (2048-bit). The DH params prevent TLS handshake failures with certain client supplicants.

---

### `scan` — Discover Enterprise Networks

```bash
sudo python3 eapx.py scan -i <interface> [-t <seconds>]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i` | Monitor-mode interface | *required* |
| `-t` | Scan duration | `15` |

---

### `attack` — Full Attack Pipeline

```bash
sudo python3 eapx.py attack -a <ap_iface> -m <mon_iface> [options]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-a`, `--iface-ap` | AP interface | *required* |
| `-m`, `--iface-mon` | Monitor interface | *required* |
| `--essid` | Target SSID (skip scan if set) | *auto-scan* |
| `--bssid` | Target BSSID | `None` |
| `--channel` | Channel | `6` |
| `--negotiate` | `balanced` / `gtc-downgrade` / `default` | `balanced` |
| `--no-cert-clone` | Skip RADIUS cert cloning | enabled |
| `--no-deauth` | Skip deauth | enabled |
| `--no-probe` | Skip EAP fingerprinting | enabled |
| `--no-harvest` | Skip identity harvesting | enabled |
| `--no-autocrack` | Skip auto-crack | enabled |
| `--no-report` | Skip report | enabled |
| `--wordlist` | Custom wordlist for cracking | `rockyou.txt` |

**Attack pipeline order:**
1. Scan & select target (via monitor interface)
2. Clone RADIUS certificate (via monitor interface)
3. Start PCAP capture (via monitor interface)
4. Probe EAP methods (via monitor interface)
5. **Start identity harvester as background daemon** (via AP interface)
6. Start auto-crack watcher
7. Deauth clients (via monitor interface)
8. **Launch evil twin AP** — hostapd-wpe parses credentials in real-time (via AP interface)
9. Stop capture & generate report

> **Key:** Steps 5 and 8 run **concurrently** — the harvester is a daemon thread that captures identities while the AP serves clients. Credentials from hostapd/hostapd-wpe stdout are also parsed in real-time during step 8.

---

### `deauth` — Deauthentication Attack

```bash
sudo python3 eapx.py deauth -i <interface> --bssid <AP_MAC> [--client <MAC>] [--continuous]
```

---

### `channel-hop` — Channel-Hopping Deauth

```bash
sudo python3 eapx.py channel-hop -i <interface> --bssid <AP_MAC> [options]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i` | Monitor-mode interface | *required* |
| `--bssid` | Target BSSID | *required* |
| `--client` | Target client MAC | broadcast |
| `--channels` | Comma-separated channels | `1,6,11` |
| `--auto-detect` | Auto-detect target's channels | off |
| `--dwell` | Seconds per channel | `2.0` |
| `--burst` | Deauth frames per channel | `10` |
| `--rounds` | Number of rounds (0=infinite) | `0` |

**Example — Channel-hop deauth with auto-detection:**
```bash
sudo python3 eapx.py channel-hop -i wlan0mon \
  --bssid AA:BB:CC:DD:EE:FF --auto-detect --burst 20
```

---

### `harvest` — Passive Identity Harvesting

```bash
sudo python3 eapx.py harvest -i <interface> [-t <seconds>]
```

Includes OUI vendor lookup, anonymous identity detection, and domain hint extraction. During `attack` mode, harvesting runs as a background daemon on the AP interface.

---

### `karma` — KARMA Attack

```bash
sudo python3 eapx.py karma -i <interface> [--no-filter]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i` | Wireless interface | *required* |
| `--no-filter` | Respond to ALL SSIDs (disable enterprise filter) | filter ON |

**Enterprise filter keywords:** corp, office, enterprise, eduroam, secure, .com, .local, etc.
**Blocked patterns:** AndroidAP, iPhone, DIRECT-, HOME-, NETGEAR, etc.

---

### `portal` — Hostile Captive Portal

```bash
sudo python3 eapx.py portal -i <interface> --essid <SSID> [--channel <ch>]
```

---

### `crack` — Multi-Stage Hash Cracking

```bash
sudo python3 eapx.py crack -f <hash_file> [-m <mode>] [-w <wordlist>]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-f` | Hash file path | *required* |
| `-m` | `5500` (NTLMv1) or `5600` (NTLMv2) | `5500` |
| `-w` | Custom wordlist path (added as Stage 0) | `rockyou.txt` |

**Crack stages:**
1. ASLEAP (MS-CHAPv2 challenge-response, if `asleap` installed)
2. Stage 0 — Custom wordlist (if provided)
3. Stage 1 — `rockyou.txt` + `best64.rule`
4. Stage 2 — `rockyou.txt` + `d3adhob0.rule`
5. Stage 3 — `rockyou.txt` direct

---

### `report` — Generate Pentest Report

```bash
sudo python3 eapx.py report [--essid <SSID>] [--bssid <BSSID>]
```

Generates both **Markdown** and **JSON** reports. Includes:
- Risk rating (CRITICAL/HIGH/MEDIUM/LOW)
- EAP methods detected
- Certificate fingerprint (deployed + cloned original)
- Client device fingerprinting (OUI vendor distribution)
- All captured identities, hashes, cracked passwords, and portal credentials

---

## Attack Workflow

```
                    ┌─────────────────────────────────────────┐
                    │          ADAPTER ASSIGNMENT              │
                    │                                         │
                    │  wlan0mon (-m) ──► Scan, Cert Clone,    │
                    │                    Probe, Deauth, PCAP  │
                    │  wlan1    (-a) ──► Rogue AP, Creds,     │
                    │                    Identity Harvest     │
                    └─────────────────────────────────────────┘

┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  1. Setup    │ ──▶│  2. Scan     │ ──▶│  3. Clone    │
│ (certs/deps) │    │ (find MGT   │    │ (RADIUS cert │
│ (+DH params) │    │  networks)  │    │  metadata)   │
│              │    │  [wlan0mon] │    │  [wlan0mon]  │
└──────────────┘    └──────────────┘    └──────┬───────┘
                                               │
┌──────────────┐    ┌──────────────┐           ▼
│  6. Evil     │    │  5. Deauth   │    ┌──────────────┐
│  Twin AP     │ ◀──│ (or ch-hop) │ ◀──│  4. Probe    │
│ (hostapd-wpe │    │ (force      │    │ (EAP methods │
│  + parsing)  │    │  reconnect) │    │  + PEAPv0/1) │
│  [wlan1]     │    │  [wlan0mon] │    │  [wlan0mon]  │
└──────┬───────┘    └──────────────┘    └──────────────┘
       │
       ├────────────┬──────────────┐
       ▼            ▼              ▼
┌───────────┐ ┌──────────┐  ┌──────────┐
│ Harvest   │ │ Capture  │  │ Portal   │
│ Identities│ │ Hashes   │  │ Phish    │
│ (daemon)  │ │ (real-   │  │          │
│ [wlan1]   │ │  time)   │  │          │
│ +OUI+Anon │ │ +PCAP    │  │          │
└───────────┘ └────┬─────┘  └──────────┘
                   ▼
            ┌──────────┐     ┌──────────────┐
            │ AutoCrack│ ──▶ │ Report       │
            │ 3-stage  │     │ MD + JSON    │
            │ +ASLEAP  │     │ +OUI +Cert   │
            └──────────┘     └──────────────┘
```

---

## Project Structure

```
eapx/
├── eapx.py                # Main entry point (CLI + interactive menu)
├── install.sh              # One-command installer (includes hostapd-wpe)
├── uninstall.sh            # Clean uninstaller
├── requirement.txt         # Python dependencies
├── README.md
├── .gitignore
├── modules/
│   ├── scanner.py          # WPA2-Enterprise network discovery
│   ├── cert_clone.py       # RADIUS certificate cloning
│   ├── cert_wizard.py      # Certificate generation (+ DH params)
│   ├── rogue_ap.py         # Evil twin AP (hostapd-wpe + real-time parsing)
│   ├── eap_probe.py        # EAP fingerprinting (TLS detect, PEAPv0/v1)
│   ├── deauth.py           # 802.11 deauthentication
│   ├── channel_hop.py      # Channel-hopping deauth
│   ├── identity.py         # Identity harvesting (OUI, anonymous detect)
│   ├── karma.py            # KARMA attack (enterprise filter)
│   ├── hostile_portal.py   # Captive portal credential phishing
│   ├── autocrack.py        # Multi-stage hash cracking + ASLEAP
│   └── pcap_capture.py     # Packet capture wrapper
├── report/
│   └── reporter.py         # Report generator (MD + JSON)
├── certs/                  # Generated certificates + DH params (git-ignored)
└── loot/                   # Captured credentials (git-ignored)
```

---

## Output & Loot

All captured data is saved to `loot/`:

| File | Contents |
|------|----------|
| `identities.txt` | Harvested EAP usernames with MACs, vendors, and timestamps |
| `identities_summary.json` | Structured identity data with OUI and domain hints |
| `hashes.txt` | Captured MSCHAPv2 challenge-response hashes (hashcat 5500 format) |
| `cracked_passwords.txt` | Successfully cracked passwords (GTC plaintext, PAP, cracked hashes) |
| `ad_creds.txt` | Portal-captured domain credentials |
| `eap_methods.txt` | Detected EAP methods, PEAP version, TLS-only flag |
| `radius_cert_metadata.json` | Cloned RADIUS cert metadata |
| `capture_*.pcap` | Full packet captures from attacks |

Reports are saved to `report/`:
- `pentest_<ESSID>_<timestamp>.md` — Markdown report
- `pentest_<ESSID>_<timestamp>.json` — JSON export (for Dradis, Plextrac)

---

## Author

**Aryan Shetty** — [@babySAMRAT](https://github.com/babySAMRAT)

---

## License

This project is for **educational and authorized testing purposes only**.
