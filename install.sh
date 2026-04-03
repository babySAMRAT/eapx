#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}"
echo "███████╗ █████╗ ██████╗ ██╗  ██╗"
echo "██╔════╝██╔══██╗██╔══██╗╚██╗██╔╝"
echo "█████╗  ███████║██████╔╝ ╚███╔╝ "
echo "██╔══╝  ██╔══██║██╔═══╝  ██╔██╗ "
echo "███████╗██║  ██║██║     ██╔╝ ██╗"
echo "╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝"
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Run as root: sudo bash install.sh${NC}"
  exit 1
fi

echo -e "${YELLOW}[*] Fixing DNS...${NC}"
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf

echo -e "${YELLOW}[*] Updating packages...${NC}"
apt update -qq

echo -e "${YELLOW}[*] Installing dependencies...${NC}"
apt install -y \
  hostapd aircrack-ng openssl iw net-tools \
  dnsmasq macchanger hashcat tmux \
  python3 python3-pip \
  python3-scapy python3-flask \
  python3-netaddr python3-colorama \
  wordlists

echo -e "${YELLOW}[*] Attempting to install hostapd-wpe (enhanced credential capture)...${NC}"
if apt install -y hostapd-wpe 2>/dev/null; then
  echo -e "${GREEN}[+] hostapd-wpe installed — full credential capture enabled${NC}"
else
  echo -e "${YELLOW}[!] hostapd-wpe not available in repos — using vanilla hostapd${NC}"
  echo -e "${YELLOW}[!] For full credential capture, compile from:${NC}"
  echo -e "${YELLOW}    https://github.com/s0lst1c3/hostapd-eaphammer${NC}"
fi

echo -e "${YELLOW}[*] Decompressing rockyou.txt...${NC}"
[ -f /usr/share/wordlists/rockyou.txt.gz ] && \
  gunzip /usr/share/wordlists/rockyou.txt.gz

echo -e "${YELLOW}[*] Creating directories...${NC}"
mkdir -p certs loot report

echo -e "${YELLOW}[*] Making eapx.py executable...${NC}"
chmod +x eapx.py

echo -e "${YELLOW}[*] Generating certificates...${NC}"
python3 eapx.py setup

echo ""
echo -e "${GREEN}[+] Installation complete!${NC}"
echo -e "${GREEN}[+] Usage: sudo python3 eapx.py menu${NC}"
