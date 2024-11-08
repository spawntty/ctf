#!/bin/bash

echo "Nmap Scan Script"

# Check if argument is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <IP>"
  exit 1
fi

IP=$1

# Run nmap TCP Connect scan to find open ports
echo "[+] Starting nmap Connect scan..."
nmap_output=$(sudo nmap -sT -p- "$IP")
echo "[+] nmap Connect scan finished..."

# Extract open ports from nmap output
open_ports=$(echo "$nmap_output" | grep '/tcp' | awk '{print $1}' | cut -d'/' -f1 | paste -sd, -)

if [ -z "$open_ports" ]; then
  echo "No open ports found."
  exit 1
else
  echo "Open ports found: $open_ports"
fi

# Run nmap Services scan
echo "[+] Starting nmap Services scan..."
sudo nmap -sV -A -p"$open_ports" "$IP"
