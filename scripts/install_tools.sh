#!/usr/bin/env bash
set -euo pipefail

if ! command -v go >/dev/null 2>&1; then
  echo "Go is required. Install Go first."
  exit 1
fi

echo "[+] Installing core ProjectDiscovery tools..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "[+] Installing optional bug bounty recon tools..."
go install github.com/lc/gau/v2/cmd/gau@latest || true
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || true
go install github.com/haccer/subjack@latest || true

# Passive subdomain source + active crawler + hidden-param discovery.
echo "[+] Installing extra recon sources (assetfinder, katana, dalfox, arjun)..."
go install github.com/tomnomnom/assetfinder@latest || true
go install github.com/projectdiscovery/katana/cmd/katana@latest || true
go install github.com/hahwul/dalfox/v2@latest || true
if command -v pip3 >/dev/null 2>&1; then
  pip3 install --break-system-packages arjun || pip3 install arjun || true
elif command -v pip >/dev/null 2>&1; then
  pip install arjun || true
else
  echo "[i] pip bulunamadı; arjun atlandı (gizli parametre keşfi için 'pip install arjun')."
fi

# gowitness has changed install paths across versions. Keep this best-effort and do not fail setup.
echo "[+] Installing optional screenshot tooling..."
go install github.com/sensepost/gowitness@latest || true

echo "[+] Done. Add Go bin to PATH if needed:"
echo 'export PATH=$PATH:$HOME/go/bin'

echo "[i] Optional tools may require extra system packages, browser dependencies, or permissions."
echo "[i] Reconixia works without optional tools; modules such as ports/screenshots simply skip when tools are absent."
