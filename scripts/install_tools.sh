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

# gowitness has changed install paths across versions. Keep this best-effort and do not fail setup.
echo "[+] Installing optional screenshot tooling..."
go install github.com/sensepost/gowitness@latest || true

echo "[+] Done. Add Go bin to PATH if needed:"
echo 'export PATH=$PATH:$HOME/go/bin'

echo "[i] Optional tools may require extra system packages, browser dependencies, or permissions."
echo "[i] Reconixia works without optional tools; modules such as ports/screenshots simply skip when tools are absent."
