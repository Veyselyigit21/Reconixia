#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
VERSION="${VERSION:-0.9.0-rc1}"

echo "[+] Building Reconixia active tools..."

go build -ldflags "-X main.version=$VERSION" -o reconixia ./cmd/reconixia-v06
go build -o reconixia-report ./cmd/reconixia-report
go build -o reconixia-augment ./cmd/reconixia-augment
go build -o reconixia-diff ./cmd/reconixia-diff
go build -o reconixia-ai-structured ./cmd/reconixia-ai-structured
go build -o reconixia-idor ./cmd/reconixia-idor

echo "[+] Build completed:"
echo "    ./reconixia"
echo "    ./reconixia-report"
echo "    ./reconixia-augment"
echo "    ./reconixia-diff"
echo "    ./reconixia-ai-structured"
echo "    ./reconixia-idor"
