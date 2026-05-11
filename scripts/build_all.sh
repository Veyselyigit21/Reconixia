#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[+] Building Reconixia active tools..."

go build -o reconixia ./cmd/reconixia-v06
go build -o reconixia-report ./cmd/reconixia-report
go build -o reconixia-augment ./cmd/reconixia-augment
go build -o reconixia-diff ./cmd/reconixia-diff
go build -o reconixia-ai-structured ./cmd/reconixia-ai-structured

echo "[+] Build completed:"
echo "    ./reconixia"
echo "    ./reconixia-report"
echo "    ./reconixia-augment"
echo "    ./reconixia-diff"
echo "    ./reconixia-ai-structured"
