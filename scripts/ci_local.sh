#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[1/5] Go version"
go version

echo "[2/5] Formatting drift report"
GOFMT_FILES="$(gofmt -l . || true)"
if [[ -n "$GOFMT_FILES" ]]; then
  echo "$GOFMT_FILES"
else
  echo "gofmt: OK"
fi

echo "[3/5] Unit tests"
go test ./...

echo "[4/5] Build active tools"
bash scripts/build_all.sh

echo "[5/5] Smoke check binaries"
for bin in reconixia reconixia-report reconixia-augment reconixia-diff reconixia-ai-structured; do
  if [[ ! -x "./$bin" ]]; then
    echo "error: missing built binary: $bin" >&2
    exit 1
  fi
  echo "OK: $bin"
done

echo "Local CI passed."
