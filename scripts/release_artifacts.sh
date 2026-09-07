#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-0.9.0-rc1}"
OUT_DIR="${OUT_DIR:-dist/$VERSION}"
GOOS_LIST="${GOOS_LIST:-linux windows darwin}"
GOARCH_LIST="${GOARCH_LIST:-amd64 arm64}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

resolve_go() {
  if [[ -n "${GO_BIN:-}" ]]; then
    echo "$GO_BIN"
    return
  fi
  if command -v go >/dev/null 2>&1; then
    command -v go
    return
  fi
  if command -v go.exe >/dev/null 2>&1; then
    command -v go.exe
    return
  fi
  echo "error: required command not found: go" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

GO_BIN="$(resolve_go)"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

echo "[release] Building Reconixia $VERSION into $OUT_DIR"
for goos in $GOOS_LIST; do
  for goarch in $GOARCH_LIST; do
    suffix="${goos}_${goarch}"
    exe=""
    if [[ "$goos" == "windows" ]]; then exe=".exe"; fi
    export GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0
    "$GO_BIN" build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT_DIR/reconixia_${suffix}${exe}" ./cmd/reconixia-v06
    "$GO_BIN" build -trimpath -ldflags "-s -w" -o "$OUT_DIR/reconixia-report_${suffix}${exe}" ./cmd/reconixia-report
    "$GO_BIN" build -trimpath -ldflags "-s -w" -o "$OUT_DIR/reconixia-augment_${suffix}${exe}" ./cmd/reconixia-augment
    "$GO_BIN" build -trimpath -ldflags "-s -w" -o "$OUT_DIR/reconixia-diff_${suffix}${exe}" ./cmd/reconixia-diff
    "$GO_BIN" build -trimpath -ldflags "-s -w" -o "$OUT_DIR/reconixia-ai-structured_${suffix}${exe}" ./cmd/reconixia-ai-structured
    "$GO_BIN" build -trimpath -ldflags "-s -w" -o "$OUT_DIR/reconixia-idor_${suffix}${exe}" ./cmd/reconixia-idor
  done
done

(
  cd "$OUT_DIR"
  : > SHA256SUMS
  for f in *; do
    [[ -f "$f" && "$f" != "SHA256SUMS" ]] || continue
    sha256_file "$f" >> SHA256SUMS
  done
)

if command -v gpg >/dev/null 2>&1; then
  if gpg --batch --yes --armor --detach-sign "$OUT_DIR/SHA256SUMS"; then
    echo "[release] GPG signature: $OUT_DIR/SHA256SUMS.asc"
  else
    echo "[release] gpg found but signing failed; SHA256SUMS created without detached signature" >&2
  fi
else
  echo "[release] gpg not found; SHA256SUMS created without detached signature" >&2
fi

echo "[release] Done:"
echo "  $OUT_DIR"
echo "  $OUT_DIR/SHA256SUMS"
