#!/usr/bin/env bash
set -euo pipefail

TARGET=""
LABEL=""

usage() {
  cat <<'EOF'
Usage:
  ./scripts/snapshot.sh -t hedef.com [-l label]

Creates a timestamped copy of results/<target>/ under snapshots/.
Useful for later diffing report.json files with reconixia-diff.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="${2:-}"; shift 2 ;;
    -l|--label) LABEL="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "error: target required" >&2
  usage
  exit 1
fi

SAFE_TARGET="${TARGET#http://}"
SAFE_TARGET="${SAFE_TARGET#https://}"
SAFE_TARGET="${SAFE_TARGET%%/*}"
SAFE_TARGET="${SAFE_TARGET%%:*}"

SRC="results/$SAFE_TARGET"
if [[ ! -d "$SRC" ]]; then
  echo "error: result directory not found: $SRC" >&2
  exit 1
fi

TS="$(date +%Y%m%d-%H%M%S)"
if [[ -n "$LABEL" ]]; then
  DEST="snapshots/$SAFE_TARGET-$TS-$LABEL"
else
  DEST="snapshots/$SAFE_TARGET-$TS"
fi

mkdir -p "$(dirname "$DEST")"
cp -a "$SRC" "$DEST"

echo "Snapshot created: $DEST"
echo "Diff example:"
echo "  ./reconixia-diff -old snapshots/<old>/report.json -new $DEST/report.json"
