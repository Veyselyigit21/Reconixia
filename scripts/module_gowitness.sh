#!/usr/bin/env bash
set -euo pipefail

TARGET=""
INPUT=""
OUTDIR=""
TIMEOUT="10"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="$2"; shift 2 ;;
    -i|--input) INPUT="$2"; shift 2 ;;
    -o|--outdir) OUTDIR="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 2 ;;
  esac
done

if [[ -z "$TARGET" ]]; then echo "TARGET required: -t example.com"; exit 1; fi
if [[ -z "$OUTDIR" ]]; then OUTDIR="results/$TARGET"; fi
if [[ -z "$INPUT" ]]; then INPUT="$OUTDIR/processed/live_hosts.txt"; fi
if [[ ! -f "$INPUT" ]]; then echo "Input not found: $INPUT"; exit 1; fi
if ! command -v gowitness >/dev/null 2>&1; then echo "gowitness not found; install it first"; exit 127; fi

mkdir -p "$OUTDIR/screenshots" "$OUTDIR/logs"

echo "[+] Running gowitness screenshots"
echo "    input: $INPUT"
echo "    output dir: $OUTDIR/screenshots"

gowitness file -f "$INPUT" --screenshot-path "$OUTDIR/screenshots" --timeout "$TIMEOUT" 2> "$OUTDIR/logs/gowitness.err" || true

echo "[+] Done: $OUTDIR/screenshots"
