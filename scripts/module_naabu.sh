#!/usr/bin/env bash
set -euo pipefail

TARGET=""
INPUT=""
OUTDIR=""
RATE="50"
TOP_PORTS="1000"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="$2"; shift 2 ;;
    -i|--input) INPUT="$2"; shift 2 ;;
    -o|--outdir) OUTDIR="$2"; shift 2 ;;
    --rate) RATE="$2"; shift 2 ;;
    --top-ports) TOP_PORTS="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 2 ;;
  esac
done

if [[ -z "$TARGET" ]]; then echo "TARGET required: -t example.com"; exit 1; fi
if [[ -z "$OUTDIR" ]]; then OUTDIR="results/$TARGET"; fi
if [[ -z "$INPUT" ]]; then INPUT="$OUTDIR/processed/live_hosts.txt"; fi
if [[ ! -f "$INPUT" ]]; then echo "Input not found: $INPUT"; exit 1; fi
if ! command -v naabu >/dev/null 2>&1; then echo "naabu not found; install it first"; exit 127; fi

mkdir -p "$OUTDIR/processed" "$OUTDIR/logs"
HOSTS="$OUTDIR/processed/naabu_hosts.txt"
OUT="$OUTDIR/processed/naabu_ports.txt"

sed -E 's#^https?://##; s#/.*$##; s#:.*$##' "$INPUT" | sed '/^$/d' | sort -u > "$HOSTS"

if [[ ! -s "$HOSTS" ]]; then echo "No hosts to scan"; exit 0; fi

echo "[+] Running naabu safely"
echo "    hosts: $HOSTS"
echo "    output: $OUT"

naabu -list "$HOSTS" -top-ports "$TOP_PORTS" -rate "$RATE" -silent -o "$OUT" 2> "$OUTDIR/logs/naabu.err" || true

echo "[+] Done: $OUT"
