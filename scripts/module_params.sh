#!/usr/bin/env bash
set -euo pipefail

TARGET=""
INPUT=""
OUTDIR=""
LIMIT="500"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="$2"; shift 2 ;;
    -i|--input) INPUT="$2"; shift 2 ;;
    -o|--outdir) OUTDIR="$2"; shift 2 ;;
    --limit) LIMIT="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 2 ;;
  esac
done

if [[ -z "$TARGET" ]]; then echo "TARGET required: -t example.com"; exit 1; fi
if [[ -z "$OUTDIR" ]]; then OUTDIR="results/$TARGET"; fi
if [[ -z "$INPUT" ]]; then INPUT="$OUTDIR/processed/passive_urls.txt"; fi
if [[ ! -f "$INPUT" ]]; then echo "Input not found: $INPUT"; exit 1; fi

mkdir -p "$OUTDIR/processed" "$OUTDIR/logs"
CANDIDATES="$OUTDIR/processed/param_candidates.txt"
OUT="$OUTDIR/processed/discovered_params.txt"

# Passive and low-noise mode: extract parameter names already visible in URLs.
# This does not fuzz targets by itself.
grep -E '\?' "$INPUT" \
  | head -n "$LIMIT" \
  | sed -E 's/^[^?]*\?//' \
  | tr '&' '\n' \
  | sed -E 's/=.*$//' \
  | sed '/^$/d' \
  | sort -u > "$OUT"

cp "$OUT" "$CANDIDATES"

echo "[+] Passive parameter candidates written: $OUT"
