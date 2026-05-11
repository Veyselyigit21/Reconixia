#!/usr/bin/env bash
set -euo pipefail

TARGET=""
INPUT=""
OUTDIR=""
LIMIT="200"

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
if [[ -z "$INPUT" ]]; then INPUT="$OUTDIR/processed/interesting_paths.txt"; fi
if [[ ! -f "$INPUT" ]]; then echo "Input not found: $INPUT"; exit 1; fi

mkdir -p "$OUTDIR/processed" "$OUTDIR/logs"
CANDIDATES="$OUTDIR/processed/403_candidates.txt"

# Safe candidate extraction only. This does not perform bypass attempts.
# It extracts URLs that Reconixia already observed as 401/403 for manual review.
awk -F '|' '{gsub(/^ +| +$/, "", $1); gsub(/^ +| +$/, "", $2); if ($2 == "401" || $2 == "403") print $1}' "$INPUT" \
  | head -n "$LIMIT" \
  | sort -u > "$CANDIDATES"

echo "[+] 401/403 manual review candidates written: $CANDIDATES"
