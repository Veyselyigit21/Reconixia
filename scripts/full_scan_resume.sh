#!/usr/bin/env bash
set -euo pipefail

TARGET=""
PROFILE="balanced"
SCOPE=""
NO_NUCLEI=""
NO_GAU=""
NO_HEADERS=""
RESET="false"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/full_scan_resume.sh -t hedef.com [options]

Options:
  -t, --target       Target domain, required
  -p, --profile      stealth|balanced|fast, default balanced
  -s, --scope        Scope file path
      --no-nuclei    Skip nuclei
      --no-gau       Skip GAU/Wayback passive URLs
      --no-headers   Skip CORS/security header analysis
      --reset        Remove existing checkpoint and start over
  -h, --help         Show help

Checkpoint:
  results/<target>/checkpoint_full_scan.json
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib/preflight.sh"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="${2:-}"; shift 2 ;;
    -p|--profile) PROFILE="${2:-balanced}"; shift 2 ;;
    -s|--scope) SCOPE="${2:-}"; shift 2 ;;
    --no-nuclei) NO_NUCLEI="-no-nuclei"; shift ;;
    --no-gau) NO_GAU="-no-gau"; shift ;;
    --no-headers) NO_HEADERS="-no-headers"; shift ;;
    --reset) RESET="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

TARGET="$(rx_validate_target "$TARGET")"
rx_validate_profile "$PROFILE"
rx_validate_scope_optional "$SCOPE"

cd "$ROOT_DIR"
WORKSPACE="results/$TARGET"
CHECKPOINT="$WORKSPACE/checkpoint_full_scan.json"
mkdir -p "$WORKSPACE"

if [[ "$RESET" == "true" ]]; then
  rm -f "$CHECKPOINT"
fi

mark_done() {
  local step="$1"
  python3 - "$CHECKPOINT" "$TARGET" "$step" <<'PY'
import json, pathlib, sys, datetime
path = pathlib.Path(sys.argv[1])
target = sys.argv[2]
step = sys.argv[3]
if path.exists():
    try:
        data = json.loads(path.read_text())
    except Exception:
        data = {}
else:
    data = {}
data.setdefault("target", target)
data.setdefault("completed_steps", {})[step] = True
data["last_step"] = step
data["updated_at"] = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
path.write_text(json.dumps(data, indent=2) + "\n")
PY
}

is_done() {
  local step="$1"
  python3 - "$CHECKPOINT" "$step" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
step = sys.argv[2]
if not path.exists():
    sys.exit(1)
try:
    data = json.loads(path.read_text())
except Exception:
    sys.exit(1)
sys.exit(0 if data.get("completed_steps", {}).get(step) is True else 1)
PY
}

if [[ ! -x ./reconixia || ! -x ./reconixia-augment || ! -x ./reconixia-report ]]; then
  echo "[i] Binaries not found, building first..."
  rx_require_file "scripts/build_all.sh" "build script"
  chmod +x scripts/build_all.sh
  ./scripts/build_all.sh
fi

rx_require_executable ./reconixia
rx_require_executable ./reconixia-augment
rx_require_executable ./reconixia-report
rx_require_cmd python3

CMD=(./reconixia run -target "$TARGET" -profile "$PROFILE")
if [[ -n "$SCOPE" ]]; then CMD+=(-scope "$SCOPE"); fi
if [[ -n "$NO_NUCLEI" ]]; then CMD+=($NO_NUCLEI); fi
if [[ -n "$NO_GAU" ]]; then CMD+=($NO_GAU); fi
if [[ -n "$NO_HEADERS" ]]; then CMD+=($NO_HEADERS); fi

if is_done recon; then
  echo "[1/3] Recon already completed, skipping."
else
  echo "[1/3] Running recon..."
  "${CMD[@]}"
  mark_done recon
fi

if is_done augment; then
  echo "[2/3] Augment already completed, skipping."
else
  echo "[2/3] Running augment checks..."
  ./reconixia-augment -target "$TARGET"
  mark_done augment
fi

if is_done report; then
  echo "[3/3] HTML report already completed, skipping."
else
  echo "[3/3] Rendering HTML report..."
  ./reconixia-report -target "$TARGET"
  mark_done report
fi

echo "[+] Resumable full scan completed."
echo "    $CHECKPOINT"
echo "    results/$TARGET/report.md"
echo "    results/$TARGET/report.json"
echo "    results/$TARGET/report.html"
