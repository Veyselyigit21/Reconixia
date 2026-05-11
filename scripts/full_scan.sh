#!/usr/bin/env bash
set -euo pipefail

TARGET=""
PROFILE="balanced"
SCOPE=""
NO_NUCLEI=""
NO_GAU=""
NO_HEADERS=""

usage() {
  cat <<'EOF'
Usage:
  ./scripts/full_scan.sh -t hedef.com [options]

Options:
  -t, --target       Target domain, required
  -p, --profile      stealth|balanced|fast, default balanced
  -s, --scope        Scope file path
      --no-nuclei    Skip nuclei
      --no-gau       Skip GAU/Wayback passive URLs
      --no-headers   Skip CORS/security header analysis
  -h, --help         Show help
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
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

TARGET="$(rx_validate_target "$TARGET")"
rx_validate_profile "$PROFILE"
rx_validate_scope_optional "$SCOPE"

cd "$ROOT_DIR"

if [[ ! -x ./reconixia || ! -x ./reconixia-augment || ! -x ./reconixia-report ]]; then
  echo "[i] Binaries not found, building first..."
  rx_require_file "scripts/build_all.sh" "build script"
  chmod +x scripts/build_all.sh
  ./scripts/build_all.sh
fi

rx_require_executable ./reconixia
rx_require_executable ./reconixia-augment
rx_require_executable ./reconixia-report

CMD=(./reconixia run -target "$TARGET" -profile "$PROFILE")
if [[ -n "$SCOPE" ]]; then
  CMD+=(-scope "$SCOPE")
fi
if [[ -n "$NO_NUCLEI" ]]; then CMD+=($NO_NUCLEI); fi
if [[ -n "$NO_GAU" ]]; then CMD+=($NO_GAU); fi
if [[ -n "$NO_HEADERS" ]]; then CMD+=($NO_HEADERS); fi

echo "[1/3] Running recon..."
"${CMD[@]}"

echo "[2/3] Running augment checks..."
./reconixia-augment -target "$TARGET"

echo "[3/3] Rendering HTML report..."
./reconixia-report -target "$TARGET"

echo "[+] Full scan completed."
echo "    results/$TARGET/report.md"
echo "    results/$TARGET/report.json"
echo "    results/$TARGET/report.html"
