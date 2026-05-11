#!/usr/bin/env bash
set -euo pipefail

TARGET=""
PROFILE="balanced"
SCOPE=""
SSH_KEY_NAME=""
IDENTITY=""
LOCATION="fsn1"
SERVER_TYPE="cx22"
IMAGE="ubuntu-24.04"
NO_NUCLEI="--no-nuclei"
SERVER_ID=""
SERVER_IP=""

usage() {
  cat <<'EOF'
Usage:
  HETZNER_TOKEN=... ./scripts/cloud_hetzner_worker.sh -t hedef.com --ssh-key KEY_NAME [options]

Options:
  -t, --target       Target domain, required
  --ssh-key          Hetzner SSH key name or ID, required
  -i, --identity     Local SSH private key path
  -p, --profile      stealth|balanced|fast, default balanced
  -s, --scope        Scope file path
  --location         Hetzner location, default fsn1
  --type             Server type, default cx22
  --image            Image, default ubuntu-24.04
  --with-nuclei      Enable nuclei scan. Default is --no-nuclei for safer first runs.
  -h, --help         Show help

Lifecycle:
  create server -> wait for public IP -> run remote_existing.sh -> destroy server

Safety:
  - The script attempts to destroy the server on EXIT/ERR/INT/TERM.
  - .env and private keys are never uploaded by remote_existing.sh.
EOF
}

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

api() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  if [[ -n "$data" ]]; then
    curl -fsS -X "$method" "https://api.hetzner.cloud/v1$path" \
      -H "Authorization: Bearer $HETZNER_TOKEN" \
      -H "Content-Type: application/json" \
      --data "$data"
  else
    curl -fsS -X "$method" "https://api.hetzner.cloud/v1$path" \
      -H "Authorization: Bearer $HETZNER_TOKEN" \
      -H "Content-Type: application/json"
  fi
}

cleanup() {
  if [[ -n "$SERVER_ID" ]]; then
    echo "[cleanup] Destroying Hetzner server: $SERVER_ID"
    api DELETE "/servers/$SERVER_ID" >/dev/null 2>&1 || true
    SERVER_ID=""
  fi
}

on_signal() {
  echo "[signal] Interrupted; cleanup will run before exit" >&2
  cleanup
  exit 130
}

trap cleanup EXIT
trap on_signal INT TERM

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="${2:-}"; shift 2 ;;
    --ssh-key) SSH_KEY_NAME="${2:-}"; shift 2 ;;
    -i|--identity) IDENTITY="${2:-}"; shift 2 ;;
    -p|--profile) PROFILE="${2:-balanced}"; shift 2 ;;
    -s|--scope) SCOPE="${2:-}"; shift 2 ;;
    --location) LOCATION="${2:-fsn1}"; shift 2 ;;
    --type) SERVER_TYPE="${2:-cx22}"; shift 2 ;;
    --image) IMAGE="${2:-ubuntu-24.04}"; shift 2 ;;
    --with-nuclei) NO_NUCLEI=""; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "${HETZNER_TOKEN:-}" ]]; then
  echo "error: HETZNER_TOKEN env var required" >&2
  exit 1
fi
if [[ -z "$TARGET" || -z "$SSH_KEY_NAME" ]]; then
  echo "error: target and ssh-key are required" >&2
  usage
  exit 1
fi

require curl
require python3
require ssh
require scp

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

NAME="reconixia-worker-$(date +%Y%m%d%H%M%S)"
PAYLOAD=$(python3 - <<PY
import json
print(json.dumps({
  "name": "$NAME",
  "server_type": "$SERVER_TYPE",
  "image": "$IMAGE",
  "location": "$LOCATION",
  "ssh_keys": ["$SSH_KEY_NAME"],
  "labels": {"tool": "reconixia", "temporary": "true"}
}))
PY
)

echo "[1/5] Creating Hetzner server..."
CREATE_RESPONSE="$(api POST /servers "$PAYLOAD")"
SERVER_ID="$(python3 - <<PY
import json
print(json.loads('''$CREATE_RESPONSE''')['server']['id'])
PY
)"
echo "Server ID: $SERVER_ID"

echo "[2/5] Waiting for public IPv4..."
for _ in $(seq 1 60); do
  SERVER_JSON="$(api GET "/servers/$SERVER_ID")"
  SERVER_IP="$(python3 - <<PY
import json
j=json.loads('''$SERVER_JSON''')
print(j['server'].get('public_net',{}).get('ipv4',{}).get('ip',''))
PY
)"
  if [[ -n "$SERVER_IP" ]]; then
    break
  fi
  sleep 5
done

if [[ -z "$SERVER_IP" ]]; then
  echo "error: public IP timeout" >&2
  exit 1
fi

echo "Server IP: $SERVER_IP"
SSH_ARGS=(--host "$SERVER_IP" --user root -t "$TARGET" -p "$PROFILE")
if [[ -n "$IDENTITY" ]]; then SSH_ARGS+=(--identity "$IDENTITY"); fi
if [[ -n "$SCOPE" ]]; then SSH_ARGS+=(-s "$SCOPE"); fi
if [[ -z "$NO_NUCLEI" ]]; then SSH_ARGS+=(--with-nuclei); fi

echo "[3/5] Running remote worker..."
chmod +x scripts/remote_existing.sh
./scripts/remote_existing.sh "${SSH_ARGS[@]}"

echo "[4/5] Destroying server..."
cleanup

echo "[5/5] Done."
