#!/usr/bin/env bash
set -euo pipefail

TARGET=""
PROFILE="balanced"
SCOPE=""
SSH_KEY_ID=""
IDENTITY=""
REGION="fra1"
SIZE="s-1vcpu-1gb"
IMAGE="ubuntu-24-04-x64"
NO_NUCLEI="--no-nuclei"
DROPLET_ID=""
DROPLET_IP=""

usage() {
  cat <<'EOF'
Usage:
  DIGITALOCEAN_TOKEN=... ./scripts/cloud_do_worker.sh -t hedef.com --ssh-key-id KEY_ID [options]

Options:
  -t, --target        Target domain, required
  --ssh-key-id        DigitalOcean SSH key ID or fingerprint, required
  -i, --identity      Local SSH private key path
  -p, --profile       stealth|balanced|fast, default balanced
  -s, --scope         Scope file path
  --region            DigitalOcean region, default fra1
  --size              Droplet size, default s-1vcpu-1gb
  --image             Droplet image, default ubuntu-24-04-x64
  --with-nuclei       Enable nuclei scan. Default is --no-nuclei for safer first runs.
  -h, --help          Show help

Lifecycle:
  create droplet -> wait for public IP -> run remote_existing.sh -> destroy droplet

Safety:
  - The script attempts to destroy the droplet on EXIT/ERR/INT/TERM.
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
    curl -fsS -X "$method" "https://api.digitalocean.com/v2$path" \
      -H "Authorization: Bearer $DIGITALOCEAN_TOKEN" \
      -H "Content-Type: application/json" \
      --data "$data"
  else
    curl -fsS -X "$method" "https://api.digitalocean.com/v2$path" \
      -H "Authorization: Bearer $DIGITALOCEAN_TOKEN" \
      -H "Content-Type: application/json"
  fi
}

cleanup() {
  if [[ -n "$DROPLET_ID" ]]; then
    echo "[cleanup] Destroying DigitalOcean droplet: $DROPLET_ID"
    api DELETE "/droplets/$DROPLET_ID" >/dev/null 2>&1 || true
    DROPLET_ID=""
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
    --ssh-key-id) SSH_KEY_ID="${2:-}"; shift 2 ;;
    -i|--identity) IDENTITY="${2:-}"; shift 2 ;;
    -p|--profile) PROFILE="${2:-balanced}"; shift 2 ;;
    -s|--scope) SCOPE="${2:-}"; shift 2 ;;
    --region) REGION="${2:-fra1}"; shift 2 ;;
    --size) SIZE="${2:-s-1vcpu-1gb}"; shift 2 ;;
    --image) IMAGE="${2:-ubuntu-24-04-x64}"; shift 2 ;;
    --with-nuclei) NO_NUCLEI=""; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "${DIGITALOCEAN_TOKEN:-}" ]]; then
  echo "error: DIGITALOCEAN_TOKEN env var required" >&2
  exit 1
fi
if [[ -z "$TARGET" || -z "$SSH_KEY_ID" ]]; then
  echo "error: target and ssh-key-id are required" >&2
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
  "region": "$REGION",
  "size": "$SIZE",
  "image": "$IMAGE",
  "ssh_keys": ["$SSH_KEY_ID"],
  "tags": ["reconixia", "temporary-worker"]
}))
PY
)

echo "[1/5] Creating DigitalOcean droplet..."
CREATE_RESPONSE="$(api POST /droplets "$PAYLOAD")"
DROPLET_ID="$(python3 - <<PY
import json
print(json.loads('''$CREATE_RESPONSE''')['droplet']['id'])
PY
)"
echo "Droplet ID: $DROPLET_ID"

echo "[2/5] Waiting for public IPv4..."
for _ in $(seq 1 60); do
  DROPLET_JSON="$(api GET "/droplets/$DROPLET_ID")"
  DROPLET_IP="$(python3 - <<PY
import json
j=json.loads('''$DROPLET_JSON''')
for n in j['droplet']['networks']['v4']:
    if n.get('type') == 'public':
        print(n.get('ip_address',''))
        break
PY
)"
  if [[ -n "$DROPLET_IP" ]]; then
    break
  fi
  sleep 5
done

if [[ -z "$DROPLET_IP" ]]; then
  echo "error: public IP timeout" >&2
  exit 1
fi

echo "Droplet IP: $DROPLET_IP"
echo "[3/5] Waiting for SSH..."
SSH_ARGS=(--host "$DROPLET_IP" --user root -t "$TARGET" -p "$PROFILE")
if [[ -n "$IDENTITY" ]]; then SSH_ARGS+=(--identity "$IDENTITY"); fi
if [[ -n "$SCOPE" ]]; then SSH_ARGS+=(-s "$SCOPE"); fi
if [[ -z "$NO_NUCLEI" ]]; then SSH_ARGS+=(--with-nuclei); fi

# remote_existing.sh has its own SSH retry and cleanup logic.
echo "[4/5] Running remote worker..."
chmod +x scripts/remote_existing.sh
./scripts/remote_existing.sh "${SSH_ARGS[@]}"

echo "[5/5] Destroying droplet..."
cleanup
echo "Done."
