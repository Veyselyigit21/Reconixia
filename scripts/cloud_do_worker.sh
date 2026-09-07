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
FIREWALL_ID=""
SSH_CIDR=""

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
  --ssh-cidr          CIDR allowed to SSH to the worker. Default: auto-detect public IPv4 /32.
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

normalize_cidr() {
  python3 - "$1" <<'PY'
import ipaddress
import sys

try:
    print(ipaddress.ip_network(sys.argv[1], strict=False))
except ValueError as exc:
    print(f"error: invalid SSH CIDR: {exc}", file=sys.stderr)
    sys.exit(1)
PY
}

resolve_ssh_cidr() {
  local ip
  if [[ -n "$SSH_CIDR" ]]; then
    normalize_cidr "$SSH_CIDR"
    return
  fi

  ip="$(curl -fsS --max-time 8 https://api.ipify.org || true)"
  if [[ -z "$ip" ]]; then
    echo "error: could not auto-detect public IP; pass --ssh-cidr 1.2.3.4/32" >&2
    exit 1
  fi
  normalize_cidr "$ip/32"
}

create_firewall() {
  local ssh_cidr="$1"
  local payload response
  payload=$(python3 - "$DROPLET_ID" "$ssh_cidr" <<'PY'
import json
import sys

droplet_id = int(sys.argv[1])
ssh_cidr = sys.argv[2]
print(json.dumps({
    "name": f"reconixia-fw-{droplet_id}",
    "droplet_ids": [droplet_id],
    "inbound_rules": [
        {
            "protocol": "tcp",
            "ports": "22",
            "sources": {"addresses": [ssh_cidr]},
        }
    ],
    "outbound_rules": [
        {
            "protocol": "tcp",
            "ports": "all",
            "destinations": {"addresses": ["0.0.0.0/0", "::/0"]},
        },
        {
            "protocol": "udp",
            "ports": "all",
            "destinations": {"addresses": ["0.0.0.0/0", "::/0"]},
        },
        {
            "protocol": "icmp",
            "destinations": {"addresses": ["0.0.0.0/0", "::/0"]},
        },
    ],
}))
PY
)
  response="$(api POST /firewalls "$payload")"
  FIREWALL_ID="$(python3 - <<PY
import json
print(json.loads('''$response''')['firewall']['id'])
PY
)"
}

wait_deleted() {
  local path="$1"
  local label="$2"
  for _ in $(seq 1 20); do
    if api GET "$path" >/dev/null 2>&1; then
      sleep 3
    else
      echo "[cleanup] Verified deleted: $label"
      return
    fi
  done
  echo "[cleanup] Warning: could not verify deletion for $label" >&2
}

cleanup() {
  if [[ -n "$DROPLET_ID" ]]; then
    local droplet_id="$DROPLET_ID"
    echo "[cleanup] Destroying DigitalOcean droplet: $DROPLET_ID"
    api DELETE "/droplets/$DROPLET_ID" >/dev/null 2>&1 || true
    wait_deleted "/droplets/$droplet_id" "droplet $droplet_id"
    DROPLET_ID=""
  fi
  if [[ -n "$FIREWALL_ID" ]]; then
    local firewall_id="$FIREWALL_ID"
    echo "[cleanup] Deleting DigitalOcean firewall: $FIREWALL_ID"
    api DELETE "/firewalls/$FIREWALL_ID" >/dev/null 2>&1 || true
    wait_deleted "/firewalls/$firewall_id" "firewall $firewall_id"
    FIREWALL_ID=""
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
    --ssh-cidr) SSH_CIDR="${2:-}"; shift 2 ;;
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

echo "[1/6] Creating DigitalOcean droplet..."
CREATE_RESPONSE="$(api POST /droplets "$PAYLOAD")"
DROPLET_ID="$(python3 - <<PY
import json
print(json.loads('''$CREATE_RESPONSE''')['droplet']['id'])
PY
)"
echo "Droplet ID: $DROPLET_ID"

SSH_CIDR="$(resolve_ssh_cidr)"
echo "[2/6] Creating firewall for SSH from $SSH_CIDR..."
create_firewall "$SSH_CIDR"
echo "Firewall ID: $FIREWALL_ID"

echo "[3/6] Waiting for public IPv4..."
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
echo "[4/6] Waiting for SSH..."
SSH_ARGS=(--host "$DROPLET_IP" --user root -t "$TARGET" -p "$PROFILE")
if [[ -n "$IDENTITY" ]]; then SSH_ARGS+=(--identity "$IDENTITY"); fi
if [[ -n "$SCOPE" ]]; then SSH_ARGS+=(-s "$SCOPE"); fi
if [[ -z "$NO_NUCLEI" ]]; then SSH_ARGS+=(--with-nuclei); fi
SSH_ARGS+=(--accept-host-key)

# remote_existing.sh has its own SSH retry and cleanup logic.
echo "[5/6] Running remote worker..."
chmod +x scripts/remote_existing.sh
./scripts/remote_existing.sh "${SSH_ARGS[@]}"

echo "[6/6] Destroying droplet and firewall..."
cleanup
echo "Done."
