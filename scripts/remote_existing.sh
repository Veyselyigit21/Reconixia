#!/usr/bin/env bash
set -euo pipefail

HOST=""
USER="root"
KEY=""
TARGET=""
PROFILE="balanced"
SCOPE=""
NO_NUCLEI="--no-nuclei"
REMOTE_BASE="/tmp"
KNOWN_HOSTS="${RECONIXIA_KNOWN_HOSTS:-}"
STRICT_HOST_KEY="yes"
ACCEPT_HOST_KEY="false"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/remote_existing.sh --host 1.2.3.4 -t hedef.com [options]

Options:
  --host          Existing VPS IP/hostname, required
  -u, --user      SSH user, default root
  -i, --identity  SSH private key path
  -t, --target    Target domain, required
  -p, --profile   stealth|balanced|fast, default balanced
  -s, --scope     Scope file path
  --with-nuclei   Enable nuclei scan. Default is --no-nuclei for safer first runs.
  --known-hosts   SSH known_hosts file. Default: ./.reconixia_known_hosts
  --strict-host-key yes|no
                  Verify SSH host keys. Default: yes
  --accept-host-key
                  Add the scanned host key without prompting, after printing its fingerprint.
  -h, --help      Show help

Notes:
  - This script does NOT create or destroy cloud servers.
  - It uploads a clean source package, runs Reconixia remotely, downloads results, then removes the remote workdir.
  - .env, results, snapshots and local binaries are excluded from upload.
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib/preflight.sh"

prepare_ssh_options() {
  local known_hosts_dir tmp_scan answer
  STRICT_HOST_KEY="$(printf '%s' "$STRICT_HOST_KEY" | tr '[:upper:]' '[:lower:]')"
  case "$STRICT_HOST_KEY" in
    yes|true|1) STRICT_HOST_KEY="yes" ;;
    no|false|0) STRICT_HOST_KEY="no" ;;
    *) echo "error: --strict-host-key must be yes or no" >&2; exit 1 ;;
  esac

  SSH_OPTS=(-o ServerAliveInterval=15 -o ServerAliveCountMax=4)
  if [[ "$STRICT_HOST_KEY" == "no" ]]; then
    echo "[ssh] warning: strict host key checking disabled" >&2
    SSH_OPTS+=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
    return
  fi

  rx_require_cmd ssh-keyscan
  rx_require_cmd ssh-keygen

  if [[ -z "$KNOWN_HOSTS" ]]; then
    KNOWN_HOSTS="$ROOT_DIR/.reconixia_known_hosts"
  fi
  known_hosts_dir="$(dirname "$KNOWN_HOSTS")"
  mkdir -p "$known_hosts_dir"
  touch "$KNOWN_HOSTS"
  chmod 600 "$KNOWN_HOSTS" >/dev/null 2>&1 || true

  if ssh-keygen -F "$HOST" -f "$KNOWN_HOSTS" >/dev/null 2>&1; then
    echo "[ssh] known_hosts entry found for $HOST"
  else
    tmp_scan="$(mktemp -t reconixia-known-host.XXXXXX)"
    for _ in $(seq 1 30); do
      if ssh-keyscan -T 5 -H "$HOST" > "$tmp_scan" 2>/dev/null && [[ -s "$tmp_scan" ]]; then
        break
      fi
      sleep 5
    done
    if [[ ! -s "$tmp_scan" ]]; then
      rm -f "$tmp_scan"
      echo "error: could not scan SSH host key for $HOST" >&2
      exit 1
    fi

    echo "[ssh] fingerprint for $HOST:"
    ssh-keygen -lf "$tmp_scan"
    if [[ "$ACCEPT_HOST_KEY" != "true" ]]; then
      if [[ ! -t 0 ]]; then
        rm -f "$tmp_scan"
        echo "error: host key is unknown and no TTY is available; pass --known-hosts with a trusted entry or --accept-host-key" >&2
        exit 1
      fi
      read -r -p "Trust this SSH host key for $HOST? Type yes: " answer || true
      if [[ "$answer" != "yes" ]]; then
        rm -f "$tmp_scan"
        echo "cancelled: SSH host key was not trusted" >&2
        exit 1
      fi
    fi
    cat "$tmp_scan" >> "$KNOWN_HOSTS"
    rm -f "$tmp_scan"
    echo "[ssh] host key saved to $KNOWN_HOSTS"
  fi

  SSH_OPTS+=(-o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS")
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="${2:-}"; shift 2 ;;
    -u|--user) USER="${2:-root}"; shift 2 ;;
    -i|--identity|--key) KEY="${2:-}"; shift 2 ;;
    -t|--target) TARGET="${2:-}"; shift 2 ;;
    -p|--profile) PROFILE="${2:-balanced}"; shift 2 ;;
    -s|--scope) SCOPE="${2:-}"; shift 2 ;;
    --with-nuclei) NO_NUCLEI=""; shift ;;
    --known-hosts) KNOWN_HOSTS="${2:-}"; shift 2 ;;
    --strict-host-key) STRICT_HOST_KEY="${2:-yes}"; shift 2 ;;
    --accept-host-key) ACCEPT_HOST_KEY="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$HOST" || -z "$TARGET" ]]; then
  echo "error: --host and --target are required" >&2
  usage
  exit 1
fi

TARGET="$(rx_validate_target "$TARGET")"
rx_validate_profile "$PROFILE"
rx_validate_scope_optional "$SCOPE"
rx_validate_identity_optional "$KEY"
rx_require_cmd ssh
rx_require_cmd scp
rx_require_cmd tar

cd "$ROOT_DIR"

prepare_ssh_options
if [[ -n "$KEY" ]]; then
  SSH_OPTS+=(-i "$KEY")
fi

REMOTE="$USER@$HOST"
STAMP="$(date +%Y%m%d-%H%M%S)"
SAFE_TARGET="$TARGET"
REMOTE_DIR="$REMOTE_BASE/reconixia-$SAFE_TARGET-$STAMP"
ARCHIVE="$(mktemp -t reconixia-src.XXXXXX.tar.gz)"
REMOTE_CLEANED="false"

cleanup() {
  rm -f "$ARCHIVE" || true
  if [[ "$REMOTE_CLEANED" != "true" && -n "${REMOTE_DIR:-}" && -n "${REMOTE:-}" ]]; then
    ssh "${SSH_OPTS[@]}" "$REMOTE" "rm -rf '$REMOTE_DIR'" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

echo "[1/7] Checking SSH connectivity..."
ssh "${SSH_OPTS[@]}" "$REMOTE" "echo ready"

echo "[2/7] Creating clean source package..."
tar \
  --exclude=.git \
  --exclude=.env \
  --exclude='.env.*' \
  --exclude='*.pem' \
  --exclude='*.key' \
  --exclude=id_rsa \
  --exclude=id_ed25519 \
  --exclude=results \
  --exclude=snapshots \
  --exclude=reconixia \
  --exclude=reconixia-report \
  --exclude=reconixia-augment \
  --exclude=reconixia-diff \
  --exclude='*.exe' \
  -czf "$ARCHIVE" .

echo "[3/7] Uploading package to remote worker..."
ssh "${SSH_OPTS[@]}" "$REMOTE" "rm -rf '$REMOTE_DIR' && mkdir -p '$REMOTE_DIR'"
scp "${SSH_OPTS[@]}" "$ARCHIVE" "$REMOTE:$REMOTE_DIR/src.tar.gz"
if [[ -n "$SCOPE" ]]; then
  scp "${SSH_OPTS[@]}" "$SCOPE" "$REMOTE:$REMOTE_DIR/scope.remote.txt"
fi

echo "[4/7] Building and running remote scan..."
REMOTE_SCOPE=""
if [[ -n "$SCOPE" ]]; then
  REMOTE_SCOPE="-s scope.remote.txt"
fi
ssh "${SSH_OPTS[@]}" "$REMOTE" "
  set -euo pipefail
  cd '$REMOTE_DIR'
  tar -xzf src.tar.gz
  chmod +x scripts/install_tools.sh scripts/build_all.sh scripts/full_scan.sh scripts/snapshot.sh scripts/reconixia_auto.sh
  if ! command -v go >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y golang-go git ca-certificates tar
  fi
  ./scripts/install_tools.sh
  ./scripts/build_all.sh
  ./scripts/full_scan.sh -t '$TARGET' -p '$PROFILE' $REMOTE_SCOPE $NO_NUCLEI
"

echo "[5/7] Downloading results..."
LOCAL_DEST="results/remote-$SAFE_TARGET-$STAMP"
mkdir -p "$(dirname "$LOCAL_DEST")"
scp "${SSH_OPTS[@]}" -r "$REMOTE:$REMOTE_DIR/results/$SAFE_TARGET" "$LOCAL_DEST"

echo "[6/7] Cleaning remote workdir..."
ssh "${SSH_OPTS[@]}" "$REMOTE" "rm -rf '$REMOTE_DIR'"
REMOTE_CLEANED="true"

echo "[7/7] Done."
echo "Remote results downloaded to: $LOCAL_DEST"
echo "HTML report: $LOCAL_DEST/report.html"
